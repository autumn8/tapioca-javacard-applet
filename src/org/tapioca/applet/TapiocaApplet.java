/*
 * TapiocaApplet — Ed25519 hardware wallet for NXP JCOP 4 (J3R180 / J3R452)
 *
 * Milestone 1.1: skeleton, PIN management, GET_STATUS, factory reset.
 * Stubs present for 1.2 (seed/key) and 1.3 (signing) — return SW_NOT_IMPLEMENTED
 * until those milestones are complete.
 *
 * License: GNU AGPL v3
 */

package org.tapioca.applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.KeyAgreement;

public class TapiocaApplet extends Applet {

    // ── Version ──────────────────────────────────────────────────────────────
    private static final byte PROTOCOL_MAJOR = (byte) 0x00;
    private static final byte PROTOCOL_MINOR = (byte) 0x01;
    private static final byte APPLET_MAJOR   = (byte) 0x00;
    private static final byte APPLET_MINOR   = (byte) 0x01;

    // ── CLA ──────────────────────────────────────────────────────────────────
    private static final byte CLA_SOLANA = (byte) 0xB0;

    // ── INS codes ────────────────────────────────────────────────────────────
    // Setup & status
    private static final byte INS_SETUP                   = (byte) 0x2A;
    private static final byte INS_GET_STATUS              = (byte) 0x3C;
    private static final byte INS_RESET_TO_FACTORY        = (byte) 0xFF;
    private static final byte INS_CARD_LABEL              = (byte) 0x3D;
    // PIN management
    private static final byte INS_VERIFY_PIN              = (byte) 0x42;
    private static final byte INS_CHANGE_PIN              = (byte) 0x44;
    private static final byte INS_UNBLOCK_PIN             = (byte) 0x46;
    // Seed & keys (Phase 1.2)
    private static final byte INS_IMPORT_SEED             = (byte) 0x6C;
    private static final byte INS_RESET_SEED              = (byte) 0x77;
    private static final byte INS_GET_PUBLIC_KEY          = (byte) 0x6D;
    // Signing (Phase 1.3)
    private static final byte INS_SIGN_TX                 = (byte) 0x6F;
    // Secure channel & authentikey (Phase 3)
    private static final byte INS_INIT_SECURE_CHANNEL     = (byte) 0x81;
    private static final byte INS_PROCESS_SECURE_CHANNEL  = (byte) 0x82;
    private static final byte INS_EXPORT_AUTHENTIKEY      = (byte) 0x73;

    // ── Status words ─────────────────────────────────────────────────────────
    // Exposed as package-private so helper classes can reference them
    static final short SW_PIN_FAILED                      = (short) 0x63C0; // | tries_left
    static final short SW_SETUP_NOT_DONE                  = (short) 0x9C04;
    static final short SW_SETUP_ALREADY_DONE              = (short) 0x9C03;
    static final short SW_UNSUPPORTED_FEATURE             = (short) 0x9C05;
    static final short SW_UNAUTHORIZED                    = (short) 0x9C06;
    static final short SW_IDENTITY_BLOCKED                = (short) 0x9C0C;
    static final short SW_INVALID_PARAMETER               = (short) 0x9C0F;
    static final short SW_SEED_NOT_IMPORTED               = (short) 0x9C14;
    static final short SW_NOT_IMPLEMENTED                 = (short) 0x9C20;
    static final short SW_RESET_TO_FACTORY                = (short) 0xFF00;
    // HmacSha512 / HmacSha160 error codes
    static final short SW_HMAC_UNSUPPORTED_KEYSIZE        = (short) 0x9C1E;
    static final short SW_HMAC_UNSUPPORTED_MSGSIZE        = (short) 0x9C1F;
    // Secure channel error codes (Phase 3)
    static final short SW_SECURE_CHANNEL_UNINITIALIZED    = (short) 0x9C21;
    static final short SW_SECURE_CHANNEL_REQUIRED         = (short) 0x9C22;
    static final short SW_SECURE_CHANNEL_WRONG_MAC        = (short) 0x9C23;
    static final short SW_SECURE_CHANNEL_WRONG_IV         = (short) 0x9C24;

    // ── PIN constraints ───────────────────────────────────────────────────────
    private static final byte PIN_MIN_SIZE    = (byte) 4;
    private static final byte PIN_MAX_SIZE    = (byte) 16;
    private static final byte PIN_MAX_TRIES   = (byte) 5;
    private static final byte PUK_MAX_TRIES   = (byte) 3;

    // ── Persistent state ──────────────────────────────────────────────────────
    private boolean setupDone = false;
    private boolean isSeeded  = false;

    // ── Card label (Phase 3) ──────────────────────────────────────────────────
    // Up to 64 bytes of UTF-8, length stored in labelLen.
    private static final byte LABEL_MAX_SIZE = (byte) 64;
    private byte[]  cardLabel;
    private byte    labelLen = (byte) 0;

    // ── PIN objects ───────────────────────────────────────────────────────────
    private OwnerPIN pin;
    private OwnerPIN puk;

    // ── SLIP-0010 master key material (EEPROM) ────────────────────────────────
    // masterKey[32]       = IL from HMAC-SHA512("ed25519 seed", bip39_seed)
    // masterChainCode[32] = IR from the same derivation
    // These are the raw SLIP-0010 scalars, not encrypted (Phase 3 adds AES wrap).
    private byte[] masterKey;
    private byte[] masterChainCode;

    // ── Ed25519 signer ────────────────────────────────────────────────────────
    // signer.init() allocates ResourceManager, ECCurve, ECPoint etc. (~4-8 KB EEPROM).
    // This is deferred to the first importSeed() call to keep the install transaction small.
    private Ed25519Signer signer;
    private boolean signerInitialized = false;

    // ── Transaction signing state ─────────────────────────────────────────────
    // txState holds the incoming message bytes across multi-chunk sign sessions.
    // txSignActive[0] = 0x01 while a sign session (after first chunk) is in progress;
    // 0x00 otherwise. CLEAR_ON_DESELECT so a dropped NFC session always resets it.
    private SolanaTransaction txState;
    private byte[] txSignActive; // 1 byte, CLEAR_ON_DESELECT

    // ── Secure channel (Phase 3) ──────────────────────────────────────────────
    private SecureChannel sc;

    // ── Secure-channel dispatch flag (CLEAR_ON_DESELECT) ─────────────────────
    // Set to 1 while dispatching a command from within the SC envelope.
    // Sensitive handlers check this to ensure commands are never processed in plaintext.
    private byte[] inSecureChannel; // 1 byte, CLEAR_ON_DESELECT

    // ── Transient scratch (cleared on deselect) ───────────────────────────────
    // Layout (300 bytes total):
    //   [0..191]   HmacSha512 internal scratch (BLOCKSIZE=128 + HASHSIZE=64)
    //              Also used by HmacSha160 (BLOCKSIZE=64 + MAXMSGSIZE=192 = 256 bytes,
    //              but its HMAC calls use short messages so [0..83] suffices)
    //   [192..255] SLIP-0010 HMAC output (IL[32] | IR[32])
    //   [256..292] SLIP-0010 deriveChild data assembly (37 bytes)
    //   Secure channel re-uses [0..127] for ECDH scratch (non-overlapping with active crypto)
    private byte[] tmp;

    // ── Install ───────────────────────────────────────────────────────────────

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new TapiocaApplet(bArray, bOffset, bLength);
    }

    private TapiocaApplet(byte[] bArray, short bOffset, byte bLength) {
        pin           = new OwnerPIN(PIN_MAX_TRIES, PIN_MAX_SIZE);
        puk           = new OwnerPIN(PUK_MAX_TRIES, PIN_MAX_SIZE);
        masterKey       = new byte[32];
        masterChainCode = new byte[32];
        cardLabel       = new byte[LABEL_MAX_SIZE];
        tmp = JCSystem.makeTransientByteArray((short) 300, JCSystem.CLEAR_ON_DESELECT);
        HmacSha512.init(tmp);
        HmacSha160.init(tmp);
        lastDerivedPath = new byte[40]; // 10 levels × 4 bytes
        signer = new Ed25519Signer();
        // signer.init() is deferred to importSeed() to keep this install transaction small
        txState         = new SolanaTransaction();
        txSignActive    = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        inSecureChannel = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        sc = new SecureChannel();
        // generateAuthentikeyIfNeeded() runs an ECDH scalar multiplication which
        // exceeds the card's install transaction buffer. Deferred to select() instead.
        register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }

    // ── Select (power-on reset hook) ──────────────────────────────────────────

    public boolean select() {
        // Generate authentikey on first select (deferred from install to avoid
        // exceeding the card's install transaction buffer).
        sc.generateAuthentikeyIfNeeded(tmp);
        // Always reset PIN validation — re-selecting the same applet does not
        // automatically clear transient state on all cards.
        if (setupDone) {
            pin.reset();
            puk.reset();
        }
        // Always refresh CLEAR_ON_RESET curve parameters (pBN, rBN) when the signer
        // has been initialized. A card reset (power cycle, NFC field loss) zeros these
        // transient arrays, and signer.setKey()'s EC math will AIOOBE on zeroed moduli.
        // This must run even when isSeeded/keyLoaded is false (e.g. after factory reset)
        // because the next importSeed call will need valid curve parameters.
        if (signerInitialized) signer.onSelect();
        return true;
    }

    // ── APDU dispatch ─────────────────────────────────────────────────────────

    public void process(APDU apdu) {
        if (selectingApplet()) return;

        byte[] buf = apdu.getBuffer();

        // Reset SC-dispatch flag at the top of every command to prevent stale state
        // from a previous exception-aborted SC dispatch.
        inSecureChannel[0] = (byte) 0;

        if (buf[ISO7816.OFFSET_CLA] != CLA_SOLANA)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        byte ins = buf[ISO7816.OFFSET_INS];

        // ── Commands always permitted without setup or secure channel ─────────
        if (ins == INS_GET_STATUS) {
            apdu.setOutgoingAndSend((short) 0, getStatus(buf));
            return;
        }

        // ── Secure channel handshake — permitted before setup ─────────────────
        if (ins == INS_INIT_SECURE_CHANNEL) {
            apdu.setIncomingAndReceive();
            short n = sc.initSecureChannel(buf, ISO7816.OFFSET_CDATA, tmp);
            apdu.setOutgoingAndSend((short) 0, n);
            return;
        }

        // ── Encrypted command envelope ────────────────────────────────────────
        if (ins == INS_PROCESS_SECURE_CHANNEL) {
            apdu.setIncomingAndReceive();
            short bytesLeft = Util.makeShort((byte) 0x00, buf[ISO7816.OFFSET_LC]);
            // Decrypt in-place; decrypted command lands at buf[0..]
            try {
                sc.processSecureChannel(buf, ISO7816.OFFSET_CDATA, bytesLeft, tmp);
            } catch (javacard.security.CryptoException e) {
                ISOException.throwIt(Util.makeShort((byte) 0x9C, (byte)(0x50 + (byte)e.getReason())));
            } catch (ArrayIndexOutOfBoundsException e) {
                ISOException.throwIt((short) 0x9C60);
            } catch (NullPointerException e) {
                ISOException.throwIt((short) 0x9C61);
            } catch (ISOException e) {
                throw e;
            } catch (Exception e) {
                ISOException.throwIt((short) 0x9C6F);
            }

            ins = buf[ISO7816.OFFSET_INS];
            // Allow INS_SETUP before setupDone; all others need setup first.
            if (ins != INS_SETUP && !setupDone)
                ISOException.throwIt(SW_SETUP_NOT_DONE);

            // Mark that we are executing inside the SC envelope.
            inSecureChannel[0] = (byte) 1;
            short sizeout = (short) 0;
            try {
                sizeout = dispatchDecrypted(buf, ins);
            } catch (javacard.security.CryptoException e) {
                inSecureChannel[0] = (byte) 0;
                ISOException.throwIt(Util.makeShort((byte) 0x9C, (byte)(0x70 + (byte)e.getReason())));
            } catch (ArrayIndexOutOfBoundsException e) {
                inSecureChannel[0] = (byte) 0;
                ISOException.throwIt((short) 0x9C80);
            } catch (NullPointerException e) {
                inSecureChannel[0] = (byte) 0;
                ISOException.throwIt((short) 0x9C81);
            } catch (ISOException e) {
                inSecureChannel[0] = (byte) 0;
                throw e;
            } catch (Exception e) {
                inSecureChannel[0] = (byte) 0;
                ISOException.throwIt((short) 0x9C8F);
            }
            inSecureChannel[0] = (byte) 0;

            // Encrypt and MAC the response (if any) before sending.
            if (sizeout > (short) 0) {
                sizeout = sc.encryptResponse(buf, sizeout, tmp);
                apdu.setOutgoingAndSend((short) 0, sizeout);
            }
            return;
        }

        // ── Plaintext setup bootstrap ─────────────────────────────────────────
        // INS_SETUP must be wrapped in the SC envelope; reject the plaintext path.
        if (ins == INS_SETUP) {
            // setup() will throw SW_SECURE_CHANNEL_REQUIRED because
            // inSecureChannel[0] == 0 here.
            apdu.setIncomingAndReceive();
            setup(buf);
            return;
        }

        // All other commands require setup to have been completed
        if (!setupDone) ISOException.throwIt(SW_SETUP_NOT_DONE);

        // Read incoming data so handlers can access OFFSET_CDATA.
        apdu.setIncomingAndReceive();
        short sizeout = dispatchDecrypted(buf, ins);
        if (sizeout > (short) 0) apdu.setOutgoingAndSend((short) 0, sizeout);
    }

    /**
     * Dispatch an already-received (and possibly SC-decrypted) command.
     * Returns the number of response bytes written to buf[0..n-1], or 0 for no data.
     * Does NOT call apdu.setOutgoingAndSend — the caller handles send.
     */
    private short dispatchDecrypted(byte[] buf, byte ins) {
        switch (ins) {
            case INS_SETUP:              return setup(buf);
            case INS_GET_STATUS:         return getStatus(buf);
            case INS_VERIFY_PIN:         return verifyPIN(buf);
            case INS_CHANGE_PIN:         return changePIN(buf);
            case INS_UNBLOCK_PIN:        return unblockPIN(buf);
            case INS_RESET_TO_FACTORY:   return resetToFactory(buf);
            case INS_CARD_LABEL:         return cardLabel(buf);
            // ── Phase 1.2 ──
            case INS_IMPORT_SEED:        return importSeed(buf);
            case INS_RESET_SEED:         return resetSeed(buf);
            case INS_GET_PUBLIC_KEY:     return getPublicKey(buf);
            // ── Phase 1.3 ──
            case INS_SIGN_TX:            return signTransaction(buf);
            // ── Phase 3 ──
            case INS_EXPORT_AUTHENTIKEY: return exportAuthentikey(buf);
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                return (short) 0; // unreachable
        }
    }

    // ── INS_SETUP (0x2A) ─────────────────────────────────────────────────────
    //
    // REQUIRES: active secure channel (inSecureChannel == 1) so PIN and PUK
    // are never transmitted in plaintext over NFC.
    //
    // Data: [pin_len (1)] [pin (4-16 bytes)]
    //       [puk_len (1)] [puk (4-16 bytes)]
    //
    // Can only be called once. Subsequent calls return SW_SETUP_ALREADY_DONE.
    //
    private short setup(byte[] buf) {
        if (setupDone) ISOException.throwIt(SW_SETUP_ALREADY_DONE);
        // Enforce SC so PIN+PUK are never transmitted in plaintext over NFC.
        if (inSecureChannel[0] != (byte) 1) ISOException.throwIt(SW_SECURE_CHANNEL_REQUIRED);

        short off = ISO7816.OFFSET_CDATA;

        // Parse PIN
        byte pinLen = buf[off++];
        if (pinLen < PIN_MIN_SIZE || pinLen > PIN_MAX_SIZE)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        short pinOff = off;
        off += pinLen;

        // Parse PUK
        byte pukLen = buf[off++];
        if (pukLen < PIN_MIN_SIZE || pukLen > PIN_MAX_SIZE)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        short pukOff = off;

        // Commit
        pin.update(buf, pinOff, pinLen);
        puk.update(buf, pukOff, pukLen);
        setupDone = true;
        return (short) 0;
    }

    // ── INS_GET_STATUS (0x3C) ─────────────────────────────────────────────────
    //
    // No authentication required. Safe to call at any time.
    //
    // Response (12 bytes):
    //   [proto_major (1)] [proto_minor (1)] [app_major (1)] [app_minor (1)]
    //   [pin_tries_left (1)] [pin_tries_max (1)]
    //   [puk_tries_left (1)] [puk_tries_max (1)]
    //   [is_seeded (1)] [secure_channel (1)] [setup_done (1)] [reserved (1)]
    //
    private short getStatus(byte[] buf) {
        short pos = (short) 0;

        buf[pos++] = PROTOCOL_MAJOR;
        buf[pos++] = PROTOCOL_MINOR;
        buf[pos++] = APPLET_MAJOR;
        buf[pos++] = APPLET_MINOR;

        if (setupDone) {
            buf[pos++] = pin.getTriesRemaining();
            buf[pos++] = PIN_MAX_TRIES;
            buf[pos++] = puk.getTriesRemaining();
            buf[pos++] = PUK_MAX_TRIES;
        } else {
            buf[pos++] = (byte) 0x00;
            buf[pos++] = (byte) 0x00;
            buf[pos++] = (byte) 0x00;
            buf[pos++] = (byte) 0x00;
        }

        buf[pos++] = isSeeded  ? (byte) 0x01 : (byte) 0x00;
        buf[pos++] = sc.isInitialized() ? (byte) 0x01 : (byte) 0x00;
        buf[pos++] = setupDone ? (byte) 0x01 : (byte) 0x00;
        buf[pos++] = (byte) 0x00;  // reserved

        return pos;
    }

    // ── INS_VERIFY_PIN (0x42) ─────────────────────────────────────────────────
    //
    // REQUIRES: active secure channel so PIN is never transmitted in plaintext.
    //
    // Data: PIN bytes (4-16)
    //
    // SW on failure: 0x63Cx where x = remaining tries
    // SW on blocked: SW_IDENTITY_BLOCKED
    // Valid until card deselected (NFC session ends or power removed).
    //
    private short verifyPIN(byte[] buf) {
        if (inSecureChannel[0] != (byte) 1) ISOException.throwIt(SW_SECURE_CHANNEL_REQUIRED);

        byte len = buf[ISO7816.OFFSET_LC];

        if (pin.getTriesRemaining() == 0) ISOException.throwIt(SW_IDENTITY_BLOCKED);

        if (!pin.check(buf, ISO7816.OFFSET_CDATA, len))
            ISOException.throwIt((short)(SW_PIN_FAILED | pin.getTriesRemaining()));
        return (short) 0;
    }

    // ── INS_CHANGE_PIN (0x44) ─────────────────────────────────────────────────
    //
    // REQUIRES: active secure channel and PIN validated in current session.
    // Data: [old_len (1)] [old_pin] [new_len (1)] [new_pin]
    //
    private short changePIN(byte[] buf) {
        if (inSecureChannel[0] != (byte) 1) ISOException.throwIt(SW_SECURE_CHANNEL_REQUIRED);
        if (!pin.isValidated()) ISOException.throwIt(SW_UNAUTHORIZED);

        short off = ISO7816.OFFSET_CDATA;

        byte oldLen = buf[off++];
        if (oldLen < PIN_MIN_SIZE || oldLen > PIN_MAX_SIZE)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        short oldOff = off;
        off += oldLen;

        byte newLen = buf[off++];
        if (newLen < PIN_MIN_SIZE || newLen > PIN_MAX_SIZE)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        short newOff = off;

        // Re-verify the old PIN before committing the change
        if (!pin.check(buf, oldOff, oldLen))
            ISOException.throwIt((short)(SW_PIN_FAILED | pin.getTriesRemaining()));

        pin.update(buf, newOff, newLen);
        return (short) 0;
    }

    // ── INS_UNBLOCK_PIN (0x46) ────────────────────────────────────────────────
    //
    // REQUIRES: active secure channel.
    // Data: [puk_len (1)] [puk] [new_pin_len (1)] [new_pin]
    //
    // Resets the PIN to a new value after verifying the PUK.
    // Also resets the PIN retry counter.
    //
    private short unblockPIN(byte[] buf) {
        if (inSecureChannel[0] != (byte) 1) ISOException.throwIt(SW_SECURE_CHANNEL_REQUIRED);

        short off = ISO7816.OFFSET_CDATA;

        byte pukLen = buf[off++];
        if (pukLen < PIN_MIN_SIZE || pukLen > PIN_MAX_SIZE)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        short pukOff = off;
        off += pukLen;

        byte newLen = buf[off++];
        if (newLen < PIN_MIN_SIZE || newLen > PIN_MAX_SIZE)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        short newOff = off;

        if (puk.getTriesRemaining() == 0) ISOException.throwIt(SW_IDENTITY_BLOCKED);

        if (!puk.check(buf, pukOff, pukLen))
            ISOException.throwIt((short)(SW_PIN_FAILED | puk.getTriesRemaining()));

        pin.resetAndUnblock();
        pin.update(buf, newOff, newLen);
        return (short) 0;
    }

    // ── INS_RESET_TO_FACTORY (0xFF) ───────────────────────────────────────────
    //
    // REQUIRES: active secure channel and PIN validated. Wipes all state — PIN, PUK, seed, keys.
    // Response SW: 0xFF00 (SW_RESET_TO_FACTORY).
    // The applet remains installed but returns to the uninitialized state;
    // INS_SETUP must be called again before any other command.
    //
    private short resetToFactory(byte[] buf) {
        if (inSecureChannel[0] != (byte) 1) ISOException.throwIt(SW_SECURE_CHANNEL_REQUIRED);
        if (!pin.isValidated()) ISOException.throwIt(SW_UNAUTHORIZED);

        pin.resetAndUnblock();
        puk.resetAndUnblock();
        Util.arrayFillNonAtomic(tmp,             (short) 0, (short) tmp.length,  (byte) 0x00);
        Util.arrayFillNonAtomic(masterKey,       (short) 0, (short) 32,          (byte) 0x00);
        Util.arrayFillNonAtomic(masterChainCode, (short) 0, (short) 32,          (byte) 0x00);
        Util.arrayFillNonAtomic(cardLabel,       (short) 0, LABEL_MAX_SIZE,      (byte) 0x00);
        Util.arrayFillNonAtomic(lastDerivedPath, (short) 0, (short) 40,          (byte) 0x00);
        lastDerivedDepth = (byte) -1;
        labelLen = (byte) 0;
        txState.reset();
        txSignActive[0] = (byte) 0x00;
        sc.reset();

        // Zero signer EEPROM key material (tmp[0..31] was zeroed above).
        if (signerInitialized) {
            signer.clearKey(tmp, (short) 0);
        }

        setupDone = false;
        isSeeded  = false;

        ISOException.throwIt(SW_RESET_TO_FACTORY);
        return (short) 0; // unreachable
    }

    // ── INS_IMPORT_SEED (0x6C) ────────────────────────────────────────────────
    //
    // REQUIRES: active secure channel and PIN validated.
    // Data: [seed (64 bytes)] — BIP-39 derived seed (PBKDF2-HMAC-SHA512 output)
    //
    // Process:
    //   1. HMAC-SHA512("ed25519 seed", seed) → [IL(32) | IR(32)]
    //   2. Atomically store IL as masterKey, IR as masterChainCode, isSeeded=true
    //   3. Derive key at m/44'/501'/0' and load into signer
    //   4. Return 32-byte public key at m/44'/501'/0'
    //
    // Note: key derivation (~2700 ms) happens in this call, not at sign time.
    //
    private short importSeed(byte[] buf) {
        if (inSecureChannel[0] != (byte) 1) ISOException.throwIt(SW_SECURE_CHANNEL_REQUIRED);
        if (!pin.isValidated()) ISOException.throwIt(SW_UNAUTHORIZED);

        byte len = buf[ISO7816.OFFSET_LC];
        if (len != (byte) 64) ISOException.throwIt(SW_INVALID_PARAMETER);

        // One-time initialization of EC math objects (deferred from install)
        if (!signerInitialized) {
            signer.init();
            signerInitialized = true;
        }

        // tmp[192..255] = HMAC output: IL[32] | IR[32]
        Slip10.deriveMaster(buf, ISO7816.OFFSET_CDATA, tmp, (short) 192);

        // Atomically commit master key material. Power loss between writes would
        // leave masterKey/masterChainCode inconsistent without a transaction.
        JCSystem.beginTransaction();
        Util.arrayCopy(tmp, (short) 192, masterKey,       (short) 0, (short) 32);
        Util.arrayCopy(tmp, (short) 224, masterChainCode, (short) 0, (short) 32);
        isSeeded = true;
        JCSystem.commitTransaction();

        // Derive m/44'/501'/0' and load into signer
        // Path bytes (all hardened): 0x8000002C, 0x800001F5, 0x80000000
        deriveAndLoadKey((byte) 3, DEFAULT_PATH, (short) 0);

        // Return 32-byte public key
        signer.getPublicKey(buf, (short) 0);
        return (short) 32;
    }

    // ── INS_RESET_SEED (0x77) ─────────────────────────────────────────────────
    //
    // Requires PIN validated. Wipes master key, chain code, and signer state.
    //
    private short resetSeed(byte[] buf) {
        if (!pin.isValidated()) ISOException.throwIt(SW_UNAUTHORIZED);

        Util.arrayFillNonAtomic(masterKey,       (short) 0, (short) 32, (byte) 0x00);
        Util.arrayFillNonAtomic(masterChainCode, (short) 0, (short) 32, (byte) 0x00);
        Util.arrayFillNonAtomic(lastDerivedPath, (short) 0, (short) 40, (byte) 0x00);
        lastDerivedDepth = (byte) -1;
        isSeeded = false;

        if (signerInitialized) {
            // Ensure tmp[0..31] is zeroed before using as a zero-fill source for clearKey.
            Util.arrayFillNonAtomic(tmp, (short) 0, (short) 32, (byte) 0x00);
            signer.clearKey(tmp, (short) 0);
        }
        return (short) 0;
    }

    // ── INS_GET_PUBLIC_KEY (0x6D) ─────────────────────────────────────────────
    //
    // Requires PIN validated and seed imported.
    //
    // Data: [depth (1)] [index_0 (4)] ... [index_depth-1 (4)]
    //   All indexes must be hardened (high bit set).
    //   depth = 0 returns the master public key.
    //   Max depth: 10 (prevents runaway derivation time).
    //
    // Response: 32-byte Ed25519 public key
    //
    private short getPublicKey(byte[] buf) {
        if (!pin.isValidated()) ISOException.throwIt(SW_UNAUTHORIZED);
        if (!isSeeded)          ISOException.throwIt(SW_SEED_NOT_IMPORTED);

        short off = ISO7816.OFFSET_CDATA;
        byte depth = buf[off++];

        if (depth < 0 || depth > (byte) 10) ISOException.throwIt(SW_INVALID_PARAMETER);

        // Validate that the APDU contains enough bytes for the full path.
        short pathLen   = (short)(depth * 4);
        short available = (short)((buf[ISO7816.OFFSET_LC] & 0xFF) - 1); // -1 for depth byte
        if (available < pathLen) ISOException.throwIt(SW_INVALID_PARAMETER);

        deriveAndLoadKey(depth, buf, off);

        signer.getPublicKey(buf, (short) 0);
        return (short) 32;
    }

    // ── Key derivation helper ─────────────────────────────────────────────────
    //
    // Derives the key at the given path starting from masterKey/masterChainCode,
    // then calls signer.setKey() with the resulting 32-byte scalar.
    //
    // pathBuf[pathOff..] contains depth × 4-byte big-endian hardened indexes.
    //
    // tmp layout during derivation:
    //   [0..191]   HmacSha512 internal scratch
    //   [192..223] current IL (private key)
    //   [224..255] current IR (chain code)
    //   [256..292] child data assembly scratch (0x00 || key[32] || index[4] = 37 bytes)
    //
    private void deriveAndLoadKey(byte depth, byte[] pathBuf, short pathOff) {
        short pathLen    = (short)(depth * 4);
        short pathOff0   = pathOff; // save original offset for cache write

        // Skip derivation if the same path was used last time (~2,700 ms saved).
        if (lastDerivedDepth == depth && depth >= (byte) 0 &&
                Util.arrayCompare(pathBuf, pathOff0,
                                  lastDerivedPath, (short) 0, pathLen) == (byte) 0) {
            return;
        }

        // Seed the working buffers with master key material
        Util.arrayCopyNonAtomic(masterKey,       (short) 0, tmp, (short) 192, (short) 32);
        Util.arrayCopyNonAtomic(masterChainCode, (short) 0, tmp, (short) 224, (short) 32);

        for (byte i = 0; i < depth; i++) {
            // Derive child: reads tmp[192..255], writes result back to tmp[192..255]
            Slip10.deriveChild(
                tmp, (short) 192,    // parentKey
                tmp, (short) 224,    // parentChain
                pathBuf, pathOff,    // 4-byte hardened index
                tmp, (short) 256,    // scratch (37 bytes)
                tmp, (short) 192);   // output overwrites parentKey/chain in place
            pathOff += (short) 4;
        }

        // tmp[192..223] = final derived IL (Ed25519 seed)
        // Load into signer — this performs RFC 8032 expansion + EC keygen (~2700 ms)
        signer.setKey(tmp, (short) 192);

        // Cache this path so the next call with the same path skips derivation
        lastDerivedDepth = depth;
        Util.arrayCopyNonAtomic(pathBuf, pathOff0, lastDerivedPath, (short) 0, pathLen);
    }

    // ── Key derivation path cache ─────────────────────────────────────────────
    // Caches the last derived path so signer.setKey() (~2,700 ms) can be skipped
    // when the same path is requested again (e.g. repeated signs on m/44'/501'/0').
    // Max path: 10 levels × 4 bytes = 40 bytes.
    private byte[] lastDerivedPath;        // 40 bytes EEPROM
    private byte   lastDerivedDepth = (byte) -1; // -1 = cache invalid

    // Default Solana BIP-44 path: m/44'/501'/0'
    // All indexes hardened: 0x8000002C, 0x800001F5, 0x80000000
    private static final byte[] DEFAULT_PATH = {
        (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x2C,  // 44'
        (byte) 0x80, (byte) 0x00, (byte) 0x01, (byte) 0xF5,  // 501'
        (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00   // 0'
    };

    // ── INS_SIGN_TX (0x6F) ───────────────────────────────────────────────────
    //
    // REQUIRES: active secure channel, PIN validated, and seed imported.
    // Streams a Solana transaction message across one or more APDUs, derives the
    // signing key for the requested path, and returns a 64-byte Ed25519 signature.
    //
    // P1 flags (may be OR-combined):
    //   0x01 = first chunk  — data starts with [depth (1)][path (depth×4)] then message bytes
    //   0x80 = last chunk   — response contains 64-byte signature
    //   0x00 = continuation — data is message bytes only; no response data
    //   0x81 = first AND last (single-chunk message)
    //
    // First chunk data: [depth (1)] [idx_0 (4)] ... [idx_n (4)] [message bytes ...]
    // Other chunk data: [message bytes ...]
    // Response (last chunk only): [signature (64 bytes)]
    //
    private short signTransaction(byte[] buf) {
        if (inSecureChannel[0] != (byte) 1) ISOException.throwIt(SW_SECURE_CHANNEL_REQUIRED);
        if (!pin.isValidated()) ISOException.throwIt(SW_UNAUTHORIZED);
        if (!isSeeded)          ISOException.throwIt(SW_SEED_NOT_IMPORTED);

        byte   p1   = buf[ISO7816.OFFSET_P1];
        short  len  = (short)(buf[ISO7816.OFFSET_LC] & 0xFF);
        short  off  = ISO7816.OFFSET_CDATA;

        boolean isFirst = (p1 & (byte) 0x01) != 0;
        boolean isLast  = (p1 & (byte) 0x80) != 0;

        if (isFirst) {
            // Parse depth and derive signing key
            if (len < (short) 1) ISOException.throwIt(SW_INVALID_PARAMETER);
            byte depth = buf[off++];
            len--;

            if (depth < 0 || depth > (byte) 10) ISOException.throwIt(SW_INVALID_PARAMETER);

            short pathLen = (short)(depth * 4);
            if (len < pathLen) ISOException.throwIt(SW_INVALID_PARAMETER);

            deriveAndLoadKey(depth, buf, off);
            off += pathLen;
            len -= pathLen;

            // Reset accumulator for fresh message
            txState.init();
            txSignActive[0] = (byte) 0x01;
        } else {
            // Continuation or last — must have been preceded by a first chunk
            if (txSignActive[0] != (byte) 0x01) ISOException.throwIt(SW_INVALID_PARAMETER);
        }

        // Accumulate message bytes for this chunk
        if (len > (short) 0) {
            txState.update(buf, off, len);
        }

        if (isLast) {
            // Sign the complete buffered message and return signature
            signer.sign(txState.getBuffer(), (short) 0, txState.getMessageLength(),
                        buf, (short) 0);
            txState.reset();
            txSignActive[0] = (byte) 0x00;
            return (short) 64;
        }
        // Non-last chunks: fall through with SW 9000 and no response data
        return (short) 0;
    }

    // ── INS_CARD_LABEL (0x3D) ─────────────────────────────────────────────────
    //
    // P1 = 0x00: GET — returns [label_len (1)] [label bytes]
    // P1 = 0x01: SET — requires PIN validated; data = [label_len (1)] [label bytes]
    //   label_len = 0 clears the label.
    //   Max label size: LABEL_MAX_SIZE (64) bytes.
    //
    private short cardLabel(byte[] buf) {
        byte p1 = buf[ISO7816.OFFSET_P1];

        if (p1 == (byte) 0x01) {
            // SET
            if (!pin.isValidated()) ISOException.throwIt(SW_UNAUTHORIZED);
            short off = ISO7816.OFFSET_CDATA;
            byte len = buf[off++];
            if (len < 0 || len > LABEL_MAX_SIZE) ISOException.throwIt(SW_INVALID_PARAMETER);
            Util.arrayCopyNonAtomic(buf, off, cardLabel, (short) 0, len);
            labelLen = len;
            return (short) 0;
        } else {
            // GET
            buf[0] = labelLen;
            Util.arrayCopyNonAtomic(cardLabel, (short) 0, buf, (short) 1, labelLen);
            return (short)(1 + labelLen);
        }
    }

    // ── INS_EXPORT_AUTHENTIKEY (0x73) ─────────────────────────────────────────
    //
    // No authentication required — authentikey is public identity.
    // Response: [65-byte uncompressed SECP256K1 public key]
    //
    private short exportAuthentikey(byte[] buf) {
        return sc.getAuthentikeyPublic(buf, (short) 0);
    }

    // ── Stub for future unimplemented milestones ──────────────────────────────
    private void notYetImplemented() {
        ISOException.throwIt(SW_NOT_IMPLEMENTED);
    }
}
