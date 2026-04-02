/*
 * SecureChannel — AES-128 CBC + HMAC-SHA1 secure channel for TapiocaApplet.
 *
 * Compatible with the Satochip secure channel protocol.
 *
 * Protocol overview:
 *   1. Host sends INS_INIT_SECURE_CHANNEL with its 65-byte uncompressed SECP256K1 pubkey.
 *   2. Card generates ephemeral SECP256K1 keypair, performs ECDH, derives:
 *        session_key (AES-128, 16 bytes) = HMAC-SHA1(shared_X, "sc_key")[0:16]
 *        mac_key     (20 bytes)          = HMAC-SHA1(shared_X, "sc_mac")[0:20]
 *   3. Card returns: [coordX_size(2) | ephemeral_coordX(32) | self_sig_size(2) | self_sig
 *                     | authentikey_sig_size(2) | authentikey_sig]
 *   4. All subsequent commands must be wrapped via INS_PROCESS_SECURE_CHANNEL:
 *        request:  [IV(16) | data_size(2) | AES-CBC(command) | mac_size(2) | HMAC-SHA1(20)]
 *        response: [IV(16) | data_size(2) | AES-CBC(response)]
 *
 * License: GNU AGPL v3
 */
package org.tapioca.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class SecureChannel {

    // ── Key derivation constants: "sc_key" || "sc_mac" ────────────────────────
    // Indices into CST_SC: [0..5] = "sc_key", [6..11] = "sc_mac"
    private static final byte[] CST_SC = {
        's','c','_','k','e','y',
        's','c','_','m','a','c'
    };
    private static final short CST_SC_KEY_OFFSET = (short) 0;
    private static final short CST_SC_KEY_LENGTH = (short) 6;
    private static final short CST_SC_MAC_OFFSET = (short) 6;
    private static final short CST_SC_MAC_LENGTH = (short) 6;

    // ── sc_buffer layout: [IV_random(12) | IV_counter(4) | mac_key(20)] ───────
    private static final short OFFSET_SC_IV         = (short)  0;
    private static final short OFFSET_SC_IV_RANDOM  = (short)  0;
    private static final short OFFSET_SC_IV_COUNTER = (short) 12;
    private static final short OFFSET_SC_MACKEY     = (short) 16;
    private static final short SIZE_SC_IV           = (short) 16;
    private static final short SIZE_SC_IV_RANDOM    = (short) 12;
    private static final short SIZE_SC_IV_COUNTER   = (short)  4;
    private static final short SIZE_SC_MACKEY       = (short) 20;
    private static final short SIZE_SC_BUFFER       = (short) 36; // IV + mac_key

    // ── Crypto objects ────────────────────────────────────────────────────────
    private ECPrivateKey  sc_ephemeralkey;
    private ECPublicKey   sc_ephemeralPublic;
    private KeyPair       sc_ephemeralPair;
    private ECPrivateKey  authentikey_private;
    private ECPublicKey   authentikey_public;
    private AESKey        sc_sessionkey;
    private Cipher        sc_aes128_cbc;
    private KeyAgreement  keyAgreement;
    private Signature     sigECDSA;
    private RandomData    randomData;

    // ── State ─────────────────────────────────────────────────────────────────
    private byte[]  sc_buffer;           // IV (16) + mac_key (20) = 36 bytes, CLEAR_ON_DESELECT
    private byte[]  sc_initialized;     // [0]=1 when channel active, CLEAR_ON_DESELECT
    private boolean authentikeyGenerated;// true after first init (authentikey is persistent)

    // ── Scratch: reused across calls (passed in from applet) ──────────────────
    // We borrow a 128-byte window of the applet's tmp[] for ECDH output + HMAC scratch.
    // Caller must ensure tmp has ≥ 128 bytes free at scScratchOffset.

    public SecureChannel() {
        randomData       = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        sc_sessionkey    = (AESKey) KeyBuilder.buildKey(
                               KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        sc_ephemeralkey  = (ECPrivateKey) KeyBuilder.buildKey(
                               KeyBuilder.TYPE_EC_FP_PRIVATE, Secp256k1.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(sc_ephemeralkey);
        sc_ephemeralPublic = (ECPublicKey) KeyBuilder.buildKey(
                               KeyBuilder.TYPE_EC_FP_PUBLIC, Secp256k1.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(sc_ephemeralPublic);
        sc_ephemeralPair = new KeyPair(sc_ephemeralPublic, sc_ephemeralkey);

        authentikey_private = (ECPrivateKey) KeyBuilder.buildKey(
                               KeyBuilder.TYPE_EC_FP_PRIVATE, Secp256k1.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(authentikey_private);
        authentikey_public  = (ECPublicKey) KeyBuilder.buildKey(
                               KeyBuilder.TYPE_EC_FP_PUBLIC, Secp256k1.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(authentikey_public);

        sc_aes128_cbc    = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

        // Use X-coordinate only ECDH — ALG_EC_SVDP_DH_PLAIN_XY is unreliable
        // on some JCOP4 firmwares (getInstance succeeds but generateSecret
        // produces incorrect output). X-only is sufficient: we only need the
        // shared X for key derivation, and KeyPair.genKeyPair() handles pubkey
        // generation without needing the full point from ECDH.
        keyAgreement = KeyAgreement.getInstance(
                           Secp256k1.ALG_EC_SVDP_DH_PLAIN, false);
        sigECDSA = Signature.getInstance(Secp256k1.ALG_ECDSA_SHA_256, false);

        sc_buffer      = JCSystem.makeTransientByteArray(SIZE_SC_BUFFER, JCSystem.CLEAR_ON_DESELECT);
        sc_initialized = JCSystem.makeTransientByteArray((short) 1,       JCSystem.CLEAR_ON_DESELECT);

        authentikeyGenerated = false;
    }

    /**
     * Must be called once after install to generate the persistent authentikey.
     */
    public void generateAuthentikeyIfNeeded(byte[] tmp) {
        if (authentikeyGenerated) return;

        KeyPair authKP = new KeyPair(authentikey_public, authentikey_private);
        authKP.genKeyPair();

        authentikeyGenerated = true;
    }

    public boolean isInitialized() { return sc_initialized[0] == (byte) 1; }

    /**
     * INS_INIT_SECURE_CHANNEL handler.
     *
     * Input (in buf starting at dataOffset):
     *   [client_pubkey (65 bytes, uncompressed)]
     *
     * Output written to buf[0..]:
     *   [coordX_size(2) | ephemeral_coordX(32) | self_sig_size(2) | self_sig
     *    | authentikey_sig_size(2) | authentikey_sig]
     *
     * tmp must be ≥ 128 bytes (used for ECDH output + HMAC scratch + pubkey assembly).
     *
     * @return number of bytes written to buf
     */
    public short initSecureChannel(byte[] buf, short dataOffset, byte[] tmp) {
        // Validate client pubkey format
        if (buf[dataOffset] != (byte) 0x04)
            ISOException.throwIt(TapiocaApplet.SW_INVALID_PARAMETER);

        // ── 1. Generate ephemeral keypair ─────────────────────────────────────
        sc_ephemeralPair.genKeyPair();

        // ── 2. ECDH: shared secret = sc_ephemeral * client_pubkey ─────────────
        // tmp[0..64] = uncompressed shared point (X||Y) or just X depending on ALG
        keyAgreement.init(sc_ephemeralkey);
        keyAgreement.generateSecret(buf, dataOffset, (short) 65, tmp, (short) 0);

        // ── 3. Derive session_key and mac_key from shared X-coordinate ─────────
        // ALG_EC_SVDP_DH_PLAIN returns 32-byte X directly at tmp[0..31].
        // HmacSha160.data IS tmp — the HMAC working area spans tmp[0..255]
        // (BLOCKSIZE=64 + MAXMSGSIZE=192). Copy shared X beyond that range so
        // the HMAC's internal writes cannot corrupt the key.
        Util.arrayCopyNonAtomic(tmp, (short) 0, tmp, (short) 256, (short) 32);

        // Derive mac_key = HMAC-SHA1(shared_X, "sc_mac")[0:20] → sc_buffer[OFFSET_SC_MACKEY]
        HmacSha160.computeHmacSha160(
            tmp, (short) 256, (short) 32,
            CST_SC, CST_SC_MAC_OFFSET, CST_SC_MAC_LENGTH,
            sc_buffer, OFFSET_SC_MACKEY);

        // Derive session_key = HMAC-SHA1(shared_X, "sc_key")[0:16]
        // Output goes to tmp[96..115]; load first 16 bytes into sc_sessionkey
        HmacSha160.computeHmacSha160(
            tmp, (short) 256, (short) 32,
            CST_SC, CST_SC_KEY_OFFSET, CST_SC_KEY_LENGTH,
            tmp, (short) 96);
        sc_sessionkey.setKey(tmp, (short) 96);

        // ── 4. Reset IV counter ───────────────────────────────────────────────
        Util.arrayFillNonAtomic(sc_buffer, OFFSET_SC_IV, SIZE_SC_IV, (byte) 0x00);

        // ── 5. Build response: ephemeral coordX + self-sig + authentikey-sig ──
        // Get ephemeral public key (04 || X || Y, 65 bytes) from the key object
        sc_ephemeralPublic.getW(tmp, (short) 0);

        // Response buffer layout (built in buf starting at 0):
        //   [coordX_size(2) | coordX(32) | self_sig_size(2) | self_sig | authSig_size(2) | authSig]
        short outOff = (short) 0;

        // Write coordX (32 bytes) — skip 0x04 prefix at tmp[0]
        Util.setShort(buf, outOff, (short) 32);
        outOff += 2;
        Util.arrayCopyNonAtomic(tmp, (short) 1, buf, outOff, (short) 32);
        outOff += 32;

        // Self-sign: sign [coordX_size(2) | coordX(32)] with ephemeral key
        sigECDSA.init(sc_ephemeralkey, Signature.MODE_SIGN);
        short selfSigSize = sigECDSA.sign(buf, (short) 0, (short)(outOff), buf, (short)(outOff + 2));
        Util.setShort(buf, outOff, selfSigSize);
        outOff += (short)(2 + selfSigSize);

        // Authentikey-sign: sign all bytes so far with authentikey
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short authSigSize = sigECDSA.sign(buf, (short) 0, outOff, buf, (short)(outOff + 2));
        Util.setShort(buf, outOff, authSigSize);
        outOff += (short)(2 + authSigSize);

        sc_initialized[0] = (byte) 1;
        return outOff;
    }

    /**
     * INS_PROCESS_SECURE_CHANNEL handler — decrypts an incoming encrypted command.
     *
     * Input (in buf starting at dataOffset):
     *   [IV(16) | data_size(2) | encrypted_data | mac_size(2) | mac(20)]
     *
     * After successful return, buf[0..returnValue-1] contains the decrypted command.
     * tmp must be ≥ 20 bytes for MAC verification scratch.
     *
     * @return number of decrypted bytes (placed at buf[0])
     */
    public short processSecureChannel(byte[] buf, short dataOffset, short bytesLeft, byte[] tmp) {
        if (sc_initialized[0] != (byte) 1)
            ISOException.throwIt(TapiocaApplet.SW_SECURE_CHANNEL_UNINITIALIZED);

        if (bytesLeft < (short)(SIZE_SC_IV + 2))
            ISOException.throwIt(TapiocaApplet.SW_INVALID_PARAMETER);

        short offset  = dataOffset;
        short dataSize = Util.getShort(buf, (short)(offset + SIZE_SC_IV));

        if (bytesLeft < (short)(SIZE_SC_IV + 2 + dataSize + 2))
            ISOException.throwIt(TapiocaApplet.SW_INVALID_PARAMETER);

        short macSize = Util.getShort(buf, (short)(offset + SIZE_SC_IV + 2 + dataSize));
        if (macSize != (short) 20)
            ISOException.throwIt(TapiocaApplet.SW_SECURE_CHANNEL_WRONG_MAC);
        if (bytesLeft < (short)(SIZE_SC_IV + 2 + dataSize + 2 + macSize))
            ISOException.throwIt(TapiocaApplet.SW_INVALID_PARAMETER);

        // ── Verify HMAC-SHA1(mac_key, IV || data_size(2) || encrypted_data) ──
        HmacSha160.computeHmacSha160(
            sc_buffer, OFFSET_SC_MACKEY, SIZE_SC_MACKEY,
            buf, offset, (short)(SIZE_SC_IV + 2 + dataSize),
            tmp, (short) 0);
        // Constant-time comparison — no early exit to prevent timing oracle
        byte diff = 0;
        short macStart = (short)(offset + SIZE_SC_IV + 2 + dataSize + 2);
        for (short i = 0; i < (short) 20; i++)
            diff |= (byte)(tmp[i] ^ buf[(short)(macStart + i)]);
        if (diff != (byte) 0)
            ISOException.throwIt(TapiocaApplet.SW_SECURE_CHANNEL_WRONG_MAC);

        // ── Validate IV ───────────────────────────────────────────────────────
        // Last byte of received IV must be odd
        if ((buf[(short)(offset + SIZE_SC_IV - 1)] & (byte) 0x01) == (byte) 0x00)
            ISOException.throwIt(TapiocaApplet.SW_SECURE_CHANNEL_WRONG_IV);
        // Counter (bytes 12..15 of IV) must be strictly greater than local counter
        if (!counterLessThan(sc_buffer, OFFSET_SC_IV_COUNTER,
                             buf, (short)(offset + SIZE_SC_IV_RANDOM)))
            ISOException.throwIt(TapiocaApplet.SW_SECURE_CHANNEL_WRONG_IV);

        // ── Update local IV ───────────────────────────────────────────────────
        Util.arrayCopy(buf, (short)(offset + SIZE_SC_IV_RANDOM),
                       sc_buffer, OFFSET_SC_IV_COUNTER, SIZE_SC_IV_COUNTER);
        counterIncrement(sc_buffer, OFFSET_SC_IV_COUNTER);
        randomData.generateData(sc_buffer, OFFSET_SC_IV_RANDOM, SIZE_SC_IV_RANDOM);

        // ── Decrypt AES-128-CBC ───────────────────────────────────────────────
        sc_aes128_cbc.init(sc_sessionkey, Cipher.MODE_DECRYPT, buf, offset, SIZE_SC_IV);
        offset += SIZE_SC_IV;
        offset += 2; // skip data_size field
        short sizeout = sc_aes128_cbc.doFinal(buf, offset, dataSize, buf, (short) 0);
        return sizeout;
    }

    /**
     * Encrypt the response in buf[0..sizeout-1] in-place (with PKCS7 padding).
     * Result layout in buf[0..]:
     *   [IV(16) | data_size(2) | AES-CBC(response+padding)]
     *
     * tmp must be ≥ sizeout + 16 bytes (for padded plaintext staging).
     *
     * @return total response bytes
     */
    public short encryptResponse(byte[] buf, short sizeout, byte[] tmp) {
        short blocksize = (short) 16;
        short padsize   = (short)(blocksize - (short)(sizeout % blocksize));

        // Stage padded plaintext in tmp
        Util.arrayCopyNonAtomic(buf, (short) 0, tmp, (short) 0, sizeout);
        Util.arrayFillNonAtomic(tmp, sizeout, padsize, (byte) padsize);

        // Write IV at buf[0..15]
        Util.arrayCopyNonAtomic(sc_buffer, OFFSET_SC_IV, buf, (short) 0, SIZE_SC_IV);

        // Encrypt into buf[18..]
        sc_aes128_cbc.init(sc_sessionkey, Cipher.MODE_ENCRYPT,
                           sc_buffer, OFFSET_SC_IV, SIZE_SC_IV);
        short encSize = sc_aes128_cbc.doFinal(
                            tmp, (short) 0, (short)(sizeout + padsize),
                            buf, (short) 18);

        Util.setShort(buf, (short) 16, encSize);

        // Append HMAC-SHA1(mac_key, IV || data_size || ciphertext) for response integrity
        short coveredLen = (short)(18 + encSize);
        HmacSha160.computeHmacSha160(
            sc_buffer, OFFSET_SC_MACKEY, SIZE_SC_MACKEY,
            buf, (short) 0, coveredLen,
            tmp, (short) 0);
        Util.setShort(buf, coveredLen, (short) 20);
        Util.arrayCopyNonAtomic(tmp, (short) 0, buf, (short)(coveredLen + 2), (short) 20);
        return (short)(coveredLen + 22);
    }

    /**
     * Export the authentikey public key (65-byte uncompressed point) to buf[offset].
     * @return 65
     */
    public short getAuthentikeyPublic(byte[] buf, short offset) {
        authentikey_public.getW(buf, offset);
        return (short) 65;
    }

    // ── IV counter helpers (4-byte big-endian) ────────────────────────────────

    /** Returns true if x[xOff..+4] < y[yOff..+4] (unsigned, big-endian). */
    private static boolean counterLessThan(byte[] x, short xOff, byte[] y, short yOff) {
        for (short i = 0; i < SIZE_SC_IV_COUNTER; i++) {
            short xs = (short)(x[(short)(xOff + i)] & 0xFF);
            short ys = (short)(y[(short)(yOff + i)] & 0xFF);
            if (xs < ys) return true;
            if (xs > ys) return false;
        }
        return false; // equal → not strictly less
    }

    /** Increments x[xOff..+4] as a big-endian unsigned 4-byte integer. */
    private static void counterIncrement(byte[] x, short xOff) {
        short carry = 1;
        for (short i = (short)(xOff + SIZE_SC_IV_COUNTER - 1); i >= xOff; i--) {
            carry += (short)(x[i] & 0xFF);
            x[i] = (byte)(carry & 0xFF);
            carry = (short)(carry >>> 8);
        }
    }

    /**
     * Clear secure channel state (called from resetToFactory).
     */
    public void reset() {
        Util.arrayFillNonAtomic(sc_buffer, (short) 0, SIZE_SC_BUFFER, (byte) 0x00);
        sc_initialized[0] = (byte) 0;
        // Note: authentikeyGenerated remains true — authentikey is persistent identity
    }
}
