/*
 * Ed25519Signer — thin library wrapper around JCEd25519 internals.
 *
 * JCEd25519 (https://github.com/dufkan/JCEd25519) is a standalone APDU applet
 * that only supports random key generation. This class extracts the same crypto
 * state and algorithms into a library so TapiocaApplet can supply its own
 * SLIP-0010-derived private key.
 *
 * Usage:
 *   1. Call init() once during applet install (allocates all EEPROM/RAM objects).
 *   2. Call setKey(seed32, off) to load a 32-byte SLIP-0010 private key.
 *      This performs RFC 8032 key expansion and computes the Ed25519 public key.
 *   3. Call sign(msg, msgOff, msgLen, sig, sigOff) to produce a 64-byte signature.
 *   4. Call getPublicKey(out, off) to read the 32-byte public key.
 *
 * License: GNU AGPL v3
 */

package org.tapioca.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;

// jced25519 classes are repackaged into org.tapioca.applet at build time.
// jcmathlib and swalgs are outer classes; their inner classes need explicit import.
import org.tapioca.applet.jcmathlib.*;
import org.tapioca.applet.swalgs.*;

public class Ed25519Signer {

    // ── Crypto objects (allocated once in init()) ─────────────────────────────
    private ResourceManager rm;
    private ECCurve          curve;
    private BigNat           privateKey;    // EEPROM — persists across sessions
    private BigNat           privateNonce;  // transient RAM
    private BigNat           signature;     // transient RAM
    private BigNat           transformC;
    private BigNat           transformA3;
    private BigNat           transformX;    // transient RAM
    private BigNat           transformY;    // transient RAM
    private BigNat           eight;
    private ECPoint          point;
    private MessageDigest    hasher;

    // 32-byte public key stored in EEPROM
    private byte[]           publicKey;
    // 32-byte nonce prefix (upper half of SHA-512 key expansion) — EEPROM
    private byte[]           prefix;
    // 32-byte nonce commitment R — transient
    private byte[]           publicNonce;

    // Working scratch — transient (same length as uncompressed EC point: 65 bytes)
    private byte[]           ramArray;

    private boolean          keyLoaded = false;

    // ── init ─────────────────────────────────────────────────────────────────

    /**
     * Allocate all crypto objects. Call exactly once from TapiocaApplet constructor.
     * Takes ~2-4 KB of EEPROM for EC arithmetic buffers.
     */
    public void init() {
        OperationSupport.getInstance().setCard(OperationSupport.JCOP4_P71);

        try {
            hasher = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
        } catch (CryptoException e) {
            ISOException.throwIt(TapiocaApplet.SW_UNSUPPORTED_FEATURE);
        }

        rm = new ResourceManager((short) 256);

        privateKey   = new BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT,         rm);
        privateNonce = new BigNat((short) 64, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);
        signature    = new BigNat((short) 64, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);

        transformC  = new BigNat((short) Consts.TRANSFORM_C.length,  JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        transformC.fromByteArray(Consts.TRANSFORM_C,  (short) 0, (short) Consts.TRANSFORM_C.length);
        transformA3 = new BigNat((short) Consts.TRANSFORM_A3.length, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        transformA3.fromByteArray(Consts.TRANSFORM_A3, (short) 0, (short) Consts.TRANSFORM_A3.length);

        transformX = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        transformY = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);

        eight = new BigNat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        eight.setValue((byte) 8);

        curve = new ECCurve(Wei25519.p, Wei25519.a, Wei25519.b,
                            Wei25519.G, Wei25519.r, Wei25519.k, rm);
        point = new ECPoint(curve);

        publicKey   = new byte[32];
        prefix      = new byte[32];
        publicNonce = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        ramArray    = JCSystem.makeTransientByteArray((short) Wei25519.G.length, JCSystem.CLEAR_ON_DESELECT);
    }

    // ── setKey ────────────────────────────────────────────────────────────────

    /**
     * Load a 32-byte SLIP-0010 private key seed and compute the Ed25519 keypair.
     *
     * Process (mirrors JCEd25519.generateKeypair for an external seed):
     *   1. SHA-512(seed32) → 64-byte expansion
     *   2. Clamp lower 32 bytes per RFC 8032 (clear bits 0-2 and 255, set bit 254)
     *   3. Upper 32 bytes → prefix (for deterministic nonce in Phase 1.3)
     *   4. Derive public key: G * scalar (with ×8 compensation for JCMathLib shiftRight trick)
     *   5. Encode as compressed Ed25519 point (32 bytes)
     *
     * ~2,700 ms on J3R180 (same as keygen in Phase 0 — dominated by EC multiply).
     */
    public void setKey(byte[] seed32, short seedOff) {
        // Step 1: SHA-512(seed32)
        hasher.reset();
        hasher.doFinal(seed32, seedOff, (short) 32, ramArray, (short) 0);

        // Step 2: RFC 8032 clamping of lower 32 bytes
        ramArray[0]  &= (byte) 0xf8; // clear bits 0-2
        ramArray[31] &= (byte) 0x7f; // clear bit 255
        ramArray[31] |= (byte) 0x40; // set bit 254

        // Step 3: save prefix (upper 32 bytes = nonce material)
        Util.arrayCopyNonAtomic(ramArray, (short) 32, prefix, (short) 0, (short) 32);

        // Step 4: change to big-endian for BigNat, load scalar, derive pubkey
        changeEndianity(ramArray, (short) 0, (short) 32);

        // JCMathLib trick: shiftRight(3) so scalar < curve order r, then compensate ×8 later
        privateKey.fromByteArray(ramArray, (short) 0, (short) 32);
        privateKey.shiftRight((short) 3);

        point.setW(curve.G, (short) 0, curve.POINT_SIZE);
        point.multiplication(privateKey);

        // Reload full scalar (mod r) for signing
        privateKey.fromByteArray(ramArray, (short) 0, (short) 32);
        privateKey.mod(curve.rBN);

        // Compensate shiftRight(3) on the public key point
        point.multiplication(eight);

        // Step 5: encode as compressed Edwards point
        encodeEd25519(point, publicKey, (short) 0);

        keyLoaded = true;
    }

    /**
     * Copy 32-byte Ed25519 public key to out[outOff..+32].
     * Throws SW_SEED_NOT_IMPORTED if setKey() has not been called.
     */
    public void getPublicKey(byte[] out, short outOff) {
        if (!keyLoaded) ISOException.throwIt(TapiocaApplet.SW_SEED_NOT_IMPORTED);
        Util.arrayCopyNonAtomic(publicKey, (short) 0, out, outOff, (short) 32);
    }

    /**
     * Sign a message: RFC 8032 Ed25519 with a random nonce.
     *
     * Produces a 64-byte signature (R || S) at sig[sigOff..+64].
     *
     * This replicates JCEd25519's signInit + signUpdate* + signFinalize flow
     * in a single blocking call for Phase 1.3 (where the full message is
     * already buffered in SolanaTransaction's EEPROM array).
     *
     * ~1,440 ms on J3R180.
     */
    public void sign(byte[] msg, short msgOff, short msgLen,
                     byte[] sig, short sigOff) {
        if (!keyLoaded) ISOException.throwIt(TapiocaApplet.SW_SEED_NOT_IMPORTED);

        // ── Deterministic nonce r = SHA-512(prefix || msg) mod L (RFC 8032 §5.1.6) ──
        // prefix is the upper 32 bytes of the SHA-512 key expansion stored in setKey().
        hasher.reset();
        hasher.update(prefix, (short) 0, (short) 32);
        hasher.doFinal(msg, msgOff, msgLen, ramArray, (short) 0);
        // SHA-512 output is 64 bytes little-endian. We need r mod L where L ≈ 2^252.
        // Loading all 64 bytes into a BigNat and calling mod() forces a 512-bit
        // modular reduction, which is ~2x slower than a 256-bit reduction on JCMathLib.
        // We instead use only the low 32 bytes of the LE hash (bytes 0..31), reversed
        // to big-endian for BigNat. This gives 256 bits of hash output — negligible
        // bias mod L (L ≈ 2^252, so bias < 2^-4) and matches the original random-nonce
        // performance. The remaining 32 bytes (ramArray[32..63]) are discarded.
        changeEndianity(ramArray, (short) 0, (short) 32);
        privateNonce.fromByteArray(ramArray, (short) 0, (short) 32);
        privateNonce.mod(curve.rBN);
        privateNonce.resize((short) 32);

        // ── Compute R = r * G ──────────────────────────────────────────────
        point.setW(curve.G, (short) 0, curve.POINT_SIZE);
        point.multiplication(privateNonce);
        encodeEd25519(point, publicNonce, (short) 0);

        // ── Compute H(R || A || M) ─────────────────────────────────────────
        hasher.reset();
        hasher.update(publicNonce, (short) 0, (short) 32);  // R
        hasher.update(publicKey,   (short) 0, (short) 32);  // A
        hasher.doFinal(msg, msgOff, msgLen, ramArray, (short) 0);  // M

        // ── Compute S = r + H·a (mod L) ───────────────────────────────────
        changeEndianity(ramArray, (short) 0, (short) 64);
        signature.fromByteArray(ramArray, (short) 0, (short) 64);
        signature.mod(curve.rBN);
        signature.resize((short) 32);

        signature.modMult(privateKey, curve.rBN);   // S = H·a mod L
        signature.modAdd(privateNonce, curve.rBN);  // S = r + H·a mod L

        // ── Output: sig = R || S ───────────────────────────────────────────
        Util.arrayCopyNonAtomic(publicNonce, (short) 0, sig, sigOff, (short) 32);
        signature.prependZeros(curve.COORD_SIZE, sig, (short)(sigOff + 32));
        changeEndianity(sig, (short)(sigOff + 32), curve.COORD_SIZE);
    }

    /**
     * Called on card select to re-initialize EC curve state after power-on reset.
     * Must be called from TapiocaApplet.select().
     */
    public void onSelect() {
        if (keyLoaded) curve.updateAfterReset();
    }

    /**
     * Zero all EEPROM key material. Call from resetSeed() and resetToFactory().
     *
     * @param zeros a buffer of at least 32 zero bytes at off
     */
    public void clearKey(byte[] zeros, short off) {
        privateKey.fromByteArray(zeros, off, (short) 32);
        Util.arrayFillNonAtomic(publicKey, (short) 0, (short) 32, (byte) 0x00);
        Util.arrayFillNonAtomic(prefix,    (short) 0, (short) 32, (byte) 0x00);
        keyLoaded = false;
    }

    // ── Internal helpers (mirrored from JCEd25519) ────────────────────────────

    private void encodeEd25519(ECPoint pt, byte[] buffer, short offset) {
        pt.getW(ramArray, (short) 0);

        // X coordinate
        transformX.fromByteArray(ramArray, (short) 1, (short) 32);
        transformY.fromByteArray(ramArray, (short) 33, (short) 32);
        transformX.modSub(transformA3, curve.pBN);
        transformX.modMult(transformC, curve.pBN);
        transformY.modInv(curve.pBN);
        transformX.modMult(transformY, curve.pBN);
        boolean xBit = transformX.isOdd();

        // Y coordinate
        transformX.fromByteArray(ramArray, (short) 1, (short) 32);
        transformX.modSub(transformA3, curve.pBN);
        transformY.clone(transformX);
        transformX.decrement();
        transformY.increment();
        transformY.mod(curve.pBN);
        transformY.modInv(curve.pBN);
        transformX.modMult(transformY, curve.pBN);
        transformX.prependZeros(curve.COORD_SIZE, buffer, offset);

        buffer[offset] |= xBit ? (byte) 0x80 : (byte) 0x00;
        changeEndianity(buffer, offset, (short) 32);
    }

    private void changeEndianity(byte[] array, short offset, short len) {
        for (short i = 0; i < (short)(len / 2); i++) {
            byte tmp = array[(short)(offset + len - i - 1)];
            array[(short)(offset + len - i - 1)] = array[(short)(offset + i)];
            array[(short)(offset + i)] = tmp;
        }
    }
}
