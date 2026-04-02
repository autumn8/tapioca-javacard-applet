/*
 * SLIP-0010 Ed25519 HD key derivation for TapiocaApplet.
 * https://github.com/satoshilabs/slips/blob/master/slip-0010.md
 *
 * License: GNU AGPL v3
 */

package org.tapioca.applet;

import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * SLIP-0010 derivation for Ed25519.
 *
 * ALL path indexes must be hardened (high bit set).
 * Non-hardened child derivation is NOT supported for Ed25519 per spec.
 *
 * Memory discipline (to work within TapiocaApplet's 300-byte tmp buffer):
 *
 *   HmacSha512 uses tmp[0..192] internally (BLOCKSIZE=128 + HASHSIZE=64).
 *   Slip10 methods accept output/scratch offsets that must be ≥ 192.
 *
 *   Typical layout in TapiocaApplet.tmp:
 *     [0..191]   HmacSha512 internal scratch
 *     [192..255] HMAC output (64 bytes: IL[32] | IR[32])
 *     [256..292] deriveChild data assembly scratch (37 bytes)
 */
public class Slip10 {

    // "ed25519 seed" as bytes — the HMAC key for master derivation
    private static final byte[] CURVE_KEY = {
        (byte) 'e', (byte) 'd', (byte) '2', (byte) '5', (byte) '5', (byte) '1',
        (byte) '9', (byte) ' ', (byte) 's', (byte) 'e', (byte) 'e', (byte) 'd'
    };

    /**
     * Derive master key from a 64-byte BIP-39 seed.
     *
     * HMAC-SHA512(key="ed25519 seed", data=seed[64])
     *
     * Output layout at mac[macOff]:
     *   mac[macOff..+32] = IL — master private key
     *   mac[macOff+32..+64] = IR — master chain code
     *
     * Requirements:
     *   mac buffer must have ≥ 64 bytes available at macOff.
     *   mac must NOT alias HmacSha512's internal data buffer (tmp[0..191]).
     *   In practice: pass tmp as mac with macOff ≥ 192.
     */
    public static void deriveMaster(
            byte[] seed, short seedOff,
            byte[] mac,  short macOff) {

        HmacSha512.computeHmacSha512(
            CURVE_KEY, (short) 0, (short) CURVE_KEY.length,
            seed, seedOff, (short) 64,
            mac, macOff);
        // mac[macOff..+32]  = IL (master private key)
        // mac[macOff+32..+64] = IR (master chain code)
    }

    /**
     * Derive a single hardened child key (in-place safe).
     *
     * HMAC-SHA512(key=parentChain[32], data=0x00 || parentKey[32] || index[4])
     *
     * The output overwrites mac[macOff..+64]:
     *   mac[macOff..+32]    = child IL (new private key)
     *   mac[macOff+32..+64] = child IR (new chain code)
     *
     * This method is safe to call with parentKey = mac[macOff] and
     * parentChain = mac[macOff+32] (i.e. in-place update), because
     * HmacSha512 reads the key and message before writing output.
     *
     * Requirements:
     *   index[indexOff] high bit must be set (hardened). Throws SW_INVALID_PARAMETER otherwise.
     *   scratch must have ≥ 37 bytes at scratchOff.
     *   scratch[scratchOff..+37] must NOT overlap mac[macOff..+64] or tmp[0..192].
     *   In practice: parentKey=mac=tmp[192], parentChain=tmp[224], scratch=tmp[256], mac=tmp[192].
     */
    public static void deriveChild(
            byte[] parentKey,   short parentKeyOff,
            byte[] parentChain, short parentChainOff,
            byte[] index,       short indexOff,   // 4 bytes big-endian, must be hardened
            byte[] scratch,     short scratchOff, // ≥ 37 bytes work area
            byte[] mac,         short macOff) {   // ≥ 64 bytes output

        // Reject non-hardened indexes
        if ((index[indexOff] & (byte) 0x80) == 0)
            ISOException.throwIt(TapiocaApplet.SW_INVALID_PARAMETER);

        // Assemble HMAC data: 0x00 || parentKey[32] || index[4]
        scratch[scratchOff] = (byte) 0x00;
        Util.arrayCopyNonAtomic(parentKey, parentKeyOff,
                                scratch, (short)(scratchOff + 1), (short) 32);
        Util.arrayCopyNonAtomic(index, indexOff,
                                scratch, (short)(scratchOff + 33), (short) 4);

        HmacSha512.computeHmacSha512(
            parentChain, parentChainOff, (short) 32,
            scratch, scratchOff, (short) 37,
            mac, macOff);
        // mac[macOff..+32]    = child IL
        // mac[macOff+32..+64] = child IR
    }
}
