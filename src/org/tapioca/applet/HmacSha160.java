/*
 * HMAC-SHA1 (160-bit) implementation for TapiocaApplet Phase 3 secure channel.
 *
 * Adapted from the parent Satochip project (org.satochip.applet.HmacSha160)
 * — same algorithm, package renamed, error codes reference TapiocaApplet.
 *
 * Used exclusively for secure channel key derivation:
 *   session_key = HMAC-SHA1(shared_secret_X, "sc_key")[0:16]
 *   mac_key     = HMAC-SHA1(shared_secret_X, "sc_mac")[0:20]
 *
 * and for MAC authentication of encrypted APDUs.
 *
 * Constraints:
 *   key_length ≤ BLOCKSIZE (64 bytes)
 *   message_length: no upper limit — message is streamed via update()+doFinal()
 *
 * Scratch buffer layout (data[]):
 *   data[0..BLOCKSIZE-1]         = ipad/opad key block
 *   data[BLOCKSIZE..+HASHSIZE-1] = inner hash staging area
 *
 * The inner hash is written to data[BLOCKSIZE..] (never to mac directly), so the
 * ipad key block at data[0..BLOCKSIZE-1] is intact when we flip to opad.
 * This avoids corruption when mac aliases data (e.g. mac=tmp, mac_offset=0).
 *
 * Scratch buffer requirements: ≥ BLOCKSIZE + HASHSIZE = 84 bytes.
 *
 * License: GNU AGPL v3
 */
package org.tapioca.applet;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.MessageDigest;

public class HmacSha160 {

    public static final short BLOCKSIZE = 64;  // SHA-1 block size in bytes
    public static final short HASHSIZE  = 20;  // SHA-1 output size in bytes

    private static MessageDigest sha160;
    private static byte[]        data;  // shared scratch: ≥ BLOCKSIZE + HASHSIZE = 84 bytes

    /**
     * Must be called once during applet install, passing the shared transient
     * scratch buffer (must be ≥ BLOCKSIZE + HASHSIZE = 84 bytes).
     */
    public static void init(byte[] tmp) {
        sha160 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        data   = tmp;
    }

    /**
     * Compute HMAC-SHA1(key, message) → mac[mac_offset..+20].
     *
     * The message is streamed directly via update()+doFinal() — no size limit.
     *
     * The inner hash is staged at data[BLOCKSIZE..] so the ipad key block at
     * data[0..BLOCKSIZE-1] remains intact until the opad flip, even when mac
     * aliases data (e.g. mac=tmp, mac_offset=0).
     *
     * @return HASHSIZE (20)
     */
    public static short computeHmacSha160(
            byte[] key,     short key_offset,     short key_length,
            byte[] message, short message_offset, short message_length,
            byte[] mac,     short mac_offset) {

        if (key_length > BLOCKSIZE || key_length < 0)
            ISOException.throwIt(TapiocaApplet.SW_HMAC_UNSUPPORTED_KEYSIZE);

        // ── Build ipad key block in data[0..BLOCKSIZE-1] ─────────────────────
        for (short i = 0; i < key_length; i++)
            data[i] = (byte)(key[(short)(key_offset + i)] ^ 0x36);
        for (short i = key_length; i < BLOCKSIZE; i++)
            data[i] = (byte) 0x36;

        // ── Inner hash → data[BLOCKSIZE..BLOCKSIZE+HASHSIZE-1] ───────────────
        // Writing to data[BLOCKSIZE..] keeps data[0..BLOCKSIZE-1] (ipad key block) intact,
        // even when mac aliases data at offset 0.
        sha160.reset();
        sha160.update(data, (short) 0, BLOCKSIZE);
        sha160.doFinal(message, message_offset, message_length, data, BLOCKSIZE);

        // ── Flip ipad → opad in data[0..BLOCKSIZE-1] (still intact) ──────────
        for (short i = 0; i < key_length; i++)
            data[i] ^= (byte)(0x36 ^ 0x5C);
        for (short i = key_length; i < BLOCKSIZE; i++)
            data[i] = (byte) 0x5C;

        // ── Outer hash: SHA1((key ^ opad) || inner_hash) → mac ───────────────
        sha160.reset();
        sha160.doFinal(data, (short) 0, (short)(BLOCKSIZE + HASHSIZE), mac, mac_offset);

        return HASHSIZE;
    }
}
