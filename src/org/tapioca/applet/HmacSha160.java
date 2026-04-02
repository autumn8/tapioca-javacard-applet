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
 *   key_length   ≤ BLOCKSIZE (64 bytes)
 *   message_length ≤ MAXMSGSIZE (192 bytes)
 *
 * License: GNU AGPL v3
 */
package org.tapioca.applet;

import javacard.framework.ISOException;
import javacard.security.MessageDigest;

public class HmacSha160 {

    public static final short BLOCKSIZE  = 64;  // SHA-1 block size in bytes
    public static final short HASHSIZE   = 20;  // SHA-1 output size in bytes
    public static final short MAXMSGSIZE = 192; // max message length supported

    private static MessageDigest sha160;
    private static byte[]        data;  // shared scratch: BLOCKSIZE + MAXMSGSIZE bytes min

    /**
     * Must be called once during applet install, passing the shared transient
     * scratch buffer (must be ≥ BLOCKSIZE + MAXMSGSIZE = 256 bytes).
     */
    public static void init(byte[] tmp) {
        sha160 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        data   = tmp;
    }

    /**
     * Compute HMAC-SHA1(key, message) → mac[mac_offset..+20].
     *
     * The scratch buffer {@code data} must be at least BLOCKSIZE + MAXMSGSIZE bytes.
     * mac must have ≥ 20 bytes available at mac_offset.
     *
     * @return HASHSIZE (20)
     */
    public static short computeHmacSha160(
            byte[] key,     short key_offset,     short key_length,
            byte[] message, short message_offset, short message_length,
            byte[] mac,     short mac_offset) {

        if (key_length > BLOCKSIZE || key_length < 0)
            ISOException.throwIt(TapiocaApplet.SW_HMAC_UNSUPPORTED_KEYSIZE);
        if (message_length > MAXMSGSIZE || message_length < 0)
            ISOException.throwIt(TapiocaApplet.SW_HMAC_UNSUPPORTED_MSGSIZE);

        // ── Inner hash: SHA1( (key ^ ipad) || message ) ──────────────────────
        for (short i = 0; i < key_length; i++)
            data[i] = (byte)(key[(short)(key_offset + i)] ^ 0x36);
        for (short i = key_length; i < BLOCKSIZE; i++)
            data[i] = (byte) 0x36;
        for (short i = 0; i < message_length; i++)
            data[(short)(BLOCKSIZE + i)] = message[(short)(message_offset + i)];
        sha160.reset();
        sha160.doFinal(data, (short) 0, (short)(BLOCKSIZE + message_length), data, BLOCKSIZE);

        // ── Outer hash: SHA1( (key ^ opad) || inner_hash ) ───────────────────
        // inner hash is now at data[BLOCKSIZE..BLOCKSIZE+HASHSIZE-1]
        for (short i = 0; i < key_length; i++)
            data[i] = (byte)(key[(short)(key_offset + i)] ^ 0x5C);
        for (short i = key_length; i < BLOCKSIZE; i++)
            data[i] = (byte) 0x5C;
        sha160.reset();
        sha160.doFinal(data, (short) 0, (short)(BLOCKSIZE + HASHSIZE), mac, mac_offset);

        return HASHSIZE;
    }
}
