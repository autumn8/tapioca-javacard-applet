/*
 * SatoChip Bitcoin Hardware Wallet based on javacard
 * (c) 2015 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
 * Sources available on https://github.com/Toporin
 *
 * Adapted for TapiocaApplet — package rename only.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.tapioca.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;

// Very limited HMAC-SHA-512 implementation.
// Message is restricted to ≤ HASHSIZE (64) bytes — sufficient for SLIP-0010.
public class HmacSha512 {

    public static final short BLOCKSIZE = 128; // bytes
    public static final short HASHSIZE  =  64; // bytes

    private static byte[]         data;
    private static MessageDigest  sha512;

    /**
     * Must be called once during applet install, passing the shared transient
     * scratch buffer (must be ≥ BLOCKSIZE + HASHSIZE = 192 bytes).
     */
    public static void init(byte[] tmp) {
        data = tmp;
        try {
            sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
        } catch (CryptoException e) {
            ISOException.throwIt(TapiocaApplet.SW_UNSUPPORTED_FEATURE);
        }
    }

    /**
     * Compute HMAC-SHA-512(key, message) → mac[mac_offset..+64].
     *
     * Constraints (enforced):
     *   key_length   ∈ [0, BLOCKSIZE]   (128 bytes max)
     *   message_length ∈ [0, HASHSIZE]  (64 bytes max — enough for SLIP-0010)
     *
     * The scratch buffer `data` must be at least BLOCKSIZE + HASHSIZE = 192 bytes.
     * The mac buffer must have ≥ 64 bytes available at mac_offset.
     *
     * @return HASHSIZE (64)
     */
    public static short computeHmacSha512(
            byte[] key,     short key_offset,     short key_length,
            byte[] message, short message_offset, short message_length,
            byte[] mac,     short mac_offset) {

        if (key_length > BLOCKSIZE || key_length < 0)
            ISOException.throwIt(TapiocaApplet.SW_HMAC_UNSUPPORTED_KEYSIZE);
        if (message_length > HASHSIZE || message_length < 0)
            ISOException.throwIt(TapiocaApplet.SW_HMAC_UNSUPPORTED_MSGSIZE);

        // ── Inner hash: SHA-512( (key ^ ipad) || message ) ───────────────────
        for (short i = 0; i < key_length; i++)
            data[i] = (byte)(key[(short)(key_offset + i)] ^ 0x36);
        Util.arrayFillNonAtomic(data, key_length, (short)(BLOCKSIZE - key_length), (byte) 0x36);
        Util.arrayCopyNonAtomic(message, message_offset, data, BLOCKSIZE, message_length);
        sha512.reset();
        // Write inner hash to mac (output buffer) — avoids overlapping input/output
        // in the same array (hardware SHA-512 accelerators do not tolerate overlap).
        sha512.doFinal(data, (short) 0, (short)(BLOCKSIZE + message_length), mac, mac_offset);

        // Copy inner hash from mac into data[BLOCKSIZE] for outer-hash input.
        // WARNING: mac (e.g. tmp[192..255]) may overlap the caller's key bytes
        // (e.g. parentChain at tmp[224..255]) — do NOT re-read key after this point.
        // Instead, recover opad from ipad already in data[0..key_length-1]:
        //   data[i] = key[i]^ipad  →  key[i]^ipad^(ipad^opad) = key[i]^opad
        Util.arrayCopyNonAtomic(mac, mac_offset, data, BLOCKSIZE, HASHSIZE);

        // ── Outer hash: SHA-512( (key ^ opad) || inner_hash ) ────────────────
        for (short i = 0; i < key_length; i++)
            data[i] ^= (byte)(0x36 ^ 0x5C);   // flip ipad (0x36) → opad (0x5C)
        Util.arrayFillNonAtomic(data, key_length, (short)(BLOCKSIZE - key_length), (byte) 0x5C);
        // inner hash now at data[BLOCKSIZE..BLOCKSIZE+HASHSIZE-1]
        sha512.reset();
        sha512.doFinal(data, (short) 0, (short)(BLOCKSIZE + HASHSIZE), mac, mac_offset);

        return HASHSIZE;
    }
}
