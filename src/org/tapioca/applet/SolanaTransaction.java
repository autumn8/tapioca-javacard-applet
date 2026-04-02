/*
 * SolanaTransaction — streaming EEPROM accumulator for Solana message bytes.
 *
 * Receives a Solana transaction message across multiple APDU chunks and holds
 * the full byte array until signing is complete. Option A from the design doc:
 * buffer the full message in EEPROM, then pass to Ed25519Signer.sign() once.
 *
 * Max message size: 1200 bytes — covers the Solana network cap (~1168 bytes).
 *
 * Usage:
 *   1. Call init()             — reset, prepare to receive a new message.
 *   2. Call update() per chunk — accumulate bytes.
 *   3. Call getBuffer() / getMessageLength() — pass to signer.
 *   4. Call reset()            — zero-fill and clear after signing.
 *
 * License: GNU AGPL v3
 */

package org.tapioca.applet;

import javacard.framework.ISOException;
import javacard.framework.Util;

public class SolanaTransaction {

    static final short MAX_MSG_SIZE = (short) 1200;

    // EEPROM buffer — persists across deselect, cleared explicitly by reset().
    private byte[] msgBuf;
    private short  msgLen;

    public SolanaTransaction() {
        msgBuf = new byte[MAX_MSG_SIZE];
        msgLen = 0;
    }

    /** Reset state and prepare to receive a new message. */
    public void init() {
        msgLen = 0;
    }

    /**
     * Append len bytes from src[srcOff..srcOff+len-1] to the message buffer.
     * Throws SW_INVALID_PARAMETER if the buffer would overflow.
     */
    public void update(byte[] src, short srcOff, short len) {
        if (len <= (short) 0) return;
        if ((short)(msgLen + len) > MAX_MSG_SIZE)
            ISOException.throwIt(TapiocaApplet.SW_INVALID_PARAMETER);
        Util.arrayCopyNonAtomic(src, srcOff, msgBuf, msgLen, len);
        msgLen += len;
    }

    /** Return the backing buffer. Valid bytes are msgBuf[0..getMessageLength()-1]. */
    public byte[] getBuffer() {
        return msgBuf;
    }

    /** Total bytes accumulated since last init(). */
    public short getMessageLength() {
        return msgLen;
    }

    /** Zero-fill the accumulated bytes and reset length counter. */
    public void reset() {
        if (msgLen > (short) 0) {
            Util.arrayFillNonAtomic(msgBuf, (short) 0, msgLen, (byte) 0x00);
        }
        msgLen = 0;
    }
}
