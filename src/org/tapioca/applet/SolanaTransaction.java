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
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class SolanaTransaction {

    static final short MAX_MSG_SIZE = (short) 1200;

    // EEPROM buffer — persists across deselect, cleared explicitly by reset().
    private byte[]  msgBuf;
    // EEPROM high-water mark — tracks the furthest byte ever written since the
    // last reset(). Persists across deselect so init() can zero exactly the
    // stale bytes left by a dropped NFC session, not the full 1200-byte buffer.
    private short[] msgHigh; // [0] = high-water mark, EEPROM
    // Transient length counter — fast RAM writes on every update(); resets to 0
    // on deselect, which is safe because txSignActive (in TapiocaApplet) also
    // clears on deselect and ensures init() is always called before update().
    private short[] msgLen; // [0] = length, CLEAR_ON_DESELECT

    public SolanaTransaction() {
        msgBuf  = new byte[MAX_MSG_SIZE];
        msgHigh = new short[1]; // EEPROM, initialises to 0
        msgLen  = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    }

    /** Reset state and prepare to receive a new message. */
    public void init() {
        // Zero only the bytes that were written in the previous session.
        // On a clean session msgHigh[0]==0, so nothing is zeroed.
        // On a dropped-session restart msgHigh[0] holds the stale length,
        // so exactly those bytes are cleared — not the full 1200-byte buffer.
        if (msgHigh[0] > (short) 0) {
            Util.arrayFillNonAtomic(msgBuf, (short) 0, msgHigh[0], (byte) 0x00);
            msgHigh[0] = (short) 0;
        }
        msgLen[0] = 0;
    }

    /**
     * Append len bytes from src[srcOff..srcOff+len-1] to the message buffer.
     * Throws SW_INVALID_PARAMETER if the buffer would overflow.
     */
    public void update(byte[] src, short srcOff, short len) {
        if (len <= (short) 0) return;
        if ((short)(msgLen[0] + len) > MAX_MSG_SIZE)
            ISOException.throwIt(TapiocaApplet.SW_INVALID_PARAMETER);
        Util.arrayCopyNonAtomic(src, srcOff, msgBuf, msgLen[0], len);
        msgLen[0] += len;
        // Advance EEPROM high-water mark so init() knows how much to zero on
        // a dropped-session restart.
        if (msgLen[0] > msgHigh[0]) msgHigh[0] = msgLen[0];
    }

    /** Return the backing buffer. Valid bytes are msgBuf[0..getMessageLength()-1]. */
    public byte[] getBuffer() {
        return msgBuf;
    }

    /** Total bytes accumulated since last init(). */
    public short getMessageLength() {
        return msgLen[0];
    }

    /** Zero-fill the accumulated bytes and reset length counter. */
    public void reset() {
        if (msgLen[0] > (short) 0) {
            Util.arrayFillNonAtomic(msgBuf, (short) 0, msgLen[0], (byte) 0x00);
        }
        msgLen[0] = 0;
        msgHigh[0] = (short) 0;
    }
}
