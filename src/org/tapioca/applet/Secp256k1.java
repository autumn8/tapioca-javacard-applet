/*
 * SECP256K1 curve parameters for TapiocaApplet Phase 3 secure channel.
 *
 * Adapted from the parent Satochip project (org.satochip.applet.Secp256k1)
 * — same curve constants, package renamed, ALG_EC_SVDP_DH_PLAIN_XY added.
 *
 * License: GNU AGPL v3
 */
package org.tapioca.applet;

import javacard.security.ECKey;

public class Secp256k1 {

    // ── Algorithm constants (not in older JC SDKs) ────────────────────────────
    public static final byte  ALG_ECDSA_SHA_256      = (byte)  33; // JC 3.0.1+
    public static final byte  ALG_EC_SVDP_DH_PLAIN   = (byte)   3; // X-coord only
    public static final byte  ALG_EC_SVDP_DH_PLAIN_XY= (byte)   7; // uncompressed point (JC 3.0.4+)
    public static final short LENGTH_EC_FP_256        = (short) 256;

    // ── secp256k1 domain parameters (big-endian) ──────────────────────────────
    // Offsets: P=0, a=32, b=64, R=96, G=128 (total 193 bytes)
    public static final byte[] SECP256K1 = {
        // P (field prime) – offset 0
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE, (byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F,
        // a – offset 32
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        // b – offset 64
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x07,
        // R (group order) – offset 96
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
        (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6, (byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
        (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C, (byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41,
        // G (uncompressed base point) – offset 128
        (byte)0x04,
        (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E, (byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
        (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95, (byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
        (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB, (byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
        (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B, (byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
        (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77, (byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
        (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC, (byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
        (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48, (byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
        (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F, (byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8
    };

    public static final short SECP256K1_K         = 0x01;
    public static final short OFFSET_SECP256K1_P  = 0;
    public static final short OFFSET_SECP256K1_a  = 32;
    public static final short OFFSET_SECP256K1_b  = 64;
    public static final short OFFSET_SECP256K1_R  = 96;
    public static final short OFFSET_SECP256K1_G  = 128;

    public static void setCommonCurveParameters(ECKey eckey) {
        eckey.setFieldFP(SECP256K1, OFFSET_SECP256K1_P, (short) 32);
        eckey.setA(      SECP256K1, OFFSET_SECP256K1_a, (short) 32);
        eckey.setB(      SECP256K1, OFFSET_SECP256K1_b, (short) 32);
        eckey.setR(      SECP256K1, OFFSET_SECP256K1_R, (short) 32);
        eckey.setG(      SECP256K1, OFFSET_SECP256K1_G, (short) 65);
        eckey.setK(      SECP256K1_K);
    }
}
