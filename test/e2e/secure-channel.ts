/**
 * SecureChannel — AES-128-CBC + HMAC-SHA1 secure channel client.
 *
 * Mirrors the card-side SecureChannel.java protocol:
 *   - INS_INIT_SECURE_CHANNEL (0x81): ECDH handshake over secp256k1
 *   - INS_PROCESS_SECURE_CHANNEL (0x82): encrypted command envelope
 *
 * Uses only Node.js built-in `crypto` — no extra npm dependencies.
 */

import * as crypto from 'crypto';

const CLA = 0xb0;

/** Function shape matching the apdu() helpers in each script. */
export type ApduFn = (ins: number, p1: number, p2: number, payload?: Buffer) => Promise<Buffer>;

// ── Internal crypto helpers ───────────────────────────────────────────────────

function swOf(resp: Buffer): number {
  return ((resp[resp.length - 2] & 0xff) << 8) | (resp[resp.length - 1] & 0xff);
}

function respDataOf(resp: Buffer): Buffer {
  return resp.subarray(0, -2);
}

function hmacSha1(key: Buffer, data: Buffer): Buffer {
  return crypto.createHmac('sha1', key).update(data).digest();
}

function pkcs7Pad(data: Buffer, blockSize = 16): Buffer {
  const pad = blockSize - (data.length % blockSize);
  return Buffer.concat([data, Buffer.alloc(pad, pad)]);
}

function aes128cbcEncrypt(key: Buffer, iv: Buffer, plaintext: Buffer): Buffer {
  const c = crypto.createCipheriv('aes-128-cbc', key, iv);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(plaintext), c.final()]);
}

// ── SecureChannel ─────────────────────────────────────────────────────────────

export class SecureChannel {
  private sessionKey!: Buffer;
  private macKey!: Buffer;
  private counter = 0;
  private initialized = false;

  /**
   * Perform the ECDH handshake with the card.
   * Sends INS_INIT_SECURE_CHANNEL and derives session + MAC keys.
   */
  async handshake(apduFn: ApduFn): Promise<void> {
    // Generate ephemeral secp256k1 keypair
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.generateKeys();
    const hostPub = ecdh.getPublicKey(); // 65-byte uncompressed point (default)

    // INS_INIT_SECURE_CHANNEL = 0x81
    const resp = await apduFn(0x81, 0x00, 0x00, hostPub);
    if (swOf(resp) !== 0x9000)
      throw new Error(`INIT_SECURE_CHANNEL failed: SW=${swOf(resp).toString(16).toUpperCase()}`);

    // Parse response: [coordX_size(2) | coordX(32) | sig1_size(2) | sig1 | sig2_size(2) | sig2]
    const d = respDataOf(resp);
    const coordXSize = d.readUInt16BE(0);
    if (coordXSize !== 32) throw new Error(`Unexpected coordX size: ${coordXSize}`);
    const coordX = d.subarray(2, 34);

    // Recover shared X by trying both Y parities of the card's ephemeral public key
    let sharedX: Buffer | null = null;
    for (const prefix of [0x02, 0x03]) {
      const compressed = Buffer.concat([Buffer.from([prefix]), coordX]);
      try {
        sharedX = ecdh.computeSecret(compressed);
        break;
      } catch {
        // wrong parity — try the other
      }
    }
    if (!sharedX) throw new Error('Could not reconstruct card ephemeral pubkey from coordX');

    // Derive keys from the ECDH shared X coordinate
    // session_key = HMAC-SHA1(shared_X, "sc_key")[0:16]
    // mac_key     = HMAC-SHA1(shared_X, "sc_mac")[0:20]
    this.sessionKey  = hmacSha1(sharedX, Buffer.from('sc_key')).subarray(0, 16);
    this.macKey      = hmacSha1(sharedX, Buffer.from('sc_mac')); // 20 bytes
    this.counter     = 0;
    this.initialized = true;
  }

  /**
   * Wrap one inner command in INS_PROCESS_SECURE_CHANNEL (0x82) and send it.
   *
   * Returns the decrypted response with SW appended — same shape as a plain
   * apdu() call, so existing SW-checking code works unchanged.
   */
  async send(
    apduFn: ApduFn,
    ins: number,
    p1: number,
    p2: number,
    innerData?: Buffer
  ): Promise<Buffer> {
    if (!this.initialized)
      throw new Error('Secure channel not initialized — call handshake() first');

    this.counter++;

    // IV = 12 random bytes || 4-byte big-endian counter; last byte must be odd
    const iv = Buffer.concat([crypto.randomBytes(12), Buffer.alloc(4)]);
    iv.writeUInt32BE(this.counter, 12);
    if ((iv[15] & 0x01) === 0) iv[15] |= 0x01;

    // Inner APDU plaintext: [CLA INS P1 P2 Lc Data...]
    const hasData   = innerData && innerData.length > 0;
    const plaintext = hasData
      ? Buffer.from([CLA, ins, p1, p2, innerData!.length, ...innerData!])
      : Buffer.from([CLA, ins, p1, p2, 0x00]);

    const padded    = pkcs7Pad(plaintext);
    const encrypted = aes128cbcEncrypt(this.sessionKey, iv, padded);

    // MAC covers [IV(16) | data_size(2) | encrypted]
    const encSizeBuf = Buffer.alloc(2);
    encSizeBuf.writeUInt16BE(encrypted.length, 0);
    const mac = hmacSha1(this.macKey, Buffer.concat([iv, encSizeBuf, encrypted]));

    const macSizeBuf = Buffer.alloc(2);
    macSizeBuf.writeUInt16BE(20, 0);

    const payload = Buffer.concat([iv, encSizeBuf, encrypted, macSizeBuf, mac]);

    // The card does not encrypt responses — the inner handler calls
    // setOutgoingAndSend() directly, so response data comes back as plaintext.
    // The secure channel protects sensitive data flowing TO the card (PIN, seed).
    return apduFn(0x82, 0x00, 0x00, payload);
  }
}
