#!/usr/bin/env ts-node
/**
 * SolanaCard CLI — end-to-end test
 *
 * Usage:
 *   ts-node index.ts "<12-or-24-word bip39 mnemonic>"
 *   ts-node index.ts "<mnemonic>" --pin 1234
 *
 * Flow:
 *   1. Derive 64-byte seed from mnemonic (BIP-39 PBKDF2)
 *   2. Connect to card via PC/SC, select TapiocaApplet
 *   3. Setup card if fresh; verify PIN
 *   4. Import seed → card derives m/44'/501'/0', returns pubkey
 *   5. Log Solana address
 *   6. Airdrop 1 SOL on testnet if balance is low
 *   7. Build a SOL transfer transaction
 *   8. Stream message bytes to card → receive 64-byte Ed25519 signature
 *   9. Attach signature, verify locally, broadcast to testnet
 *  10. Confirm and log explorer link
 */

// ⚠️  DEVNET ONLY — never use this mnemonic on mainnet; it is publicly known.
// Ensure card is working from a clean install.
// Run :
// npm test:devnet-tx "always thunder family peasant ancient pioneer nut vote detect monster shaft timber prepare program clump awake unable error garden shield sand fossil orphan clump" -- --pin 5678

import * as crypto from 'crypto';
import {
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
  LAMPORTS_PER_SOL,
  Keypair,
} from '@solana/web3.js';
import * as bip39 from 'bip39';

// ── Constants ─────────────────────────────────────────────────────────────────

const APPLET_AID = Buffer.from('536F6C616E6100', 'hex');
const CLA = 0xb0;
const DEFAULT_PUK = Buffer.from([0x41, 0x42, 0x43, 0x44, 0x45, 0x46]); // "ABCDEF"
const SOLANA_PATH = [0x8000002c, 0x800001f5, 0x80000000]; // m/44'/501'/0'
const TESTNET_RPC = 'https://api.devnet.solana.com';
const CHUNK_SIZE = 200; // bytes of message per APDU data field in INS_SIGN_TX

const INS = {
  SETUP: 0x2a,
  GET_STATUS: 0x3c,
  VERIFY_PIN: 0x42,
  IMPORT_SEED: 0x6c,
  GET_PUBLIC_KEY: 0x6d,
  SIGN_TX: 0x6f,
  INIT_SECURE_CHANNEL: 0x81,
  PROCESS_SECURE_CHANNEL: 0x82,
  EXPORT_AUTHENTIKEY: 0x73,
} as const;

const P1 = {
  FIRST: 0x01,
  LAST: 0x80,
  FIRST_LAST: 0x81,
  CONTINUATION: 0x00,
} as const;

const SW = {
  OK: 0x9000,
  SETUP_NOT_DONE: 0x9c04,
  SETUP_DONE: 0x9c03,
  UNAUTHORIZED: 0x9c06,
} as const;

// ── Secure Channel ────────────────────────────────────────────────────────────

/**
 * SECP256K1 ECDH + AES-128-CBC + HMAC-SHA1 secure channel.
 *
 * Protocol (from SecureChannel.java / PROTOCOL.md):
 *   Handshake:
 *     Host → Card: INS_INIT_SECURE_CHANNEL [65-byte uncompressed host pubkey]
 *     Card → Host: [coordX_size(2) | coordX(32) | sig1_size(2) | sig1 | sig2_size(2) | sig2]
 *
 *   Key derivation from shared ECDH X-coordinate:
 *     session_key = HMAC-SHA1(shared_X, "sc_key")[0:16]
 *     mac_key     = HMAC-SHA1(shared_X, "sc_mac")[0:20]
 *
 *   Wrapping (INS_PROCESS_SECURE_CHANNEL = 0x82):
 *     payload = IV(16) | data_size(2) | AES-CBC(inner_apdu) | mac_size(2) | HMAC-SHA1(20)
 *     IV[0:12]  = 12 random bytes
 *     IV[12:16] = 4-byte big-endian counter (must be strictly > card's last counter)
 *     IV[15]   |= 0x01  (last byte must be odd)
 *
 *   Response (encrypted only when inner command returns data):
 *     IV(16) | data_size(2) | AES-CBC(response+padding) | mac_size(2) | HMAC-SHA1(20)
 */
class SecureChannel {
  private sessionKey!: Buffer;
  private macKey!: Buffer;
  private hostECDH: crypto.ECDH;
  // Counter starts at 1 (odd). Incremented by 2 each command (stays odd, always > card counter).
  private counter = 1;

  constructor() {
    this.hostECDH = crypto.createECDH('secp256k1');
    this.hostECDH.generateKeys();
  }

  /** 65-byte uncompressed host ephemeral public key to send in INS_INIT_SECURE_CHANNEL. */
  getHostPublicKey(): Buffer {
    return this.hostECDH.getPublicKey() as Buffer;
  }

  /**
   * Derive session_key and mac_key from the card's handshake response.
   * respData is the response body (without SW bytes).
   *
   * The card returns only the X coordinate of its ephemeral key. We must
   * reconstruct the full compressed public key by trying both Y parities
   * (0x02 and 0x03) and using sig1 — which signs [coordX_size||coordX] with
   * the ephemeral private key — to identify the correct one.
   */
  processHandshakeResponse(respData: Buffer): void {
    // Parse: [coordX_size(2) | coordX(32) | sig1_size(2) | sig1 | sig2_size(2) | sig2]
    const coordXSize = respData.readUInt16BE(0);
    if (coordXSize !== 32)
      throw new Error(`Unexpected coordX size: ${coordXSize}`);
    const coordX = respData.subarray(2, 2 + coordXSize);

    let off = 2 + coordXSize;
    const sig1Size = respData.readUInt16BE(off);
    off += 2;
    const sig1 = respData.subarray(off, off + sig1Size);

    // The data signed by sig1: [coordX_size(2) | coordX(32)]
    const sig1Message = respData.subarray(0, 2 + coordXSize);

    // DER SPKI wrapper for a 33-byte compressed secp256k1 public key.
    // Structure: SEQUENCE { SEQUENCE { OID id-ecPublicKey, OID secp256k1 } BIT STRING { key } }
    //   30 36 30 10 06 07 2a 86 48 ce 3d 02 01 06 05 2b 81 04 00 0a 03 22 00 <33 bytes>
    const spkiPrefix = Buffer.from(
      '3036301006072a8648ce3d020106052b8104000a032200',
      'hex'
    );

    let sharedX: Buffer | null = null;
    for (const parity of [0x02, 0x03]) {
      const cardPubCompressed = Buffer.concat([Buffer.from([parity]), coordX]);
      const spkiDer = Buffer.concat([spkiPrefix, cardPubCompressed]);
      try {
        const pubKeyObj = crypto.createPublicKey({
          key: spkiDer,
          format: 'der',
          type: 'spki',
        });
        const verifier = crypto.createVerify('SHA256');
        verifier.update(sig1Message);
        if (verifier.verify(pubKeyObj, sig1)) {
          sharedX = Buffer.from(this.hostECDH.computeSecret(cardPubCompressed));
          break;
        }
      } catch {
        // Wrong parity or invalid point — try the other
      }
    }
    if (!sharedX)
      throw new Error(
        'SC handshake: sig1 did not verify for either Y parity — handshake failed'
      );

    this.sessionKey = this.hmacSha1(sharedX, Buffer.from('sc_key')).subarray(
      0,
      16
    );
    this.macKey = this.hmacSha1(sharedX, Buffer.from('sc_mac'));
  }

  /**
   * Build the INS_PROCESS_SECURE_CHANNEL payload wrapping an inner command.
   * Returns the bytes to use as the data field of the outer PROCESS_SECURE_CHANNEL APDU.
   */
  wrapCommand(ins: number, p1: number, p2: number, data?: Buffer): Buffer {
    // Inner APDU plaintext: [CLA, INS, P1, P2, Lc, data...]
    const inner =
      data && data.length > 0
        ? Buffer.concat([Buffer.from([CLA, ins, p1, p2, data.length]), data])
        : Buffer.from([CLA, ins, p1, p2, 0x00]);

    // PKCS#7 pad to AES block boundary (16 bytes)
    const padLen = 16 - (inner.length % 16);
    const padded = Buffer.concat([inner, Buffer.alloc(padLen, padLen)]);

    // IV: 12 random bytes || 4-byte big-endian counter (last byte must be odd)
    const iv = Buffer.alloc(16);
    crypto.randomBytes(12).copy(iv, 0);
    iv.writeUInt32BE(this.counter, 12);
    iv[15] |= 0x01; // ensure last byte is odd (counter is already odd, but be explicit)
    this.counter += 2; // advance by 2: 1→3→5→7…, always odd, always > card's incremented counter

    // Encrypt: AES-128-CBC(session_key, IV, padded_inner)
    const cipher = crypto.createCipheriv('aes-128-cbc', this.sessionKey, iv);
    cipher.setAutoPadding(false);
    const encrypted = Buffer.concat([cipher.update(padded), cipher.final()]);

    // MAC: HMAC-SHA1(mac_key, IV || data_size(2) || encrypted)
    const dataSize = Buffer.alloc(2);
    dataSize.writeUInt16BE(encrypted.length);
    const macInput = Buffer.concat([iv, dataSize, encrypted]);
    const mac = this.hmacSha1(this.macKey, macInput);

    // Assembled SC payload: IV(16) | data_size(2) | ciphertext | mac_size(2=0x0014) | mac(20)
    return Buffer.concat([
      iv,
      dataSize,
      encrypted,
      Buffer.from([0x00, 0x14]),
      mac,
    ]);
  }

  /**
   * Decrypt and verify an encrypted card response body (without SW bytes).
   * Returns the inner plaintext (with PKCS#7 padding stripped).
   * Returns an empty buffer if there is no response data.
   */
  unwrapResponse(data: Buffer): Buffer {
    // Minimum encrypted response: IV(16) + data_size(2) + 1 block(16) + mac_size(2) + mac(20) = 56
    if (data.length < 56) return Buffer.alloc(0);

    const iv = data.subarray(0, 16);
    const dataSize = data.readUInt16BE(16);
    const ciphertext = data.subarray(18, 18 + dataSize);

    // Verify response MAC: HMAC-SHA1(mac_key, IV || data_size(2) || ciphertext)
    const macOffset = 18 + dataSize;
    if (data.length >= macOffset + 2) {
      const macSize = data.readUInt16BE(macOffset);
      if (macSize === 20 && data.length >= macOffset + 2 + 20) {
        const receivedMac = data.subarray(macOffset + 2, macOffset + 2 + 20);
        const covered = data.subarray(0, macOffset);
        const expectedMac = this.hmacSha1(this.macKey, covered);
        if (!crypto.timingSafeEqual(receivedMac, expectedMac)) {
          throw new Error(
            'Secure channel response MAC verification failed — possible tampering'
          );
        }
      }
    }

    // Decrypt
    const decipher = crypto.createDecipheriv(
      'aes-128-cbc',
      this.sessionKey,
      iv
    );
    decipher.setAutoPadding(false);
    const padded = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    // Strip PKCS#7 padding
    const padByte = padded[padded.length - 1];
    return padded.subarray(0, padded.length - padByte);
  }

  private hmacSha1(key: Buffer, data: Buffer): Buffer {
    return crypto.createHmac('sha1', key).update(data).digest() as Buffer;
  }
}

// ── PC/SC types ───────────────────────────────────────────────────────────────

interface PcscReader {
  name: string;
  state: number;
  SCARD_STATE_PRESENT: number;
  SCARD_SHARE_SHARED: number;
  SCARD_LEAVE_CARD: number;
  connect(
    opts: { share_mode: number },
    cb: (err: Error | null, protocol: number) => void
  ): void;
  transmit(
    data: Buffer,
    maxLen: number,
    protocol: number,
    cb: (err: Error | null, response: Buffer) => void
  ): void;
  disconnect(disposition: number, cb: () => void): void;
  on(event: 'status', cb: (status: { state: number }) => void): void;
  on(event: 'error', cb: (err: Error) => void): void;
}

interface CardConn {
  reader: PcscReader;
  protocol: number;
}

// ── PC/SC helpers ─────────────────────────────────────────────────────────────

function connectCard(): Promise<CardConn> {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const pcsclite = require('pcsclite') as () => NodeJS.EventEmitter & {
    on(event: 'reader', cb: (reader: PcscReader) => void): void;
    on(event: 'error', cb: (err: Error) => void): void;
  };

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error('Timeout: no card detected after 30s')),
      30_000
    );

    const pcsc = pcsclite();

    pcsc.on('reader', (reader) => {
      log(`  Reader: ${reader.name}`);

      reader.on('status', (status) => {
        const changes = reader.state ^ status.state;
        if (
          changes & reader.SCARD_STATE_PRESENT &&
          status.state & reader.SCARD_STATE_PRESENT
        ) {
          log('  Card present — connecting...');
          reader.connect(
            { share_mode: reader.SCARD_SHARE_SHARED },
            (err, protocol) => {
              clearTimeout(timeout);
              if (err) reject(err);
              else resolve({ reader, protocol });
            }
          );
        }
      });

      reader.on('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    });

    pcsc.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });
    log('  Waiting for card...');
  });
}

function transmit(card: CardConn, apdu: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    card.reader.transmit(apdu, 4096, card.protocol, (err, data) => {
      if (err) reject(err);
      else resolve(data);
    });
  });
}

function sw(resp: Buffer): number {
  return ((resp[resp.length - 2] & 0xff) << 8) | (resp[resp.length - 1] & 0xff);
}

function respData(resp: Buffer): Buffer {
  return resp.subarray(0, -2);
}

async function apdu(
  card: CardConn,
  ins: number,
  p1: number,
  p2: number,
  payload?: Buffer
): Promise<Buffer> {
  let cmd: Buffer;
  if (!payload || payload.length === 0) {
    cmd = Buffer.from([CLA, ins, p1, p2, 0x00]);
  } else {
    cmd = Buffer.concat([
      Buffer.from([CLA, ins, p1, p2, payload.length]),
      payload,
      Buffer.from([0x00]),
    ]);
  }
  return transmit(card, cmd);
}

/**
 * Send a command wrapped inside INS_PROCESS_SECURE_CHANNEL.
 * Encrypts the command, sends it, decrypts the response.
 * Returns a synthetic response buffer: [plaintext_data...][0x90][0x00].
 * On inner-command error, returns [SW1][SW2] (the card's error SW, no data).
 */
async function scApdu(
  card: CardConn,
  sc: SecureChannel,
  ins: number,
  p1: number,
  p2: number,
  payload?: Buffer
): Promise<Buffer> {
  const wrappedPayload = sc.wrapCommand(ins, p1, p2, payload);
  const outerCmd = Buffer.concat([
    Buffer.from([
      CLA,
      INS.PROCESS_SECURE_CHANNEL,
      0x00,
      0x00,
      wrappedPayload.length,
    ]),
    wrappedPayload,
    Buffer.from([0x00]),
  ]);
  const outerResp = await transmit(card, outerCmd);
  const outerSW = sw(outerResp);
  const outerData = respData(outerResp);

  if (outerSW !== SW.OK) {
    // Inner command failed — pass through the SW bytes directly
    return outerResp.subarray(outerResp.length - 2);
  }

  if (outerData.length === 0) {
    // Inner command succeeded with no response data (e.g. VERIFY_PIN success)
    return Buffer.from([0x90, 0x00]);
  }

  // Decrypt and verify the response, then reattach a 9000 SW
  const plaintext = sc.unwrapResponse(outerData);
  return Buffer.concat([plaintext, Buffer.from([0x90, 0x00])]);
}

// ── Card: SELECT ──────────────────────────────────────────────────────────────

async function selectApplet(card: CardConn): Promise<void> {
  const cmd = Buffer.concat([
    Buffer.from([0x00, 0xa4, 0x04, 0x00, APPLET_AID.length]),
    APPLET_AID,
  ]);
  const resp = await transmit(card, cmd);
  if (sw(resp) !== SW.OK)
    throw new Error(`SELECT failed: ${sw(resp).toString(16).toUpperCase()}`);
}

// ── Card: INIT_SECURE_CHANNEL ─────────────────────────────────────────────────

async function initSecureChannel(card: CardConn): Promise<SecureChannel> {
  const sc = new SecureChannel();
  const hostPubKey = sc.getHostPublicKey(); // 65-byte uncompressed SECP256K1 pubkey

  const resp = await apdu(
    card,
    INS.INIT_SECURE_CHANNEL,
    0x00,
    0x00,
    hostPubKey
  );
  if (sw(resp) !== SW.OK)
    throw new Error(
      `INIT_SECURE_CHANNEL failed: ${sw(resp).toString(16).toUpperCase()}`
    );

  sc.processHandshakeResponse(respData(resp));
  return sc;
}

// ── Card: GET_STATUS ──────────────────────────────────────────────────────────

interface CardStatus {
  setupDone: boolean;
  isSeeded: boolean;
  pinTriesLeft: number;
  pinTriesMax: number;
}

async function getStatus(card: CardConn): Promise<CardStatus> {
  const resp = await apdu(card, INS.GET_STATUS, 0x00, 0x00);
  if (sw(resp) !== SW.OK)
    throw new Error(
      `GET_STATUS failed: ${sw(resp).toString(16).toUpperCase()}`
    );
  const d = respData(resp);
  return {
    setupDone: d[10] === 0x01,
    isSeeded: d[8] === 0x01,
    pinTriesLeft: d[4],
    pinTriesMax: d[5],
  };
}

// ── Card: SETUP ───────────────────────────────────────────────────────────────

async function setupCard(
  card: CardConn,
  sc: SecureChannel,
  pin: Buffer
): Promise<void> {
  const payload = Buffer.concat([
    Buffer.from([pin.length]),
    pin,
    Buffer.from([DEFAULT_PUK.length]),
    DEFAULT_PUK,
  ]);
  const resp = await scApdu(card, sc, INS.SETUP, 0x00, 0x00, payload);
  if (sw(resp) !== SW.OK)
    throw new Error(`SETUP failed: ${sw(resp).toString(16).toUpperCase()}`);
}

// ── Card: VERIFY_PIN ──────────────────────────────────────────────────────────

async function verifyPin(
  card: CardConn,
  sc: SecureChannel,
  pin: Buffer
): Promise<void> {
  const resp = await scApdu(card, sc, INS.VERIFY_PIN, 0x00, 0x00, pin);
  if (sw(resp) !== SW.OK) {
    const tries = sw(resp) & 0x0f;
    throw new Error(`PIN incorrect — ${tries} tries remaining`);
  }
}

// ── Card: IMPORT_SEED ─────────────────────────────────────────────────────────

async function importSeed(
  card: CardConn,
  sc: SecureChannel,
  seed64: Buffer
): Promise<Buffer> {
  if (seed64.length !== 64) throw new Error('Seed must be 64 bytes');
  const resp = await scApdu(card, sc, INS.IMPORT_SEED, 0x00, 0x00, seed64);
  if (sw(resp) !== SW.OK)
    throw new Error(
      `IMPORT_SEED failed: ${sw(resp).toString(16).toUpperCase()}`
    );
  return respData(resp); // 32-byte pubkey at m/44'/501'/0'
}

// ── Card: GET_PUBLIC_KEY ──────────────────────────────────────────────────────

async function getPublicKey(
  card: CardConn,
  sc: SecureChannel,
  path: number[]
): Promise<Buffer> {
  const buf = Buffer.alloc(1 + path.length * 4);
  buf[0] = path.length;
  for (let i = 0; i < path.length; i++) buf.writeUInt32BE(path[i], 1 + i * 4);
  const resp = await scApdu(card, sc, INS.GET_PUBLIC_KEY, 0x00, 0x00, buf);
  if (sw(resp) !== SW.OK)
    throw new Error(
      `GET_PUBLIC_KEY failed: ${sw(resp).toString(16).toUpperCase()}`
    );
  return respData(resp); // 32 bytes
}

// ── Card: SIGN_TX ─────────────────────────────────────────────────────────────

async function signTx(
  card: CardConn,
  sc: SecureChannel,
  path: number[],
  message: Buffer
): Promise<Buffer> {
  // Build path header: [depth (1)] [idx_0 (4)] ... [idx_n (4)]
  const header = Buffer.alloc(1 + path.length * 4);
  header[0] = path.length;
  for (let i = 0; i < path.length; i++)
    header.writeUInt32BE(path[i], 1 + i * 4);

  const firstMsgCap = CHUNK_SIZE - header.length;
  const firstMsg = message.subarray(0, firstMsgCap);
  const rest = message.subarray(firstMsgCap);

  // Slice rest into CHUNK_SIZE pieces
  const chunks: Buffer[] = [];
  for (let off = 0; off < rest.length; off += CHUNK_SIZE) {
    chunks.push(rest.subarray(off, off + CHUNK_SIZE));
  }

  let resp: Buffer;

  if (chunks.length === 0) {
    // Entire message fits in one APDU
    resp = await scApdu(
      card,
      sc,
      INS.SIGN_TX,
      P1.FIRST_LAST,
      0x00,
      Buffer.concat([header, firstMsg])
    );
    if (sw(resp) !== SW.OK)
      throw new Error(`SIGN_TX failed: ${sw(resp).toString(16).toUpperCase()}`);
    return respData(resp);
  }

  // First chunk
  resp = await scApdu(
    card,
    sc,
    INS.SIGN_TX,
    P1.FIRST,
    0x00,
    Buffer.concat([header, firstMsg])
  );
  if (sw(resp) !== SW.OK)
    throw new Error(
      `SIGN_TX first chunk failed: ${sw(resp).toString(16).toUpperCase()}`
    );

  // Middle chunks
  for (let i = 0; i < chunks.length - 1; i++) {
    resp = await scApdu(
      card,
      sc,
      INS.SIGN_TX,
      P1.CONTINUATION,
      0x00,
      chunks[i]
    );
    if (sw(resp) !== SW.OK)
      throw new Error(
        `SIGN_TX continuation failed: ${sw(resp).toString(16).toUpperCase()}`
      );
  }

  // Last chunk — returns 64-byte signature
  resp = await scApdu(
    card,
    sc,
    INS.SIGN_TX,
    P1.LAST,
    0x00,
    chunks[chunks.length - 1]
  );
  if (sw(resp) !== SW.OK)
    throw new Error(
      `SIGN_TX last chunk failed: ${sw(resp).toString(16).toUpperCase()}`
    );
  return respData(resp);
}

// ── Logging ───────────────────────────────────────────────────────────────────

function log(msg: string): void {
  console.log(msg);
}

function logStep(n: number, title: string): void {
  console.log(`\n── Step ${n}: ${title} ──`);
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === '--help') {
    console.log('Usage: ts-node index.ts "<bip39 mnemonic>" [--pin <pin>]');
    console.log('');
    console.log(
      '  Imports the mnemonic seed to the card, logs the Solana address,'
    );
    console.log('  and submits a test SOL transfer on testnet.');
    console.log('');
    console.log('  --pin <pin>   PIN for the card (default: 1234)');
    process.exit(args[0] === '--help' ? 0 : 1);
  }

  const mnemonic = args[0];
  const pinIdx = args.indexOf('--pin');
  const pinStr = pinIdx >= 0 ? args[pinIdx + 1] : '1234';
  const pin = Buffer.from(pinStr);

  if (pin.length < 4 || pin.length > 16) {
    console.error('ERROR: PIN must be 4–16 characters');
    process.exit(1);
  }

  if (!bip39.validateMnemonic(mnemonic)) {
    console.error('ERROR: Invalid BIP-39 mnemonic');
    process.exit(1);
  }

  // ── 1. Derive seed ────────────────────────────────────────────────────────
  logStep(1, 'Derive seed from mnemonic');
  const seed = await bip39.mnemonicToSeed(mnemonic); // Buffer, 64 bytes
  log(`  Mnemonic: ${mnemonic.split(' ').length} words`);
  log(`  Seed:     ${seed.toString('hex').slice(0, 32)}...`);

  // ── 2. Connect to card ────────────────────────────────────────────────────
  logStep(2, 'Connect to card via PC/SC');
  const card = await connectCard();
  log('  Connected.');
  await selectApplet(card);
  log('  TapiocaApplet selected.');

  // ── 3. Secure channel handshake ───────────────────────────────────────────
  logStep(3, 'Secure channel handshake');
  const sc = await initSecureChannel(card);
  log('  Secure channel established.');

  // ── 4. Card setup & PIN ───────────────────────────────────────────────────
  logStep(4, 'Card setup');
  const statusBefore = await getStatus(card);
  log(
    `  setup_done=${statusBefore.setupDone}  is_seeded=${statusBefore.isSeeded}  pin_tries_left=${statusBefore.pinTriesLeft}`
  );

  if (!statusBefore.setupDone) {
    log('  Card not set up — running SETUP (via secure channel)...');
    await setupCard(card, sc, pin);
    log('  SETUP complete.');
  }

  await verifyPin(card, sc, pin);
  log('  PIN verified.');

  // ── 5. Import seed ────────────────────────────────────────────────────────
  logStep(5, 'Import seed / read public key');
  let pubkeyBytes: Buffer;

  const statusAfterPin = await getStatus(card);
  if (!statusAfterPin.isSeeded) {
    log('  No seed on card — importing (~5–8s)...');
    const t0 = Date.now();
    pubkeyBytes = await importSeed(card, sc, seed);
    log(`  Seed imported in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  } else {
    log('  Card already seeded — reading public key...');
    pubkeyBytes = await getPublicKey(card, sc, SOLANA_PATH);
  }

  const address = new PublicKey(pubkeyBytes);
  log(`\n  ✓ Address (m/44'/501'/0'): ${address.toBase58()}`);

  // ── 6. Solana testnet connection ──────────────────────────────────────────
  logStep(6, 'Connect to Solana testnet');
  const connection = new Connection(TESTNET_RPC, 'confirmed');
  const version = await connection.getVersion();
  log(`  RPC:     ${TESTNET_RPC}`);
  log(`  Version: ${version['solana-core']}`);

  // ── 7. Fund account if needed ─────────────────────────────────────────────
  logStep(7, 'Check / fund account');
  let balance = await connection.getBalance(address);
  log(
    `  Balance: ${(balance / LAMPORTS_PER_SOL).toFixed(6)} SOL (${balance} lamports)`
  );

  if (balance < 0.01 * LAMPORTS_PER_SOL) {
    log('  Balance below 0.01 SOL — requesting airdrop (1 SOL)...');
    const airdropSig = await connection.requestAirdrop(
      address,
      LAMPORTS_PER_SOL
    );
    const { blockhash: abh, lastValidBlockHeight: alvbh } =
      await connection.getLatestBlockhash();
    await connection.confirmTransaction(
      { signature: airdropSig, blockhash: abh, lastValidBlockHeight: alvbh },
      'confirmed'
    );
    balance = await connection.getBalance(address);
    log(
      `  Airdrop confirmed. New balance: ${(balance / LAMPORTS_PER_SOL).toFixed(6)} SOL`
    );
  }

  const transferAmount = await connection.getMinimumBalanceForRentExemption(0);
  const signTimings: number[] = [];

  for (let txNum = 1; txNum <= 2; txNum++) {
    // ── 8/12. Build transaction ─────────────────────────────────────────────
    logStep(txNum === 1 ? 8 : 12, `Build transfer transaction (tx ${txNum}/2)`);
    const recipient = Keypair.generate();
    log(`  From:      ${address.toBase58()}`);
    log(`  To:        ${recipient.publicKey.toBase58()} (throwaway)`);
    log(`  Amount:    ${transferAmount} lamports (rent-exempt minimum)`);

    const { blockhash, lastValidBlockHeight } =
      await connection.getLatestBlockhash();

    const tx = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: address,
        toPubkey: recipient.publicKey,
        lamports: transferAmount,
      })
    );
    tx.recentBlockhash = blockhash;
    tx.feePayer = address;

    const msgBytes = tx.serializeMessage();
    log(`  Message:   ${msgBytes.length} bytes`);

    // ── 9/13. Sign on card ──────────────────────────────────────────────────
    logStep(txNum === 1 ? 9 : 13, `Sign on card (tx ${txNum}/2)`);
    log(
      txNum === 1
        ? '  Signing tx 1 — expect key setup + sign (~4s if re-derivation, ~1.4s if cached)...'
        : '  Signing tx 2 — timing reveals whether re-derivation occurs on every sign...'
    );
    const tSign = Date.now();
    const sigBytes = await signTx(card, sc, SOLANA_PATH, msgBytes);
    const elapsed = (Date.now() - tSign) / 1000;
    signTimings.push(elapsed);
    log(`  Done in ${elapsed.toFixed(3)}s`);
    log(`  Signature: ${sigBytes.toString('hex').slice(0, 32)}...`);

    // ── 10/14. Attach signature, verify, broadcast ──────────────────────────
    logStep(txNum === 1 ? 10 : 14, `Broadcast transaction (tx ${txNum}/2)`);
    tx.addSignature(address, sigBytes);

    if (!tx.verifySignatures()) {
      throw new Error(
        `Signature verification failed for tx ${txNum} — card returned an invalid signature`
      );
    }
    log('  Signature verified locally ✓');

    const rawTx = tx.serialize();
    const txSig = await connection.sendRawTransaction(rawTx, {
      skipPreflight: false,
    });
    log(`  Sent: ${txSig}`);

    // ── 11/15. Confirm ──────────────────────────────────────────────────────
    logStep(txNum === 1 ? 11 : 15, `Confirm (tx ${txNum}/2)`);
    log('  Waiting for confirmation...');
    await connection.confirmTransaction(
      { signature: txSig, blockhash, lastValidBlockHeight },
      'confirmed'
    );

    const balance = await connection.getBalance(address);
    console.log(`
  ✓ Tx ${txNum} confirmed!
  TxID:     ${txSig}
  Balance:  ${(balance / LAMPORTS_PER_SOL).toFixed(6)} SOL
  Explorer: https://explorer.solana.com/tx/${txSig}?cluster=devnet`);
  }

  // ── 16. Timing summary ────────────────────────────────────────────────────
  logStep(16, 'Sign timing summary');
  const [t1, t2] = signTimings;
  const delta = t2 - t1;
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║  Sign timing results                                         ║
╚══════════════════════════════════════════════════════════════╝
  Tx 1 sign time: ${t1.toFixed(3)}s
  Tx 2 sign time: ${t2.toFixed(3)}s
  Delta (tx2-tx1): ${delta >= 0 ? '+' : ''}${delta.toFixed(3)}s
`);

  card.reader.disconnect(card.reader.SCARD_LEAVE_CARD, () => {
    console.log('  Card disconnected, exiting.');
    process.exit(0);
  });
}

main().catch((err: Error) => {
  console.error(`\nERROR: ${err.message}`);
  process.exit(1);
});
