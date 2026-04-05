#!/usr/bin/env ts-node
/**
 * TapiocaApplet — end-to-end test suite
 *
 * Runs against a real (or simulated) JavaCard via PC/SC.
 * Tests must run sequentially — card state carries between tests.
 *
 * Usage:
 *   ts-node applet.test.ts
 *   ts-node applet.test.ts --pin 5678
 */

import * as crypto from 'crypto';
import * as bip39 from 'bip39';

// ── Constants ────────────────────────────────────────────────────────────────

const APPLET_AID = Buffer.from('536F6C616E6100', 'hex');
const CLA = 0xb0;
const DEFAULT_PIN = Buffer.from('1234');
const DEFAULT_PUK = Buffer.from([0x41, 0x42, 0x43, 0x44, 0x45, 0x46]); // "ABCDEF"
const SOLANA_PATH = [0x8000002c, 0x800001f5, 0x80000000]; // m/44'/501'/0'
const CHUNK_SIZE = 200;

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const INS = {
  SETUP: 0x2a,
  GET_STATUS: 0x3c,
  CARD_LABEL: 0x3d,
  VERIFY_PIN: 0x42,
  CHANGE_PIN: 0x44,
  UNBLOCK_PIN: 0x46,
  IMPORT_SEED: 0x6c,
  GET_PUBLIC_KEY: 0x6d,
  SIGN_TX: 0x6f,
  EXPORT_AUTHENTIKEY: 0x73,
  RESET_SEED: 0x77,
  INIT_SECURE_CHANNEL: 0x81,
  PROCESS_SECURE_CHANNEL: 0x82,
  RESET_TO_FACTORY: 0xff,
} as const;

const P1 = {
  FIRST: 0x01,
  LAST: 0x80,
  FIRST_LAST: 0x81,
  CONTINUATION: 0x00,
} as const;

const SW = {
  OK: 0x9000,
  RESET_TO_FACTORY: 0xff00,
  SETUP_ALREADY_DONE: 0x9c03,
  SETUP_NOT_DONE: 0x9c04,
  UNAUTHORIZED: 0x9c06,
  IDENTITY_BLOCKED: 0x9c0c,
} as const;

// ── Secure Channel ───────────────────────────────────────────────────────────

class SecureChannel {
  private sessionKey!: Buffer;
  private macKey!: Buffer;
  private hostECDH: crypto.ECDH;
  private counter = 1;

  constructor() {
    this.hostECDH = crypto.createECDH('secp256k1');
    this.hostECDH.generateKeys();
  }

  getHostPublicKey(): Buffer {
    return this.hostECDH.getPublicKey() as Buffer;
  }

  processHandshakeResponse(respData: Buffer): void {
    const coordXSize = respData.readUInt16BE(0);
    if (coordXSize !== 32)
      throw new Error(`Unexpected coordX size: ${coordXSize}`);
    const coordX = respData.subarray(2, 2 + coordXSize);

    let off = 2 + coordXSize;
    const sig1Size = respData.readUInt16BE(off);
    off += 2;
    const sig1 = respData.subarray(off, off + sig1Size);

    const sig1Message = respData.subarray(0, 2 + coordXSize);

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
        // Wrong parity — try the other
      }
    }
    if (!sharedX)
      throw new Error('SC handshake: sig1 did not verify for either Y parity');

    this.sessionKey = this.hmacSha1(sharedX, Buffer.from('sc_key')).subarray(
      0,
      16
    );
    this.macKey = this.hmacSha1(sharedX, Buffer.from('sc_mac'));
  }

  wrapCommand(ins: number, p1: number, p2: number, data?: Buffer): Buffer {
    const inner =
      data && data.length > 0
        ? Buffer.concat([Buffer.from([CLA, ins, p1, p2, data.length]), data])
        : Buffer.from([CLA, ins, p1, p2, 0x00]);

    const padLen = 16 - (inner.length % 16);
    const padded = Buffer.concat([inner, Buffer.alloc(padLen, padLen)]);

    const iv = Buffer.alloc(16);
    crypto.randomBytes(12).copy(iv, 0);
    iv.writeUInt32BE(this.counter, 12);
    iv[15] |= 0x01;
    this.counter += 2;

    const cipher = crypto.createCipheriv('aes-128-cbc', this.sessionKey, iv);
    cipher.setAutoPadding(false);
    const encrypted = Buffer.concat([cipher.update(padded), cipher.final()]);

    const dataSize = Buffer.alloc(2);
    dataSize.writeUInt16BE(encrypted.length);
    const macInput = Buffer.concat([iv, dataSize, encrypted]);
    const mac = this.hmacSha1(this.macKey, macInput);

    return Buffer.concat([
      iv,
      dataSize,
      encrypted,
      Buffer.from([0x00, 0x14]),
      mac,
    ]);
  }

  unwrapResponse(data: Buffer): Buffer {
    if (data.length < 56) return Buffer.alloc(0);

    const iv = data.subarray(0, 16);
    const dataSize = data.readUInt16BE(16);
    const ciphertext = data.subarray(18, 18 + dataSize);

    const macOffset = 18 + dataSize;
    if (data.length >= macOffset + 2) {
      const macSize = data.readUInt16BE(macOffset);
      if (macSize === 20 && data.length >= macOffset + 2 + 20) {
        const receivedMac = data.subarray(macOffset + 2, macOffset + 2 + 20);
        const covered = data.subarray(0, macOffset);
        const expectedMac = this.hmacSha1(this.macKey, covered);
        if (!crypto.timingSafeEqual(receivedMac, expectedMac)) {
          throw new Error('Secure channel response MAC verification failed');
        }
      }
    }

    const decipher = crypto.createDecipheriv(
      'aes-128-cbc',
      this.sessionKey,
      iv
    );
    decipher.setAutoPadding(false);
    const decPadded = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    const padByte = decPadded[decPadded.length - 1];
    return decPadded.subarray(0, decPadded.length - padByte);
  }

  private hmacSha1(key: Buffer, data: Buffer): Buffer {
    return crypto.createHmac('sha1', key).update(data).digest() as Buffer;
  }
}

// ── PC/SC types ──────────────────────────────────────────────────────────────

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

// ── PC/SC helpers ────────────────────────────────────────────────────────────

function connectCard(): Promise<CardConn> {
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
      reader.on('status', (status) => {
        const changes = reader.state ^ status.state;
        if (
          changes & reader.SCARD_STATE_PRESENT &&
          status.state & reader.SCARD_STATE_PRESENT
        ) {
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
  });
}

function transmit(card: CardConn, apduBuf: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    card.reader.transmit(apduBuf, 4096, card.protocol, (err, data) => {
      if (err) reject(err);
      else resolve(data);
    });
  });
}

function swCode(resp: Buffer): number {
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
  const outerSW = swCode(outerResp);
  const outerData = respData(outerResp);

  if (outerSW !== SW.OK) {
    return outerResp.subarray(outerResp.length - 2);
  }

  if (outerData.length === 0) {
    return Buffer.from([0x90, 0x00]);
  }

  const plaintext = sc.unwrapResponse(outerData);
  return Buffer.concat([plaintext, Buffer.from([0x90, 0x00])]);
}

// ── Applet helpers ───────────────────────────────────────────────────────────

async function selectApplet(card: CardConn): Promise<void> {
  const cmd = Buffer.concat([
    Buffer.from([0x00, 0xa4, 0x04, 0x00, APPLET_AID.length]),
    APPLET_AID,
  ]);
  const resp = await transmit(card, cmd);
  if (swCode(resp) !== SW.OK)
    throw new Error(
      `SELECT failed: ${swCode(resp).toString(16).toUpperCase()}`
    );
}

async function initSecureChannel(card: CardConn): Promise<SecureChannel> {
  const sc = new SecureChannel();
  const hostPubKey = sc.getHostPublicKey();
  const resp = await apdu(
    card,
    INS.INIT_SECURE_CHANNEL,
    0x00,
    0x00,
    hostPubKey
  );
  if (swCode(resp) !== SW.OK)
    throw new Error(
      `INIT_SECURE_CHANNEL failed: ${swCode(resp).toString(16).toUpperCase()}`
    );
  sc.processHandshakeResponse(respData(resp));
  return sc;
}

interface CardStatus {
  setupDone: boolean;
  isSeeded: boolean;
  pinTriesLeft: number;
  pinTriesMax: number;
  pukTriesLeft: number;
  pukTriesMax: number;
}

async function getStatus(card: CardConn): Promise<CardStatus> {
  const resp = await apdu(card, INS.GET_STATUS, 0x00, 0x00);
  if (swCode(resp) !== SW.OK)
    throw new Error(
      `GET_STATUS failed: ${swCode(resp).toString(16).toUpperCase()}`
    );
  const d = respData(resp);
  return {
    setupDone: d[10] === 0x01,
    isSeeded: d[8] === 0x01,
    pinTriesLeft: d[4],
    pinTriesMax: d[5],
    pukTriesLeft: d[6],
    pukTriesMax: d[7],
  };
}

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
  if (swCode(resp) !== SW.OK)
    throw new Error(`SETUP failed: ${swCode(resp).toString(16).toUpperCase()}`);
}

async function verifyPinRaw(
  card: CardConn,
  sc: SecureChannel,
  pin: Buffer
): Promise<Buffer> {
  return scApdu(card, sc, INS.VERIFY_PIN, 0x00, 0x00, pin);
}

async function verifyPin(
  card: CardConn,
  sc: SecureChannel,
  pin: Buffer
): Promise<void> {
  const resp = await verifyPinRaw(card, sc, pin);
  if (swCode(resp) !== SW.OK)
    throw new Error(
      `VERIFY_PIN failed: ${swCode(resp).toString(16).toUpperCase()}`
    );
}

async function importSeed(
  card: CardConn,
  sc: SecureChannel,
  seed64: Buffer
): Promise<Buffer> {
  if (seed64.length !== 64) throw new Error('Seed must be 64 bytes');
  const resp = await scApdu(card, sc, INS.IMPORT_SEED, 0x00, 0x00, seed64);
  if (swCode(resp) !== SW.OK)
    throw new Error(
      `IMPORT_SEED failed: ${swCode(resp).toString(16).toUpperCase()}`
    );
  return respData(resp);
}

async function getPublicKey(
  card: CardConn,
  sc: SecureChannel,
  path: number[]
): Promise<Buffer> {
  const buf = Buffer.alloc(1 + path.length * 4);
  buf[0] = path.length;
  for (let i = 0; i < path.length; i++) buf.writeUInt32BE(path[i], 1 + i * 4);
  const resp = await scApdu(card, sc, INS.GET_PUBLIC_KEY, 0x00, 0x00, buf);
  if (swCode(resp) !== SW.OK)
    throw new Error(
      `GET_PUBLIC_KEY failed: ${swCode(resp).toString(16).toUpperCase()}`
    );
  return respData(resp);
}

async function signTx(
  card: CardConn,
  sc: SecureChannel,
  path: number[],
  message: Buffer
): Promise<Buffer> {
  const header = Buffer.alloc(1 + path.length * 4);
  header[0] = path.length;
  for (let i = 0; i < path.length; i++)
    header.writeUInt32BE(path[i], 1 + i * 4);

  const firstMsgCap = CHUNK_SIZE - header.length;
  const firstMsg = message.subarray(0, firstMsgCap);
  const rest = message.subarray(firstMsgCap);

  const chunks: Buffer[] = [];
  for (let off = 0; off < rest.length; off += CHUNK_SIZE) {
    chunks.push(rest.subarray(off, off + CHUNK_SIZE));
  }

  let resp: Buffer;

  if (chunks.length === 0) {
    resp = await scApdu(
      card,
      sc,
      INS.SIGN_TX,
      P1.FIRST_LAST,
      0x00,
      Buffer.concat([header, firstMsg])
    );
    if (swCode(resp) !== SW.OK)
      throw new Error(
        `SIGN_TX failed: ${swCode(resp).toString(16).toUpperCase()}`
      );
    return respData(resp);
  }

  resp = await scApdu(
    card,
    sc,
    INS.SIGN_TX,
    P1.FIRST,
    0x00,
    Buffer.concat([header, firstMsg])
  );
  if (swCode(resp) !== SW.OK)
    throw new Error(
      `SIGN_TX first chunk failed: ${swCode(resp).toString(16).toUpperCase()}`
    );

  for (let i = 0; i < chunks.length - 1; i++) {
    resp = await scApdu(
      card,
      sc,
      INS.SIGN_TX,
      P1.CONTINUATION,
      0x00,
      chunks[i]
    );
    if (swCode(resp) !== SW.OK)
      throw new Error(
        `SIGN_TX continuation failed: ${swCode(resp).toString(16).toUpperCase()}`
      );
  }

  resp = await scApdu(
    card,
    sc,
    INS.SIGN_TX,
    P1.LAST,
    0x00,
    chunks[chunks.length - 1]
  );
  if (swCode(resp) !== SW.OK)
    throw new Error(
      `SIGN_TX last chunk failed: ${swCode(resp).toString(16).toUpperCase()}`
    );
  return respData(resp);
}

async function changePinRaw(
  card: CardConn,
  sc: SecureChannel,
  oldPin: Buffer,
  newPin: Buffer
): Promise<Buffer> {
  const payload = Buffer.concat([
    Buffer.from([oldPin.length]),
    oldPin,
    Buffer.from([newPin.length]),
    newPin,
  ]);
  return scApdu(card, sc, INS.CHANGE_PIN, 0x00, 0x00, payload);
}

async function changePin(
  card: CardConn,
  sc: SecureChannel,
  oldPin: Buffer,
  newPin: Buffer
): Promise<void> {
  const resp = await changePinRaw(card, sc, oldPin, newPin);
  if (swCode(resp) !== SW.OK)
    throw new Error(
      `CHANGE_PIN failed: ${swCode(resp).toString(16).toUpperCase()}`
    );
}

async function unblockPin(
  card: CardConn,
  sc: SecureChannel,
  puk: Buffer,
  newPin: Buffer
): Promise<void> {
  const payload = Buffer.concat([
    Buffer.from([puk.length]),
    puk,
    Buffer.from([newPin.length]),
    newPin,
  ]);
  const resp = await scApdu(card, sc, INS.UNBLOCK_PIN, 0x00, 0x00, payload);
  if (swCode(resp) !== SW.OK)
    throw new Error(
      `UNBLOCK_PIN failed: ${swCode(resp).toString(16).toUpperCase()}`
    );
}

async function getLabel(card: CardConn): Promise<string> {
  const resp = await apdu(card, INS.CARD_LABEL, 0x00, 0x00);
  if (swCode(resp) !== SW.OK)
    throw new Error(
      `GET_LABEL failed: ${swCode(resp).toString(16).toUpperCase()}`
    );
  const d = respData(resp);
  if (d.length === 0) return '';
  const labelLen = d[0];
  if (labelLen === 0) return '';
  return d.subarray(1, 1 + labelLen).toString('utf8');
}

async function setLabel(
  card: CardConn,
  sc: SecureChannel,
  label: string
): Promise<void> {
  const labelBuf = Buffer.from(label, 'utf8');
  const payload = Buffer.concat([Buffer.from([labelBuf.length]), labelBuf]);
  const resp = await scApdu(card, sc, INS.CARD_LABEL, 0x01, 0x00, payload);
  if (swCode(resp) !== SW.OK)
    throw new Error(
      `SET_LABEL failed: ${swCode(resp).toString(16).toUpperCase()}`
    );
}

async function resetSeed(card: CardConn, sc: SecureChannel): Promise<void> {
  const resp = await scApdu(card, sc, INS.RESET_SEED, 0x00, 0x00);
  if (swCode(resp) !== SW.OK)
    throw new Error(
      `RESET_SEED failed: ${swCode(resp).toString(16).toUpperCase()}`
    );
}

async function resetToFactory(
  card: CardConn,
  sc: SecureChannel
): Promise<Buffer> {
  return scApdu(card, sc, INS.RESET_TO_FACTORY, 0x00, 0x00);
}

// ── Ed25519 verification helper ──────────────────────────────────────────────

function verifyEd25519(
  pubkey: Buffer,
  message: Buffer,
  signature: Buffer
): boolean {
  const keyObj = crypto.createPublicKey({
    key: Buffer.concat([
      // Ed25519 SPKI DER prefix (12 bytes) + 32-byte key
      Buffer.from('302a300506032b6570032100', 'hex'),
      pubkey,
    ]),
    format: 'der',
    type: 'spki',
  });
  return crypto.verify(null, message, keyObj, signature);
}

// ── Test runner ──────────────────────────────────────────────────────────────

interface TestResult {
  name: string;
  passed: boolean;
  error?: string;
}

const results: TestResult[] = [];

function assert(condition: boolean, msg: string): void {
  if (!condition) throw new Error(`Assertion failed: ${msg}`);
}

function assertEqual(actual: unknown, expected: unknown, msg: string): void {
  if (actual !== expected)
    throw new Error(`${msg}: expected ${expected}, got ${actual}`);
}

async function runTest(name: string, fn: () => Promise<void>): Promise<void> {
  process.stdout.write(`  ${name} ... `);
  try {
    await fn();
    results.push({ name, passed: true });
    console.log('\x1b[32mPASS\x1b[0m');
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    results.push({ name, passed: false, error: message });
    console.log(`\x1b[31mFAIL\x1b[0m — ${message}`);
  }
}

// ── Main test suite ──────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const pinIdx = args.indexOf('--pin');
  const pinStr = pinIdx >= 0 ? args[pinIdx + 1] : '1234';
  const pin = Buffer.from(pinStr);

  console.log('\nConnecting to card...');
  const card = await connectCard();
  console.log('Connected. Selecting applet...');
  await selectApplet(card);
  console.log('Applet selected. Establishing secure channel...');
  let sc = await initSecureChannel(card);
  console.log('Secure channel ready.\n');

  // Derive seed from test mnemonic
  const seed = await bip39.mnemonicToSeed(TEST_MNEMONIC);
  let savedPubkey: Buffer;

  console.log('Running tests:\n');

  // ── Factory reset first to ensure clean state ──────────────────────────────
  // Try to set up and verify PIN so we can factory reset, or skip if already fresh
  {
    const status = await getStatus(card);
    if (status.setupDone) {
      // Card was left in a setup state — attempt to reset it
      try {
        await verifyPin(card, sc, pin);
        await resetToFactory(card, sc);
      } catch {
        // If PIN doesn't match, we can't reset — tests may fail
      }
      // Reconnect: factory reset clears SC and session
      await selectApplet(card);
      sc = await initSecureChannel(card);
    }
  }

  // ── Tests ──────────────────────────────────────────────────────────────────

  await runTest('getStatus: fresh card reports setup not done', async () => {
    const status = await getStatus(card);
    assertEqual(status.setupDone, false, 'setupDone');
    assertEqual(status.isSeeded, false, 'isSeeded');
  });

  await runTest('setup: initialises PIN and PUK', async () => {
    await setupCard(card, sc, pin);
  });

  await runTest('getStatus: setup done after setup()', async () => {
    const status = await getStatus(card);
    assertEqual(status.setupDone, true, 'setupDone');
    assertEqual(status.isSeeded, false, 'isSeeded');
  });

  await runTest(
    'setup: second call throws SETUP_ALREADY_DONE (0x9C03)',
    async () => {
      const payload = Buffer.concat([
        Buffer.from([pin.length]),
        pin,
        Buffer.from([DEFAULT_PUK.length]),
        DEFAULT_PUK,
      ]);
      const resp = await scApdu(card, sc, INS.SETUP, 0x00, 0x00, payload);
      assertEqual(swCode(resp), SW.SETUP_ALREADY_DONE, 'SW');
    }
  );

  await runTest(
    'verifyPin: each wrong attempt returns correct SW and triesRemaining',
    async () => {
      const wrongPin = Buffer.from('9999');
      const maxTries = (await getStatus(card)).pinTriesMax;

      // Use up to maxTries - 2 wrong attempts so we don't block the card
      // (leave at least 2 tries: one for the blocking test, one for correct PIN)
      const wrongAttempts = Math.min(3, maxTries - 2);

      for (let i = 0; i < wrongAttempts; i++) {
        const resp = await verifyPinRaw(card, sc, wrongPin);
        const code = swCode(resp);
        const expectedRemaining = maxTries - (i + 1);
        const expectedSW = 0x63c0 | expectedRemaining;
        assertEqual(code, expectedSW, `attempt ${i + 1} SW`);
      }
    }
  );

  await runTest(
    'verifyPin: correct PIN resets tries and succeeds',
    async () => {
      await verifyPin(card, sc, pin);
      const status = await getStatus(card);
      assertEqual(
        status.pinTriesLeft,
        status.pinTriesMax,
        'pinTriesLeft should be restored'
      );
    }
  );

  await runTest(
    'verifyPin: last wrong attempt blocks card (0x9C0C)',
    async () => {
      // Drain all remaining tries with wrong PIN.
      const wrongPin = Buffer.from('9999');
      const status = await getStatus(card);
      const remaining = status.pinTriesLeft;

      for (let i = 0; i < remaining; i++) {
        const resp = await verifyPinRaw(card, sc, wrongPin);
        const code = swCode(resp);
        const expectedSW = 0x63c0 | (remaining - (i + 1));
        assertEqual(code, expectedSW, `drain attempt ${i + 1} SW`);
      }

      // Card is now blocked — next attempt must return IDENTITY_BLOCKED
      const blockedResp = await verifyPinRaw(card, sc, wrongPin);
      assertEqual(swCode(blockedResp), SW.IDENTITY_BLOCKED, 'blocked card SW');
    }
  );

  await runTest(
    'unblockPin: PUK unblocks card and restores correct PIN',
    async () => {
      await unblockPin(card, sc, DEFAULT_PUK, pin);
      // Re-select applet to clear transient state, then establish fresh secure channel
      //await selectApplet(card);
      sc = await initSecureChannel(card);
      // Verify the new PIN works
      await verifyPin(card, sc, pin);
      const status = await getStatus(card);
      assertEqual(
        status.pinTriesLeft,
        status.pinTriesMax,
        'pinTriesLeft should be restored'
      );
    }
  );

  await runTest('importSeed: returns 32-byte Ed25519 public key', async () => {
    const pubkey = await importSeed(card, sc, seed);
    assertEqual(pubkey.length, 32, 'pubkey length');
    savedPubkey = pubkey;
  });

  await runTest('getStatus: isSeeded true after importSeed()', async () => {
    const status = await getStatus(card);
    assertEqual(status.isSeeded, true, 'isSeeded');
    assertEqual(status.setupDone, true, 'setupDone');
  });

  await runTest(
    'getPublicKey: returns same 32-byte key as importSeed()',
    async () => {
      const pubkey = await getPublicKey(card, sc, SOLANA_PATH);
      assertEqual(pubkey.length, 32, 'pubkey length');
      assert(
        pubkey.equals(savedPubkey!),
        'pubkey should match importSeed result'
      );
    }
  );

  await runTest(
    'signTransaction: returns valid 64-byte Ed25519 signature',
    async () => {
      const message = crypto.randomBytes(64);
      const sig = await signTx(card, sc, SOLANA_PATH, message);
      assertEqual(sig.length, 64, 'signature length');
      assert(
        verifyEd25519(savedPubkey!, message, sig),
        'signature should verify'
      );
    }
  );

  await runTest(
    'signTransaction: large message (multi-chunk) produces valid signature',
    async () => {
      const message = crypto.randomBytes(500);
      const sig = await signTx(card, sc, SOLANA_PATH, message);
      assertEqual(sig.length, 64, 'signature length');
      assert(
        verifyEd25519(savedPubkey!, message, sig),
        'signature should verify'
      );
    }
  );

  await runTest('getLabel: returns empty string on fresh card', async () => {
    const label = await getLabel(card);
    assertEqual(label, '', 'label should be empty');
  });

  await runTest('setLabel / getLabel: round-trips a UTF-8 label', async () => {
    const testLabel = 'My Tapioca Card';
    await setLabel(card, sc, testLabel);
    const label = await getLabel(card);
    assertEqual(label, testLabel, 'label');
  });

  await runTest('setLabel: clears label when given empty string', async () => {
    await setLabel(card, sc, '');
    const label = await getLabel(card);
    assertEqual(label, '', 'label should be empty after clear');
  });

  await runTest('changePin: new PIN accepted after change', async () => {
    const newPin = Buffer.from('5678');
    await changePin(card, sc, pin, newPin);
    // Verify new PIN works
    await verifyPin(card, sc, newPin);
  });

  await runTest('changePin: restore original PIN', async () => {
    const tempPin = Buffer.from('5678');
    await changePin(card, sc, tempPin, pin);
    await verifyPin(card, sc, pin);
  });

  await runTest(
    'resetSeed: clears seed; getStatus shows isSeeded=false',
    async () => {
      await resetSeed(card, sc);
      const status = await getStatus(card);
      assertEqual(status.isSeeded, false, 'isSeeded');
      assertEqual(status.setupDone, true, 'setupDone should still be true');
    }
  );

  await runTest(
    're-importSeed: produces the same public key as the first import',
    async () => {
      // Re-select applet to clear transient state, then establish fresh secure channel
      //await selectApplet(card);
      sc = await initSecureChannel(card);
      await verifyPin(card, sc, pin);
      const pubkey = await importSeed(card, sc, seed);
      assertEqual(pubkey.length, 32, 'pubkey length');
      assert(
        pubkey.equals(savedPubkey!),
        'pubkey should match first importSeed result'
      );
    }
  );

  await runTest(
    'resetToFactory: wipes card; status shows setup not done',
    async () => {
      const resp = await resetToFactory(card, sc);
      assertEqual(swCode(resp), SW.RESET_TO_FACTORY, 'SW should be 0xFF00');

      // Re-establish secure channel after factory reset
      await selectApplet(card);
      sc = await initSecureChannel(card);

      const status = await getStatus(card);
      assertEqual(status.setupDone, false, 'setupDone');
      assertEqual(status.isSeeded, false, 'isSeeded');
    }
  );

  // ── Summary ────────────────────────────────────────────────────────────────

  console.log('\n── Results ──');
  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed).length;
  console.log(
    `  ${passed} passed, ${failed} failed, ${results.length} total\n`
  );

  if (failed > 0) {
    console.log('Failures:');
    for (const r of results.filter((r) => !r.passed)) {
      console.log(`  \x1b[31m✗\x1b[0m ${r.name}: ${r.error}`);
    }
    console.log('');
  }

  card.reader.disconnect(card.reader.SCARD_LEAVE_CARD, () => {
    process.exit(failed > 0 ? 1 : 0);
  });
}

main().catch((err: Error) => {
  console.error(`\nFATAL: ${err.message}`);
  process.exit(1);
});
