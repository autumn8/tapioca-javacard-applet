#!/usr/bin/env ts-node
/**
 * setup-fresh-card.ts — provision a fresh TapiocaApplet card
 *
 * Usage:
 *   ts-node setup-fresh-card.ts [mnemonic] [--pin <pin>] [--puk <puk>]
 *
 * Flow:
 *   1. Generate (or accept) a BIP-39 mnemonic
 *   2. Connect to card via PC/SC, select TapiocaApplet
 *   3. Setup card with PIN/PUK
 *   4. Verify PIN
 *   5. Import seed → card derives m/44'/501'/0', returns pubkey
 *   6. Write mnemonic and public address to card-info.json
 *   7. Log mnemonic and address to console
 * 
 *  N.B. Never store real mnemonics or use real funds with this script, as the mnemonic and PIN/PUK are written in plaintext to a local file. 
 */

import * as fs from 'fs';
import * as path from 'path';
import * as bip39 from 'bip39';
import { PublicKey } from '@solana/web3.js';
import { SecureChannel } from './secure-channel';

// ── Constants ─────────────────────────────────────────────────────────────────

const APPLET_AID = Buffer.from('536F6C616E6100', 'hex');
const CLA = 0xb0;
const INS = {
  SETUP: 0x2a,
  GET_STATUS: 0x3c,
  VERIFY_PIN: 0x42,
  IMPORT_SEED: 0x6c,
} as const;

const SW = {
  OK: 0x9000,
} as const;

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

function transmit(card: CardConn, apduBuf: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    card.reader.transmit(apduBuf, 4096, card.protocol, (err, data) => {
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

// ── Card operations ───────────────────────────────────────────────────────────

async function selectApplet(card: CardConn): Promise<void> {
  const cmd = Buffer.concat([
    Buffer.from([0x00, 0xa4, 0x04, 0x00, APPLET_AID.length]),
    APPLET_AID,
  ]);
  const resp = await transmit(card, cmd);
  if (sw(resp) !== SW.OK)
    throw new Error(`SELECT failed: ${sw(resp).toString(16).toUpperCase()}`);
}

interface CardStatus {
  setupDone: boolean;
  isSeeded: boolean;
  pinTriesLeft: number;
  pinTriesMax: number;
}

async function getStatus(card: CardConn): Promise<CardStatus> {
  const resp = await apdu(card, INS.GET_STATUS, 0x00, 0x00);
  if (sw(resp) !== SW.OK)
    throw new Error(`GET_STATUS failed: ${sw(resp).toString(16).toUpperCase()}`);
  const d = respData(resp);
  return {
    setupDone: d[10] === 0x01,
    isSeeded: d[8] === 0x01,
    pinTriesLeft: d[4],
    pinTriesMax: d[5],
  };
}

async function setupCard(
  card: CardConn,
  pin: Buffer,
  puk: Buffer
): Promise<void> {
  const payload = Buffer.concat([
    Buffer.from([pin.length]),
    pin,
    Buffer.from([puk.length]),
    puk,
  ]);
  const resp = await apdu(card, INS.SETUP, 0x00, 0x00, payload);
  if (sw(resp) !== SW.OK)
    throw new Error(`SETUP failed: ${sw(resp).toString(16).toUpperCase()}`);
}

async function verifyPin(sc: SecureChannel, card: CardConn, pin: Buffer): Promise<void> {
  const resp = await sc.send((ins, p1, p2, payload) => apdu(card, ins, p1, p2, payload),
    INS.VERIFY_PIN, 0x00, 0x00, pin);
  if (sw(resp) !== SW.OK) {
    const s = sw(resp);
    if ((s & 0xfff0) === 0x63c0)
      throw new Error(`PIN incorrect — ${s & 0x0f} tries remaining`);
    throw new Error(`VERIFY_PIN failed: ${s.toString(16).toUpperCase()}`);
  }
}

async function importSeed(sc: SecureChannel, card: CardConn, seed64: Buffer): Promise<Buffer> {
  if (seed64.length !== 64) throw new Error('Seed must be 64 bytes');
  const resp = await sc.send((ins, p1, p2, payload) => apdu(card, ins, p1, p2, payload),
    INS.IMPORT_SEED, 0x00, 0x00, seed64);
  if (sw(resp) !== SW.OK)
    throw new Error(`IMPORT_SEED failed: ${sw(resp).toString(16).toUpperCase()}`);
  return respData(resp); // 32-byte pubkey at m/44'/501'/0'
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

  if (args.includes('--help')) {
    console.log(
      'Usage: ts-node setup-fresh-card.ts [mnemonic] [--pin <pin>] [--puk <puk>]'
    );
    console.log('');
    console.log(
      '  Generates a new mnemonic (or uses the one provided), seeds the card,'
    );
    console.log('  and writes the mnemonic and public address to card-info.json.');
    console.log('');
    console.log('  mnemonic       Optional BIP-39 mnemonic (12 or 24 words)');
    console.log('  --pin <pin>    PIN for the card (default: 1234)');
    console.log('  --puk <puk>    PUK for the card (default: 1234)');
    process.exit(0);
  }

  // Parse args: first positional (if not a flag) is the mnemonic
  const pinIdx = args.indexOf('--pin');
  const pukIdx = args.indexOf('--puk');
  const pinStr = pinIdx >= 0 ? args[pinIdx + 1] : '1234';
  const pukStr = pukIdx >= 0 ? args[pukIdx + 1] : '1234';

  const firstArg = args[0];
  const providedMnemonic =
    firstArg && !firstArg.startsWith('--') ? firstArg : undefined;

  const pin = Buffer.from(pinStr);
  const puk = Buffer.from(pukStr);

  if (pin.length < 4 || pin.length > 16) {
    console.error('ERROR: PIN must be 4–16 characters');
    process.exit(1);
  }
  if (puk.length < 4 || puk.length > 16) {
    console.error('ERROR: PUK must be 4–16 characters');
    process.exit(1);
  }

  // ── 1. Mnemonic ───────────────────────────────────────────────────────────
  logStep(1, 'Mnemonic');

  let mnemonic: string;
  if (providedMnemonic) {
    if (!bip39.validateMnemonic(providedMnemonic)) {
      console.error('ERROR: Invalid BIP-39 mnemonic');
      process.exit(1);
    }
    mnemonic = providedMnemonic;
    log('  Using provided mnemonic.');
  } else {
    mnemonic = bip39.generateMnemonic(256); // 24 words
    log('  Generated new 24-word mnemonic.');
  }

  const seed = await bip39.mnemonicToSeed(mnemonic); // 64 bytes

  // ── 2. Connect to card ────────────────────────────────────────────────────
  logStep(2, 'Connect to card via PC/SC');
  const card = await connectCard();
  log('  Connected.');
  await selectApplet(card);
  log('  TapiocaApplet selected.');

  // ── 3. Setup card ─────────────────────────────────────────────────────────
  logStep(3, 'Setup card with PIN / PUK');
  await setupCard(card, pin, puk);
  log('  SETUP complete.');

  const statusAfterSetup = await getStatus(card);
  if (!statusAfterSetup.setupDone)
    throw new Error('Card reported setup_done=false after SETUP — unexpected');
  log(`  Verified: setup_done=true  pin_tries_left=${statusAfterSetup.pinTriesLeft}/${statusAfterSetup.pinTriesMax}`);

  // Establish secure channel (required for PIN and seed commands)
  const sc = new SecureChannel();
  await sc.handshake((ins, p1, p2, payload) => apdu(card, ins, p1, p2, payload));
  log('  Secure channel established.');

  // ── 4. Verify PIN ─────────────────────────────────────────────────────────
  logStep(4, 'Verify PIN');
  const triesBefore = (await getStatus(card)).pinTriesLeft;
  await verifyPin(sc, card, pin);
  const triesAfter = (await getStatus(card)).pinTriesLeft;
  if (triesAfter !== triesBefore)
    throw new Error(`PIN verification consumed a try (${triesBefore} → ${triesAfter}) — PIN may be wrong`);
  log(`  PIN verified. Tries remaining: ${triesAfter}/${statusAfterSetup.pinTriesMax}`);

  // ── 5. Import seed ────────────────────────────────────────────────────────
  logStep(5, 'Import seed');
  log("  Importing seed (~5–8s)...");
  const t0 = Date.now();
  const pubkeyBytes = await importSeed(sc, card, seed);
  log(`  Seed imported in ${((Date.now() - t0) / 1000).toFixed(1)}s`);

  const address = new PublicKey(pubkeyBytes);

  // ── 6. Write to file ──────────────────────────────────────────────────────
  logStep(6, 'Write card-info.json');
  const outPath = path.resolve(__dirname, 'card-info.json');
  const info = {
    mnemonic,
    address: address.toBase58(),
    derivationPath: "m/44'/501'/0'",
    pin: pinStr,
    puk: pukStr,
  };
  fs.writeFileSync(outPath, JSON.stringify(info, null, 2) + '\n');
  log(`  Written to ${outPath}`);

  // ── 7. Summary ────────────────────────────────────────────────────────────
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║  Card provisioned successfully                               ║
╚══════════════════════════════════════════════════════════════╝
  Mnemonic: ${mnemonic}
  Address:  ${address.toBase58()}
  PIN:      ${pinStr}
  PUK:      ${pukStr}
  File:     ${outPath}
  Get devnet SOL from: https://faucet.solana.com/ or https://solfaucet.com/ 
  Get devnet USDC from: https://faucet.circle.com/
`);

  card.reader.disconnect(card.reader.SCARD_LEAVE_CARD, () => {
    console.log('  Card disconnected.');
    process.exit(0);
  });
}

main().catch((err: Error) => {
  console.error(`\nERROR: ${err.message}`);
  process.exit(1);
});
