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
//test run : npm start "always thunder family peasant ancient pioneer nut vote detect monster shaft timber prepare program clump awake unable error garden shield sand fossil orphan clump" -- --pin 5678

import {
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
  LAMPORTS_PER_SOL,
  Keypair,
} from '@solana/web3.js';
import * as bip39 from 'bip39';
import { SecureChannel } from './secure-channel';

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

async function setupCard(card: CardConn, pin: Buffer): Promise<void> {
  const payload = Buffer.concat([
    Buffer.from([pin.length]),
    pin,
    Buffer.from([DEFAULT_PUK.length]),
    DEFAULT_PUK,
  ]);
  const resp = await apdu(card, INS.SETUP, 0x00, 0x00, payload);
  if (sw(resp) !== SW.OK)
    throw new Error(`SETUP failed: ${sw(resp).toString(16).toUpperCase()}`);
}

// ── Card: VERIFY_PIN ──────────────────────────────────────────────────────────

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

// ── Card: IMPORT_SEED ─────────────────────────────────────────────────────────

async function importSeed(sc: SecureChannel, card: CardConn, seed64: Buffer): Promise<Buffer> {
  if (seed64.length !== 64) throw new Error('Seed must be 64 bytes');
  const resp = await sc.send((ins, p1, p2, payload) => apdu(card, ins, p1, p2, payload),
    INS.IMPORT_SEED, 0x00, 0x00, seed64);
  if (sw(resp) !== SW.OK)
    throw new Error(`IMPORT_SEED failed: ${sw(resp).toString(16).toUpperCase()}`);
  return respData(resp); // 32-byte pubkey at m/44'/501'/0'
}

// ── Card: GET_PUBLIC_KEY ──────────────────────────────────────────────────────

async function getPublicKey(card: CardConn, path: number[]): Promise<Buffer> {
  const buf = Buffer.alloc(1 + path.length * 4);
  buf[0] = path.length;
  for (let i = 0; i < path.length; i++) buf.writeUInt32BE(path[i], 1 + i * 4);
  const resp = await apdu(card, INS.GET_PUBLIC_KEY, 0x00, 0x00, buf);
  if (sw(resp) !== SW.OK)
    throw new Error(
      `GET_PUBLIC_KEY failed: ${sw(resp).toString(16).toUpperCase()}`
    );
  return respData(resp); // 32 bytes
}

// ── Card: SIGN_TX ─────────────────────────────────────────────────────────────
// Always signs at m/44'/501'/0' — no path bytes in the APDU.
// Response: 64-byte Ed25519 signature + 32-byte public key (96 bytes total).

async function signTx(
  card: CardConn,
  message: Buffer
): Promise<{ sig: Buffer; pubkey: Buffer }> {
  // Slice message into CHUNK_SIZE pieces
  const chunks: Buffer[] = [];
  for (let off = 0; off < message.length; off += CHUNK_SIZE) {
    chunks.push(message.subarray(off, off + CHUNK_SIZE));
  }
  if (chunks.length === 0) chunks.push(Buffer.alloc(0));

  let resp: Buffer;

  if (chunks.length === 1) {
    // Entire message fits in one APDU
    resp = await apdu(card, INS.SIGN_TX, P1.FIRST_LAST, 0x00, chunks[0]);
    if (sw(resp) !== SW.OK)
      throw new Error(`SIGN_TX failed: ${sw(resp).toString(16).toUpperCase()}`);
  } else {
    // First chunk
    resp = await apdu(card, INS.SIGN_TX, P1.FIRST, 0x00, chunks[0]);
    if (sw(resp) !== SW.OK)
      throw new Error(
        `SIGN_TX first chunk failed: ${sw(resp).toString(16).toUpperCase()}`
      );

    // Middle chunks
    for (let i = 1; i < chunks.length - 1; i++) {
      resp = await apdu(card, INS.SIGN_TX, P1.CONTINUATION, 0x00, chunks[i]);
      if (sw(resp) !== SW.OK)
        throw new Error(
          `SIGN_TX continuation failed: ${sw(resp).toString(16).toUpperCase()}`
        );
    }

    // Last chunk — returns 64-byte signature + 32-byte public key
    resp = await apdu(
      card,
      INS.SIGN_TX,
      P1.LAST,
      0x00,
      chunks[chunks.length - 1]
    );
    if (sw(resp) !== SW.OK)
      throw new Error(
        `SIGN_TX last chunk failed: ${sw(resp).toString(16).toUpperCase()}`
      );
  }

  const data = respData(resp);
  if (data.length !== 96)
    throw new Error(`SIGN_TX: expected 96-byte response, got ${data.length}`);
  return { sig: data.subarray(0, 64), pubkey: data.subarray(64, 96) };
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

  // ── 3. Card setup & PIN ───────────────────────────────────────────────────
  logStep(3, 'Card setup');
  const statusBefore = await getStatus(card);
  log(
    `  setup_done=${statusBefore.setupDone}  is_seeded=${statusBefore.isSeeded}  pin_tries_left=${statusBefore.pinTriesLeft}`
  );

  if (!statusBefore.setupDone) {
    log('  Card not set up — running SETUP...');
    await setupCard(card, pin);
    log('  SETUP complete.');
  }

  const sc = new SecureChannel();
  await sc.handshake((ins, p1, p2, payload) => apdu(card, ins, p1, p2, payload));
  log('  Secure channel established.');

  await verifyPin(sc, card, pin);
  log('  PIN verified.');

  // ── 4. Import seed ────────────────────────────────────────────────────────
  logStep(4, 'Import seed / read public key');
  let pubkeyBytes: Buffer;

  const statusAfterPin = await getStatus(card);
  if (!statusAfterPin.isSeeded) {
    log('  No seed on card — importing (~5–8s)...');
    const t0 = Date.now();
    pubkeyBytes = await importSeed(sc, card, seed);
    log(`  Seed imported in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  } else {
    log('  Card already seeded — reading public key...');
    pubkeyBytes = await getPublicKey(card, SOLANA_PATH);
  }

  const address = new PublicKey(pubkeyBytes);
  log(`\n  ✓ Address (m/44'/501'/0'): ${address.toBase58()}`);

  // ── 5. Solana testnet connection ──────────────────────────────────────────
  logStep(5, 'Connect to Solana testnet');
  const connection = new Connection(TESTNET_RPC, 'confirmed');
  const version = await connection.getVersion();
  log(`  RPC:     ${TESTNET_RPC}`);
  log(`  Version: ${version['solana-core']}`);

  // ── 6. Fund account if needed ─────────────────────────────────────────────
  logStep(6, 'Check / fund account');
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

  // ── 7. Build transaction ──────────────────────────────────────────────────
  logStep(7, 'Build transfer transaction');
  const recipient = Keypair.generate();
  const transferAmount = await connection.getMinimumBalanceForRentExemption(0);
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

  // ── 8. Sign on card ───────────────────────────────────────────────────────
  logStep(8, 'Sign on card');
  log('  Signing (~1.4s)...');
  const t1 = Date.now();
  const { sig: sigBytes } = await signTx(card, msgBytes);
  const elapsed = ((Date.now() - t1) / 1000).toFixed(1);
  log(`  Done in ${elapsed}s`);
  log(`  Signature: ${sigBytes.toString('hex').slice(0, 32)}...`);

  // ── 9. Attach signature, verify, broadcast ────────────────────────────────
  logStep(9, 'Broadcast transaction');
  tx.addSignature(address, sigBytes);

  if (!tx.verifySignatures()) {
    throw new Error(
      'Signature verification failed — card returned an invalid signature'
    );
  }
  log('  Signature verified locally ✓');

  const rawTx = tx.serialize();
  const txSig = await connection.sendRawTransaction(rawTx, {
    skipPreflight: false,
  });
  log(`  Sent: ${txSig}`);

  // ── 10. Confirm ───────────────────────────────────────────────────────────
  logStep(10, 'Confirm');
  log('  Waiting for confirmation...');
  await connection.confirmTransaction(
    { signature: txSig, blockhash, lastValidBlockHeight },
    'confirmed'
  );

  const finalBalance = await connection.getBalance(address);

  console.log(`
╔══════════════════════════════════════════════════════════════╗
║  ✓ Transaction confirmed!                                    ║
╚══════════════════════════════════════════════════════════════╝
  Address:  ${address.toBase58()}
  Balance:  ${(finalBalance / LAMPORTS_PER_SOL).toFixed(6)} SOL
  TxID:     ${txSig}
  Explorer: https://explorer.solana.com/tx/${txSig}?cluster=devnet
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
