#!/usr/bin/env ts-node
/**
 * create-usdc-ata.ts — derive a Solana keypair from a mnemonic, show SOL
 * balance and public address, then create a USDC Associated Token Account
 * (paying the rent-exempt minimum) if one does not already exist.
 *
 * Usage:
 *   ts-node create-usdc-ata.ts "<mnemonic>" [--network devnet|mainnet-beta]
 *
 * The mnemonic is derived using BIP-44 path m/44'/501'/0'/0' (Phantom-compatible).
 * Default network: devnet
 */

import * as bip39 from 'bip39';
import { derivePath } from 'ed25519-hd-key';
import {
  clusterApiUrl,
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  sendAndConfirmTransaction,
} from '@solana/web3.js';
import {
  createAssociatedTokenAccountInstruction,
  getAssociatedTokenAddressSync,
  getAccount,
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
} from '@solana/spl-token';
import { Transaction } from '@solana/web3.js';

// ── Constants ──────────────────────────────────────────────────────────────────

const USDC_MINT: Record<string, PublicKey> = {
  'mainnet-beta': new PublicKey('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'),
  devnet: new PublicKey('4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'),
};

const DERIVATION_PATH = "m/44'/501'/0'";

// ── Helpers ────────────────────────────────────────────────────────────────────

function parseArgs(): { mnemonic: string; network: 'devnet' | 'mainnet-beta' } {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help')) {
    console.log(
      'Usage: ts-node create-usdc-ata.ts "<mnemonic>" [--network devnet|mainnet-beta]'
    );
    process.exit(args.includes('--help') ? 0 : 1);
  }

  const networkIdx = args.indexOf('--network');
  const positionalNetwork = args[1] && !args[1].startsWith('--') ? args[1] : undefined;
  const networkRaw = networkIdx >= 0 ? args[networkIdx + 1] : (positionalNetwork ?? 'devnet');
  if (networkRaw !== 'devnet' && networkRaw !== 'mainnet-beta') {
    console.error(`ERROR: network must be "devnet" or "mainnet-beta", got "${networkRaw}"`);
    process.exit(1);
  }

  // First positional arg is the mnemonic
  const mnemonic = args[0];
  if (!mnemonic || mnemonic.startsWith('--')) {
    console.error('ERROR: mnemonic must be the first argument');
    process.exit(1);
  }

  return { mnemonic, network: networkRaw };
}

function keypairFromMnemonic(mnemonic: string): Keypair {
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  const { key } = derivePath(DERIVATION_PATH, seed.toString('hex'));
  return Keypair.fromSeed(key);
}

// ── Main ───────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const { mnemonic, network } = parseArgs();

  if (!bip39.validateMnemonic(mnemonic)) {
    console.error('ERROR: Invalid BIP-39 mnemonic');
    process.exit(1);
  }

  const keypair = keypairFromMnemonic(mnemonic);
  const address = keypair.publicKey;
  const connection = new Connection(clusterApiUrl(network), 'confirmed');
  const usdcMint = USDC_MINT[network];

  console.log(`\nNetwork:    ${network}`);
  console.log(`Address:    ${address.toBase58()}`);
  console.log(`Derivation: ${DERIVATION_PATH}`);

  // ── SOL balance ──────────────────────────────────────────────────────────────
  const lamports = await connection.getBalance(address);
  const sol = lamports / LAMPORTS_PER_SOL;
  console.log(`SOL:        ${sol.toFixed(6)} SOL  (${lamports} lamports)`);

  if (lamports === 0) {
    console.log('\nWARNING: Account has no SOL — it cannot pay rent for the ATA.');
    console.log(`  Fund it first: https://faucet.solana.com/ (devnet) or send SOL to ${address.toBase58()}`);
    process.exit(1);
  }

  // ── USDC ATA ─────────────────────────────────────────────────────────────────
  const ata = getAssociatedTokenAddressSync(
    usdcMint,
    address,
    false,
    TOKEN_PROGRAM_ID,
    ASSOCIATED_TOKEN_PROGRAM_ID
  );

  console.log(`\nUSDC mint:  ${usdcMint.toBase58()}`);
  console.log(`USDC ATA:   ${ata.toBase58()}`);

  // Check if ATA already exists
  let ataExists = false;
  try {
    const acct = await getAccount(connection, ata, 'confirmed', TOKEN_PROGRAM_ID);
    ataExists = true;
    console.log(`\nATA status: already exists`);
    console.log(`USDC bal:   ${Number(acct.amount) / 1_000_000} USDC`);
  } catch {
    // TokenAccountNotFoundError — needs to be created
  }

  if (ataExists) {
    console.log('\nNothing to do — ATA already exists.');
    return;
  }

  // Estimate rent
  const rentLamports = await connection.getMinimumBalanceForRentExemption(165);
  console.log(`\nATA rent:   ${rentLamports} lamports (${(rentLamports / LAMPORTS_PER_SOL).toFixed(6)} SOL)`);

  if (lamports < rentLamports + 5_000) {
    console.error(
      `ERROR: Insufficient SOL. Need at least ${((rentLamports + 5_000) / LAMPORTS_PER_SOL).toFixed(6)} SOL, have ${sol.toFixed(6)} SOL.`
    );
    process.exit(1);
  }

  console.log('\nCreating ATA...');
  const ix = createAssociatedTokenAccountInstruction(
    address,     // payer
    ata,         // associated token account
    address,     // owner
    usdcMint,
    TOKEN_PROGRAM_ID,
    ASSOCIATED_TOKEN_PROGRAM_ID
  );

  const tx = new Transaction().add(ix);
  const sig = await sendAndConfirmTransaction(connection, tx, [keypair]);

  console.log(`\nATA created!`);
  console.log(`  Signature: ${sig}`);
  console.log(`  Explorer:  https://explorer.solana.com/tx/${sig}${network === 'devnet' ? '?cluster=devnet' : ''}`);
}

main().catch((err: Error) => {
  console.error(`\nERROR: ${err.message}`);
  process.exit(1);
});
