# E2E Test — Solana Card CLI

End-to-end test that imports a BIP-39 mnemonic to a TapiocaApplet card, derives the Solana key at `m/44'/501'/0'`, and submits a real SOL transfer on Solana devnet.

## Prerequisites

- **Node.js** (18+)
- **pcsclite** native library — required by the `pcsclite` npm package:
  ```sh
  brew install pcsc-lite   # macOS
  # or: apt install libpcsclite-dev   # Linux
  ```
- A PC/SC smart card reader with a TapiocaApplet card installed

## Setup

```sh
cd test/e2e
npm install
```

## Usage

```sh
npm start "<12-or-24-word bip39 mnemonic>"
npm start "<mnemonic>" -- --pin 5678
```

`--pin` defaults to `1234`. PIN must be 4–16 characters.

**Example:**

> **Warning:** the mnemonic below is publicly known — devnet only, never use it on mainnet.

```sh
npm start "always thunder family peasant ancient pioneer nut vote detect monster shaft timber prepare program clump awake unable error garden shield sand fossil orphan clump" -- --pin 5678
```

## What It Does

| Step | Action |
| ---- | ------ |
| 1 | Derive 64-byte seed from mnemonic via BIP-39 PBKDF2 |
| 2 | Connect to card via PC/SC, select TapiocaApplet |
| 3 | Setup card if fresh; verify PIN |
| 4 | Import seed → card derives `m/44'/501'/0'`, returns pubkey |
| 5 | Connect to Solana devnet RPC |
| 6 | Airdrop 1 SOL if balance < 0.01 SOL |
| 7 | Build a SOL transfer to a throwaway keypair |
| 8 | Stream transaction message to card → receive 64-byte Ed25519 signature (~4s) |
| 9 | Verify signature locally, broadcast to devnet |
| 10 | Confirm and log explorer link |

## Notes

- Targets **Solana devnet** — no real funds involved.
- Default PUK is `ABCDEF` (bytes `41 42 43 44 45 46`).
- Signing takes ~4s on J3R180 (key setup ~2.7s + EC sign ~1.4s).
- The card must have TapiocaApplet installed (AID: `536F6C616E6100`).
