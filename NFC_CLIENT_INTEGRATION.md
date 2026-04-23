# TapiocaApplet — React Native NFC Client Integration Guide

Complete, implementation-accurate guide for building a React Native app that communicates with TapiocaApplet over NFC. Based directly on the JavaCard source code and test suite.

---

## Table of Contents

1. [Overview](#1-overview)
2. [NFC Transport Layer](#2-nfc-transport-layer)
3. [APDU Fundamentals](#3-apdu-fundamentals)
4. [Session Lifecycle](#4-session-lifecycle)
5. [Card State Machine](#5-card-state-machine)
6. [Command Reference (Wire Level)](#6-command-reference-wire-level)
7. [Secure Channel Protocol](#7-secure-channel-protocol)
8. [Full Flows](#8-full-flows)
9. [TypeScript Reference Implementation](#9-typescript-reference-implementation)
10. [Error Handling](#10-error-handling)
11. [Timing and UX](#11-timing-and-ux)
12. [Security Considerations](#12-security-considerations)

---

## 1. Overview

TapiocaApplet is a JavaCard applet that implements a Solana hardware wallet. It:

- Stores a BIP-39-derived Ed25519 signing key using SLIP-0010 derivation.
- Always signs at the Solana path `m/44'/501'/0'`.
- Protects all sensitive operations with a PIN.
- Requires an AES-128-CBC + HMAC-SHA1 secure channel for all commands that transmit sensitive data (PIN, PUK, seed).
- Communicates via ISO 7816-4 APDUs transported over ISO-DEP (NFC-A or NFC-B).

**Card identity:**

| Field       | Value                                         |
|-------------|-----------------------------------------------|
| AID         | `53 6F 6C 61 6E 61 00` (ASCII "Solana" + NUL) |
| CLA byte    | `0xB0`                                        |
| Protocol    | `0x00.0x01`                                   |
| Applet      | `0x00.0x01`                                   |

---

## 2. NFC Transport Layer

### 2.1 Recommended Library

Use [`react-native-nfc-manager`](https://github.com/revtel/react-native-nfc-manager). It exposes raw ISO-DEP APDU transceive, which is what the card requires.

```bash
npm install react-native-nfc-manager
```

Minimum platform requirements:
- iOS: Core NFC entitlement + `NFCReaderUsageDescription` in `Info.plist`
- Android: `<uses-permission android:name="android.permission.NFC" />` in `AndroidManifest.xml`

### 2.2 Technology Type

The card presents as **ISO-DEP** (NfcA or NfcB depending on card variant). Always request the `Ndef` technology for discovery, then switch to `IsoDep` for APDU communication:

```typescript
import NfcManager, { NfcTech } from 'react-native-nfc-manager';

// In your NFC session handler:
await NfcManager.requestTechnology(NfcTech.IsoDep, {
  alertMessage: 'Hold your Tapioca card to the back of your phone',
});
```

### 2.3 APDU Transceive

All APDU exchanges use `NfcManager.isoDepHandler.transceive()`, which accepts and returns `number[]`:

```typescript
async function transceive(apdu: number[]): Promise<number[]> {
  return NfcManager.isoDepHandler.transceive(apdu);
}
```

The response always ends with a two-byte status word (SW1 SW2). Strip it to get data:

```typescript
function sw(resp: number[]): number {
  return ((resp[resp.length - 2] & 0xff) << 8) | (resp[resp.length - 1] & 0xff);
}

function respData(resp: number[]): number[] {
  return resp.slice(0, -2);
}
```

### 2.4 NFC Session Management

Wrap all card operations in a try/finally to guarantee technology release:

```typescript
async function withCard<T>(fn: (send: Transceiver) => Promise<T>): Promise<T> {
  await NfcManager.start();
  await NfcManager.requestTechnology(NfcTech.IsoDep);
  try {
    const send = (apdu: number[]) => NfcManager.isoDepHandler.transceive(apdu);
    return await fn(send);
  } finally {
    NfcManager.cancelTechnologyRequest();
  }
}
```

---

## 3. APDU Fundamentals

### 3.1 Command APDU Format

```
[CLA=0xB0] [INS] [P1] [P2] [Lc] [Data...] [Le=0x00]
```

- `Lc` is the number of data bytes. Omit both `Lc` and `Data` if there is no payload (send `0x00` as Le in that case — or omit Le too; the card accepts both).
- `Le = 0x00` requests the maximum response length.

**Building a command APDU:**

```typescript
function buildApdu(ins: number, p1: number, p2: number, data?: number[]): number[] {
  if (!data || data.length === 0) {
    return [0xb0, ins, p1, p2, 0x00];
  }
  return [0xb0, ins, p1, p2, data.length, ...data, 0x00];
}
```

### 3.2 Response APDU Format

```
[Data...] [SW1] [SW2]
```

`SW1 SW2 = 0x90 0x00` (`0x9000`) signals success.

### 3.3 Size Limits

Each individual APDU data field is limited to **255 bytes** (standard short APDU). For messages larger than fits in one APDU, use the multi-chunk streaming protocol provided by `INS_SIGN_TX`.

### 3.4 Multi-byte integers

All multi-byte integers in APDU payloads are **big-endian** unless otherwise noted.

---

## 4. Session Lifecycle

### 4.1 Every NFC tap is a fresh session

The card has no persistent session state across NFC taps. On every new ISO-DEP connection:

1. PIN validation is **reset** — the PIN must be re-verified.
2. Any active secure channel is **reset** — the handshake must be repeated.
3. Any in-progress multi-chunk `INS_SIGN_TX` is **aborted** — restart from the first chunk.

This is by design: the applet's `select()` method explicitly resets PIN state and clears transient buffers on every power-on.

### 4.2 Required first step: SELECT

Before any other command, issue an ISO 7816-4 SELECT by AID:

```
00 A4 04 00 07  53 6F 6C 61 6E 61 00  00
```

In code:

```typescript
const APPLET_AID = [0x53, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x00];

async function selectApplet(send: Transceiver): Promise<void> {
  const cmd = [0x00, 0xa4, 0x04, 0x00, APPLET_AID.length, ...APPLET_AID];
  const resp = await send(cmd);
  if (sw(resp) !== 0x9000) {
    throw new Error(`SELECT failed: ${sw(resp).toString(16)}`);
  }
}
```

`0x6A82` in response means the applet is not installed on the card.

### 4.3 Typical session sequence

```
1. NFC tap detected
2. SELECT applet
3. INS_GET_STATUS          → check setup_done, is_seeded, pin_tries_left
4. INS_EXPORT_AUTHENTIKEY  → (if using secure channel)
5. INS_INIT_SECURE_CHANNEL → (if using secure channel)
6. INS_VERIFY_PIN          → authenticate (via secure channel if active)
7. <application command>   → import seed / get pubkey / sign tx
8. NFC tap ends            → all session state cleared by card
```

---

## 5. Card State Machine

```
┌──────────────┐    INS_SETUP       ┌──────────────┐   INS_IMPORT_SEED   ┌──────────────┐
│  Fresh Card  │ ──────────────────>│  Setup Done  │ ──────────────────> │   Seeded     │
│  (no PIN)    │  set PIN + PUK    │  (no seed)   │  load BIP-39 seed  │  (ready)     │
└──────────────┘                   └──────────────┘                     └──────────────┘
                                          │                                     │
                                          │       INS_RESET_TO_FACTORY          │
                                          │<────────────────────────────────────┘
                                          v
                                    back to Fresh Card
```

**Fresh card:** Only `INS_GET_STATUS`, `INS_EXPORT_AUTHENTIKEY`, and `INS_INIT_SECURE_CHANNEL` are available. All others return `0x9C04` (SW_SETUP_NOT_DONE).

**Setup done:** PIN and PUK are set. PIN verification and label operations are available. Signing returns `0x9C14` (SW_SEED_NOT_IMPORTED).

**Seeded:** BIP-39 seed imported. All commands available.

### 5.1 Checking card state

Always call `INS_GET_STATUS` early in each session to branch on the card's current state:

```typescript
interface CardStatus {
  protoMajor:    number;   // byte[0]
  protoMinor:    number;   // byte[1]
  appMajor:      number;   // byte[2]
  appMinor:      number;   // byte[3]
  pinTriesLeft:  number;   // byte[4] — 0 if not setup
  pinTriesMax:   number;   // byte[5] — 0 if not setup
  pukTriesLeft:  number;   // byte[6] — 0 if not setup
  pukTriesMax:   number;   // byte[7] — 0 if not setup
  isSeeded:      boolean;  // byte[8]
  secureChannel: boolean;  // byte[9]
  setupDone:     boolean;  // byte[10]
}
```

### 5.2 PIN Session Model

| Parameter    | Value          |
|--------------|----------------|
| PIN length   | 4–16 bytes     |
| PIN attempts | 5 max          |
| PUK length   | 4–16 bytes     |
| PUK attempts | 3 max          |

- After exhausting PIN retries, use `INS_UNBLOCK_PIN` with the PUK to set a new PIN.
- After exhausting PUK retries, the card is **permanently locked**. The applet must be reinstalled.
- PIN validation is cleared on every `SELECT` (every NFC tap).

---

## 6. Command Reference (Wire Level)

All commands use `CLA = 0xB0`. Successful responses return `SW = 0x9000` unless noted.

---

### INS_GET_STATUS — `0x3C`

**Auth:** None. Always available.

**Request:**
```
B0 3C 00 00 00
```

**Response (12 bytes):**

| Offset | Size | Field          | Description                                   |
|--------|------|----------------|-----------------------------------------------|
| 0      | 1    | proto_major    | `0x00`                                        |
| 1      | 1    | proto_minor    | `0x01`                                        |
| 2      | 1    | app_major      | `0x00`                                        |
| 3      | 1    | app_minor      | `0x01`                                        |
| 4      | 1    | pin_tries_left | Remaining PIN attempts (`0` if not setup)     |
| 5      | 1    | pin_tries_max  | Max PIN attempts (`5`)                        |
| 6      | 1    | puk_tries_left | Remaining PUK attempts (`0` if not setup)     |
| 7      | 1    | puk_tries_max  | Max PUK attempts (`3`)                        |
| 8      | 1    | is_seeded      | `0x01` if seed imported, `0x00` otherwise     |
| 9      | 1    | secure_channel | `0x01` if SC session active, `0x00` otherwise |
| 10     | 1    | setup_done     | `0x01` if setup complete, `0x00` otherwise    |
| 11     | 1    | reserved       | Always `0x00`                                 |

---

### INS_SETUP — `0x2A`

**Auth:** None. Can only be called once — subsequent calls return `0x9C03`.

**Request data:**
```
[pin_len (1)] [pin (4–16 bytes)] [puk_len (1)] [puk (4–16 bytes)]
```

**Example** — PIN = `"1234"` (ASCII bytes `31 32 33 34`), PUK = `"ABCDEF"` (`41 42 43 44 45 46`):
```
B0 2A 00 00 0C  04 31 32 33 34  06 41 42 43 44 45 46  00
```

**Response:** `SW 0x9000`

**Errors:**
- `0x9C03` — already set up
- `0x9C0F` — PIN or PUK length out of range (< 4 or > 16)

---

### INS_VERIFY_PIN — `0x42`

**Auth:** Requires setup done.

**Request data:** Raw PIN bytes (4–16 bytes, NOT length-prefixed).

**Example** — PIN `"1234"`:
```
B0 42 00 00 04  31 32 33 34  00
```

**Response:** `SW 0x9000` on success.

**Errors:**
- `0x63Cx` — wrong PIN; `x` = remaining tries. e.g. `0x63C4` = 4 tries remaining.
- `0x9C0C` — PIN blocked (retry counter at zero).

> **Important:** This response encodes remaining tries in the low nibble of the last byte. Parse it as:
> ```typescript
> const triesLeft = swValue & 0x0f;
> ```

---

### INS_CHANGE_PIN — `0x44`

**Auth:** PIN must be verified in the current session.

**Request data:**
```
[old_pin_len (1)] [old_pin (4–16)] [new_pin_len (1)] [new_pin (4–16)]
```

**Errors:**
- `0x9C06` — PIN not verified
- `0x63Cx` — old PIN incorrect; `x` = tries remaining

---

### INS_UNBLOCK_PIN — `0x46`

**Auth:** None (PUK itself provides authentication).

**Request data:**
```
[puk_len (1)] [puk (4–16)] [new_pin_len (1)] [new_pin (4–16)]
```

**Errors:**
- `0x63Cx` — wrong PUK; `x` = PUK tries remaining
- `0x9C0C` — PUK blocked (permanent lockout)

---

### INS_IMPORT_SEED — `0x6C`

**Auth:** Requires PIN verified.

**Request data:** 64-byte BIP-39 derived seed (PBKDF2-HMAC-SHA512 output). Must be sent inside the secure channel over NFC to protect the seed.

```
B0 6C 00 00 40  [64-byte seed]  00
```

**Response:** 32-byte Ed25519 public key at `m/44'/501'/0'`.

**Timing:** ~2,700 ms (SLIP-0010 derivation is computationally expensive on-card).

**Notes:**
- Replaces any previously imported seed.
- The 64-byte seed is:
  ```
  PBKDF2(HMAC-SHA512, mnemonic_words_joined_by_spaces, "mnemonic" + passphrase, 2048 iterations, 64 bytes)
  ```
- The host computes PBKDF2 — not the card. Only the 64-byte output is sent.

---

### INS_RESET_SEED — `0x77`

**Auth:** Requires PIN verified.

**Request:**
```
B0 77 00 00 00
```

Wipes the master key and chain code. Card returns to "setup done, not seeded" state.

---

### INS_GET_PUBLIC_KEY — `0x6D`

**Auth:** Requires PIN verified and seed imported.

**Request data:**
```
[depth (1)] [index_0 (4 BE)] [index_1 (4 BE)] ... [index_{depth-1} (4 BE)]
```

All indexes **must be hardened** (bit 31 set: `0x80000000 | n`). Returns `0x9C0F` if any index is unhardened.

**Response:** 32-byte Ed25519 public key at the requested derivation path.

**Timing:** ~2,700 ms.

**Standard Solana path** `m/44'/501'/0'`:
```
depth = 0x03
index_0 = 0x8000002C   (44')
index_1 = 0x800001F5   (501')
index_2 = 0x80000000   (0')
```

**Example:**
```
B0 6D 00 00 0D  03  80 00 00 2C  80 00 01 F5  80 00 00 00  00
```

**Note:** If you request a non-default path, the card re-derives the default `m/44'/501'/0'` key afterward so that `INS_SIGN_TX` continues to work correctly. This means a `GET_PUBLIC_KEY` on a non-default path costs approximately double the derivation time (~5,400 ms).

---

### INS_SIGN_TX — `0x6F`

**Auth:** Requires PIN verified and seed imported.

Signs a Solana transaction message using Ed25519 at the hardcoded path `m/44'/501'/0'`. Supports multi-chunk streaming for messages up to 1,200 bytes.

> **Key behavioral note:** No derivation path is sent in the APDU data. All bytes in the data field are message bytes. The signing key is always the one loaded at `importSeed` time (`m/44'/501'/0'`).

**P1 flags:**

| P1     | Meaning                                              |
|--------|------------------------------------------------------|
| `0x81` | Single-chunk: first AND last. Response has signature.|
| `0x01` | First chunk of a multi-chunk message. No response.   |
| `0x00` | Continuation chunk. No response.                     |
| `0x80` | Last chunk. Response has signature + public key.     |

**All chunk data:** Raw message bytes only. No path prefix.

**Response (last chunk / single-chunk only): 96 bytes total**

| Offset | Size | Description          |
|--------|------|----------------------|
| 0      | 64   | Ed25519 signature    |
| 64     | 32   | Ed25519 public key   |

**Timing:**
- First chunk: ~0 ms (just buffers data)
- Last chunk: ~1,440 ms (Ed25519 signing)
- Total for a fresh sign after `importSeed`: the key is already loaded, so total signing time ≈ 1,440 ms.

**Maximum message size:** 1,200 bytes.

**Single-chunk example** (message fits in one APDU):
```
→ B0 6F 81 00 [Lc]  [message bytes]  00
← [64-byte signature] [32-byte public key]  90 00
```

**Multi-chunk example** (message spans multiple APDUs):
```
→ B0 6F 01 00 [Lc]  [first message bytes]          (no response data)
→ B0 6F 00 00 [Lc]  [next message bytes]            (no response data)
→ B0 6F 80 00 [Lc]  [final message bytes]
← [64-byte signature] [32-byte public key]  90 00
```

**Errors:**
- `0x9C06` — PIN not verified
- `0x9C14` — seed not imported
- `0x9C0F` — continuation/last chunk sent without a preceding first chunk (or after a session reset)

**What to sign:** The serialized Solana transaction **message** (not the full transaction). In `@solana/web3.js`:
```typescript
const msgBytes = transaction.serializeMessage();
// send msgBytes to INS_SIGN_TX
```

---

### INS_CARD_LABEL — `0x3D`

**GET (P1 = `0x00`):** No authentication required.

**Request:**
```
B0 3D 00 00 00
```

**Response:** `[label_len (1)] [label bytes (0–64)]`

**SET (P1 = `0x01`):** Requires PIN verified.

**Request data:** `[label_len (1)] [label bytes (0–64 UTF-8)]`

Set `label_len = 0x00` to clear the label. Max 64 UTF-8 bytes.

---

### INS_EXPORT_AUTHENTIKEY — `0x73`

**Auth:** None. Works before setup.

**Request:**
```
B0 73 00 00 00
```

**Response:** 65-byte uncompressed SECP256K1 public key (`0x04` prefix + 32-byte X + 32-byte Y).

The authentikey is a persistent on-card identity keypair. It is generated on first card select after install, survives power cycles and NFC disconnects, and is wiped only by factory reset. Used to anchor the secure channel handshake.

---

### INS_INIT_SECURE_CHANNEL — `0x81`

**Auth:** None. Works before setup.

**Request data:** 65-byte uncompressed SECP256K1 public key (host's ephemeral public key, `0x04` prefix + X + Y).

**Response:**
```
[coordX_size (2 BE)] [coordX (32)] [sig1_size (2 BE)] [sig1 (~72)] [sig2_size (2 BE)] [sig2 (~72)]
```

Typical total response: ~176 bytes. See [Section 7](#7-secure-channel-protocol) for full details.

---

### INS_PROCESS_SECURE_CHANNEL — `0x82`

**Auth:** Requires active secure channel (handshake completed).

**Request data:** Encrypted command payload (see [Section 7.4](#74-wrapping-commands)).

**Response:** Encrypted response data, or empty body if the inner command produces no output. SW reflects the inner command's result code.

---

### INS_RESET_TO_FACTORY — `0xFF`

**Auth:** Requires PIN verified.

**Request:**
```
B0 FF 00 00 00
```

**Response:** `SW 0xFF00` — not `0x9000`. This special code signals reset complete.

Wipes everything: PIN, PUK, seed, master key, card label, authentikey, secure channel state. The applet remains installed but returns to the fresh/uninitialized state.

---

## 7. Secure Channel Protocol

The secure channel provides **confidentiality and integrity** for APDU communication over NFC. It uses AES-128-CBC encryption and HMAC-SHA1 message authentication, with session keys derived from a SECP256K1 ECDH exchange.

The following commands **require** an active secure channel — they will be rejected with `0x9C22` (SW_SECURE_CHANNEL_REQUIRED) if sent in plaintext:

- `INS_VERIFY_PIN` — transmits the PIN
- `INS_CHANGE_PIN` — transmits old and new PIN
- `INS_UNBLOCK_PIN` — transmits the PUK and new PIN
- `INS_IMPORT_SEED` — transmits the 64-byte BIP-39 seed

All other commands (including `INS_SIGN_TX`, `INS_GET_PUBLIC_KEY`, `INS_CARD_LABEL`) may be sent either plaintext or wrapped. The tradeoff is different for each:

- **Confidentiality** — irrelevant. `INS_SIGN_TX` input (the Solana message) is about to be broadcast on-chain; its output (signature + pubkey) is also public. Same for `INS_GET_PUBLIC_KEY` and `INS_CARD_LABEL`.
- **Integrity** — relevant for `INS_SIGN_TX`. The card has no display and signs whatever message arrives (blind signing). A physically present attacker with a rogue antenna between the phone and the card could substitute the message and the card would sign the attacker's transaction. Wrapping detects this via the HMAC.

For most users (app is trusted, NFC range is ~4 cm) the plaintext path is fine. For defense-in-depth against a physical-proximity MITM, wrap `INS_SIGN_TX`. A compromised host app is not in the threat model the secure channel addresses — it holds the session keys regardless.

**The channel is cleared on every applet deselect (every NFC tap disconnection).** There is no resumption — each new NFC session requires a full handshake.

---

### 7.1 Handshake Flow

```
Host                                              Card
 │                                                 │
 │  INS_EXPORT_AUTHENTIKEY                         │
 │ ──────────────────────────────────────────────> │
 │ <──────────────────────────────────────────────  │
 │  65-byte authentikey pubkey                     │
 │                                                 │
 │  Generate ephemeral SECP256K1 keypair           │
 │                                                 │
 │  INS_INIT_SECURE_CHANNEL                        │
 │  [65-byte host ephemeral pubkey]                │
 │ ──────────────────────────────────────────────> │
 │                                                 │  Generate ephemeral keypair
 │                                                 │  ECDH: shared = card_ephemeral_priv × host_pub
 │                                                 │  Derive session_key, mac_key from shared_X
 │ <──────────────────────────────────────────────  │
 │  [coordX_size(2) | coordX(32)                  │
 │   | sig1_size(2)  | sig1(~72)                  │
 │   | sig2_size(2)  | sig2(~72)]                 │
 │                                                 │
 │  Reconstruct card ephemeral pubkey from coordX  │
 │  Try both Y parities                            │
 │  ECDH: shared = host_priv × card_ephemeral_pub  │
 │  Derive session_key, mac_key from shared_X      │
 │                                                 │
 │  Verify sig2 against authentikey               │
 │  (confirms response came from this card)        │
 │                                                 │
 │  Channel active. All subsequent commands        │
 │  wrapped via INS_PROCESS_SECURE_CHANNEL.        │
```

---

### 7.2 Session Key Derivation

From the 32-byte ECDH shared X-coordinate:

```
session_key = HMAC-SHA1(key=shared_X, data="sc_key")[0:16]   // AES-128 key (16 bytes)
mac_key     = HMAC-SHA1(key=shared_X, data="sc_mac")[0:20]   // MAC key (20 bytes)
```

HMAC-SHA1 outputs 20 bytes. `session_key` uses only the first 16.

---

### 7.3 Reconstructing the Ephemeral Public Key

The card returns only the 32-byte X-coordinate of its ephemeral key. Recover the full point by trying both possible Y parities:

```typescript
import { ec as EC } from 'elliptic';

const secp256k1 = new EC('secp256k1');

function recoverSharedX(
  hostPrivKey: Uint8Array,
  cardEphemeralCoordX: Uint8Array
): Uint8Array {
  for (const prefix of [0x02, 0x03]) {
    const compressed = Buffer.concat([Buffer.from([prefix]), cardEphemeralCoordX]);
    try {
      const cardPub = secp256k1.keyFromPublic(compressed);
      const hostKey = secp256k1.keyFromPrivate(hostPrivKey);
      const shared = hostKey.derive(cardPub.getPublic());  // returns BN (big-endian x)
      return shared.toArrayLike(Buffer, 'be', 32);
    } catch {
      // wrong parity — try the other
    }
  }
  throw new Error('Could not reconstruct ephemeral public key');
}
```

---

### 7.4 Signature Verification

The handshake response includes two DER-encoded ECDSA-SHA256 signatures.

**sig1 (self-signature):** The card signs `[coordX_size(2) | coordX(32)]` with its ephemeral private key. Confirms the card generated the ephemeral key it returned.

**sig2 (authentikey cross-signature):** The card signs `[coordX_size(2) | coordX(32) | sig1_size(2) | sig1]` with its persistent authentikey private key. **This is the important one** — it proves the response came from the card with the known authentikey identity. Always verify this before trusting the channel.

```typescript
// Bytes covered by sig2:
const sig2Payload = Buffer.concat([
  uint16BE(32),
  cardEphemeralCoordX,
  uint16BE(sig1.length),
  sig1,
]);

// Verify using the authentikey pubkey from INS_EXPORT_AUTHENTIKEY
const authKey = secp256k1.keyFromPublic(authentikeyBytes);
const isValid = authKey.verify(sha256(sig2Payload), sig2DER);
```

---

### 7.5 Wrapping Commands

Once the handshake is complete, wrap any command inside `INS_PROCESS_SECURE_CHANNEL (0x82)`.

**Building an encrypted command:**

```
1. Construct inner APDU plaintext:
   [CLA=0xB0] [INS] [P1] [P2] [Lc] [Data...]
   (If no data: Lc = 0x00, no Data bytes; total 5 bytes)

2. PKCS#7-pad to AES block size (16 bytes):
   pad_len = 16 - (len(plaintext) % 16)
   padded  = plaintext + [pad_len] × pad_len

3. Generate IV (16 bytes):
   iv[0:12]  = 12 random bytes
   iv[12:16] = 4-byte big-endian counter (must be strictly > card's last accepted counter)
   iv[15]   |= 0x01   // last byte MUST be odd

4. Encrypt:
   encrypted = AES-128-CBC(session_key, iv, padded)

5. Compute MAC:
   mac_input = iv(16) + uint16_BE(len(encrypted)) + encrypted
   mac = HMAC-SHA1(mac_key, mac_input)   // full 20 bytes

6. Assemble payload:
   payload = iv(16) + uint16_BE(len(encrypted)) + encrypted + uint16_BE(20) + mac(20)

7. Send:
   CLA=0xB0  INS=0x82  P1=0x00  P2=0x00  Lc=len(payload)  Data=payload  Le=0x00
```

**IV counter rules:**

- The 4-byte counter at `iv[12:16]` must be **strictly greater** than the counter the card last accepted.
- Start at `1` for the first command after handshake, increment by 1 per command.
- `iv[15]` must be odd (bit 0 set). If your counter naturally makes it even, OR with `0x01`.
- The card stores the accepted counter and rejects replay or out-of-order IVs with `0x9C24`.

**Decrypting the response:**

If the inner command produces output data, the card's response body is encrypted:

```
[IV(16)] [data_size(2 BE)] [AES-CBC-ciphertext]
```

To decrypt:
```
1. iv         = response[0:16]
2. data_size  = uint16_BE(response[16:18])
3. ciphertext = response[18 : 18 + data_size]
4. padded     = AES-128-CBC-decrypt(session_key, iv, ciphertext)
5. plaintext  = padded[0 : len(padded) - padded[-1]]   // strip PKCS#7 pad
```

If the inner command produces no response data (e.g., `INS_VERIFY_PIN` on success), the outer response body is empty. Only check the SW code.

---

## 8. Full Flows

### 8.1 First-Time Setup Flow

```
1. SELECT applet
2. INS_GET_STATUS             → confirm setup_done = false
3. INS_EXPORT_AUTHENTIKEY     → store authentikey pubkey
4. INS_INIT_SECURE_CHANNEL    → complete handshake, derive session keys
5. INS_SETUP                  → set PIN + PUK
   (wrap in SC for confidentiality, or send plain — both work)
6. INS_VERIFY_PIN (wrapped)   → authenticate
7. INS_IMPORT_SEED (wrapped)  → send 64-byte BIP-39 seed
   response: 32-byte Ed25519 pubkey at m/44'/501'/0'
8. Convert pubkey to Solana address: base58encode(pubkey_32_bytes)
9. Store authentikey pubkey persistently for future session verification
```

### 8.2 Transaction Signing Flow (Established Card)

```
1. SELECT applet
2. INS_GET_STATUS             → confirm setup_done = true, is_seeded = true
3. INS_EXPORT_AUTHENTIKEY     → verify it matches the stored authentikey (card identity check)
4. INS_INIT_SECURE_CHANNEL    → ECDH handshake
5. Verify sig2 against stored authentikey pubkey
6. INS_VERIFY_PIN (wrapped)   → authenticate with user's PIN (secure channel REQUIRED)
7. Build Solana transaction, call transaction.serializeMessage()
8. INS_SIGN_TX (plaintext by default; wrap only for defense-in-depth vs physical MITM):
   - If msgBytes.length ≤ 255: single chunk (P1=0x81)
   - Otherwise: stream in 200-byte chunks
9. Response: [64-byte signature][32-byte pubkey]
10. transaction.addSignature(pubkey, signature)
11. transaction.serialize() → broadcast via @solana/web3.js
```

### 8.3 PIN Unlock Flow (Wrong PIN)

```
1. SELECT applet
2. INS_GET_STATUS             → check pin_tries_left
3. INS_VERIFY_PIN             → if 0x63Cx: wrong PIN; x tries remaining
4. If pin_tries_left = 0     → pin blocked, must use PUK
5. INS_UNBLOCK_PIN            → [puk_len][puk][new_pin_len][new_pin]
   - 0x9C0C if PUK blocked — card permanently locked, reinstall required
```

### 8.4 Recovery from Interrupted NFC Session

If an NFC tap is interrupted (user moves phone away) mid-stream `INS_SIGN_TX`:

- The signing state is **automatically cleared** by the card on `CLEAR_ON_DESELECT` (the `txSignActive` flag is transient).
- On the next tap: `SELECT`, `VERIFY_PIN`, then restart `INS_SIGN_TX` from the first chunk.
- No cleanup command is required.

---

## 9. TypeScript Reference Implementation

```typescript
import NfcManager, { NfcTech } from 'react-native-nfc-manager';
import { ec as EC } from 'elliptic';
import { createHmac, createHash } from 'crypto';
import { createCipheriv, createDecipheriv } from 'crypto';

// ── Constants ─────────────────────────────────────────────────────────────────

const APPLET_AID  = [0x53, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x00];
const CLA         = 0xb0;
const secp256k1   = new EC('secp256k1');

const INS = {
  SETUP:                  0x2a,
  GET_STATUS:             0x3c,
  CARD_LABEL:             0x3d,
  VERIFY_PIN:             0x42,
  CHANGE_PIN:             0x44,
  UNBLOCK_PIN:            0x46,
  IMPORT_SEED:            0x6c,
  GET_PUBLIC_KEY:         0x6d,
  SIGN_TX:                0x6f,
  EXPORT_AUTHENTIKEY:     0x73,
  RESET_SEED:             0x77,
  INIT_SECURE_CHANNEL:    0x81,
  PROCESS_SECURE_CHANNEL: 0x82,
  RESET_TO_FACTORY:       0xff,
} as const;

const P1_SIGN = { FIRST: 0x01, LAST: 0x80, FIRST_LAST: 0x81, CONTINUATION: 0x00 } as const;

// ── APDU helpers ──────────────────────────────────────────────────────────────

type Transceiver = (apdu: number[]) => Promise<number[]>;

function swOf(resp: number[]): number {
  return ((resp[resp.length - 2] & 0xff) << 8) | (resp[resp.length - 1] & 0xff);
}

function dataOf(resp: number[]): Buffer {
  return Buffer.from(resp.slice(0, -2));
}

function assertSW(resp: number[], expected = 0x9000, label = 'command'): void {
  const s = swOf(resp);
  if (s !== expected) throw new Error(`${label} failed: SW=${s.toString(16).toUpperCase()}`);
}

function buildApdu(ins: number, p1: number, p2: number, data?: Buffer | number[]): number[] {
  const payload = data ? Buffer.from(data) : null;
  if (!payload || payload.length === 0) return [CLA, ins, p1, p2, 0x00];
  return [CLA, ins, p1, p2, payload.length, ...payload, 0x00];
}

async function send(
  transceive: Transceiver,
  ins: number, p1: number, p2: number, data?: Buffer | number[]
): Promise<number[]> {
  return transceive(buildApdu(ins, p1, p2, data));
}

// ── Card commands ─────────────────────────────────────────────────────────────

async function selectApplet(transceive: Transceiver): Promise<void> {
  const cmd = [0x00, 0xa4, 0x04, 0x00, APPLET_AID.length, ...APPLET_AID];
  assertSW(await transceive(cmd), 0x9000, 'SELECT');
}

async function getStatus(transceive: Transceiver) {
  const resp = await send(transceive, INS.GET_STATUS, 0, 0);
  assertSW(resp, 0x9000, 'GET_STATUS');
  const d = dataOf(resp);
  return {
    protoMajor:    d[0],  protoMinor:   d[1],
    appMajor:      d[2],  appMinor:     d[3],
    pinTriesLeft:  d[4],  pinTriesMax:  d[5],
    pukTriesLeft:  d[6],  pukTriesMax:  d[7],
    isSeeded:      d[8]  === 0x01,
    secureChannel: d[9]  === 0x01,
    setupDone:     d[10] === 0x01,
  };
}

async function setupCard(
  transceive: Transceiver,
  pin: Buffer,
  puk: Buffer
): Promise<void> {
  const data = Buffer.concat([Buffer.from([pin.length]), pin, Buffer.from([puk.length]), puk]);
  assertSW(await send(transceive, INS.SETUP, 0, 0, data), 0x9000, 'SETUP');
}

async function verifyPin(transceive: Transceiver, pin: Buffer): Promise<void> {
  const resp = await send(transceive, INS.VERIFY_PIN, 0, 0, pin);
  const s = swOf(resp);
  if (s === 0x9000) return;
  if ((s & 0xfff0) === 0x63c0) throw new Error(`Wrong PIN — ${s & 0x0f} tries remaining`);
  if (s === 0x9c0c) throw new Error('PIN blocked — use PUK to unblock');
  throw new Error(`VERIFY_PIN failed: ${s.toString(16).toUpperCase()}`);
}

async function importSeed(transceive: Transceiver, seed64: Buffer): Promise<Buffer> {
  if (seed64.length !== 64) throw new Error('Seed must be exactly 64 bytes');
  const resp = await send(transceive, INS.IMPORT_SEED, 0, 0, seed64);
  assertSW(resp, 0x9000, 'IMPORT_SEED');
  return dataOf(resp); // 32-byte public key
}

async function getPublicKey(transceive: Transceiver, path: number[]): Promise<Buffer> {
  const buf = Buffer.alloc(1 + path.length * 4);
  buf[0] = path.length;
  path.forEach((idx, i) => buf.writeUInt32BE(idx, 1 + i * 4));
  const resp = await send(transceive, INS.GET_PUBLIC_KEY, 0, 0, buf);
  assertSW(resp, 0x9000, 'GET_PUBLIC_KEY');
  return dataOf(resp); // 32 bytes
}

async function signTx(
  transceive: Transceiver,
  message: Buffer,
  chunkSize = 200
): Promise<{ sig: Buffer; pubkey: Buffer }> {
  const chunks: Buffer[] = [];
  for (let off = 0; off < message.length; off += chunkSize) {
    chunks.push(message.subarray(off, off + chunkSize));
  }
  if (chunks.length === 0) chunks.push(Buffer.alloc(0));

  let resp: number[];

  if (chunks.length === 1) {
    resp = await send(transceive, INS.SIGN_TX, P1_SIGN.FIRST_LAST, 0, chunks[0]);
    assertSW(resp, 0x9000, 'SIGN_TX (single)');
  } else {
    resp = await send(transceive, INS.SIGN_TX, P1_SIGN.FIRST, 0, chunks[0]);
    assertSW(resp, 0x9000, 'SIGN_TX (first)');

    for (let i = 1; i < chunks.length - 1; i++) {
      resp = await send(transceive, INS.SIGN_TX, P1_SIGN.CONTINUATION, 0, chunks[i]);
      assertSW(resp, 0x9000, `SIGN_TX (chunk ${i})`);
    }

    resp = await send(transceive, INS.SIGN_TX, P1_SIGN.LAST, 0, chunks[chunks.length - 1]);
    assertSW(resp, 0x9000, 'SIGN_TX (last)');
  }

  const data = dataOf(resp);
  if (data.length !== 96) throw new Error(`Expected 96-byte response, got ${data.length}`);
  return { sig: data.subarray(0, 64), pubkey: data.subarray(64, 96) };
}

// ── Secure Channel ────────────────────────────────────────────────────────────

function hmacSha1(key: Buffer, data: Buffer): Buffer {
  return createHmac('sha1', key).update(data).digest();
}

function uint16BE(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  return b;
}

function pkcs7Pad(data: Buffer, blockSize = 16): Buffer {
  const pad = blockSize - (data.length % blockSize);
  return Buffer.concat([data, Buffer.alloc(pad, pad)]);
}

function pkcs7Unpad(data: Buffer): Buffer {
  const pad = data[data.length - 1];
  return data.subarray(0, data.length - pad);
}

function aes128cbcEncrypt(key: Buffer, iv: Buffer, plaintext: Buffer): Buffer {
  const cipher = createCipheriv('aes-128-cbc', key, iv);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

function aes128cbcDecrypt(key: Buffer, iv: Buffer, ciphertext: Buffer): Buffer {
  const decipher = createDecipheriv('aes-128-cbc', key, iv);
  decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

class SecureChannel {
  private sessionKey!: Buffer;
  private macKey!: Buffer;
  private counter = 0;
  authentikeyPubkey: Buffer | null = null;

  async exportAuthentikey(transceive: Transceiver): Promise<Buffer> {
    const resp = await send(transceive, INS.EXPORT_AUTHENTIKEY, 0, 0);
    assertSW(resp, 0x9000, 'EXPORT_AUTHENTIKEY');
    const key = dataOf(resp);
    if (key.length !== 65 || key[0] !== 0x04) throw new Error('Invalid authentikey format');
    this.authentikeyPubkey = key;
    return key;
  }

  async handshake(transceive: Transceiver): Promise<void> {
    // 1. Generate ephemeral host keypair
    const hostKey     = secp256k1.genKeyPair();
    const hostPubUncompressed = Buffer.from(hostKey.getPublic().encode('array', false));

    // 2. Send INS_INIT_SECURE_CHANNEL
    const resp = await send(transceive, INS.INIT_SECURE_CHANNEL, 0, 0, hostPubUncompressed);
    assertSW(resp, 0x9000, 'INIT_SECURE_CHANNEL');
    const d = dataOf(resp);

    // 3. Parse response
    let off = 0;
    const coordXSize = d.readUInt16BE(off); off += 2;
    if (coordXSize !== 32) throw new Error(`Unexpected coordX size: ${coordXSize}`);
    const coordX = d.subarray(off, off + 32); off += 32;
    const sig1Size = d.readUInt16BE(off); off += 2;
    const sig1 = d.subarray(off, off + sig1Size); off += sig1Size;
    const sig2Size = d.readUInt16BE(off); off += 2;
    const sig2 = d.subarray(off, off + sig2Size);

    // 4. Recover shared X via ECDH (try both Y parities)
    let sharedX: Buffer | null = null;
    for (const prefix of [0x02, 0x03]) {
      const compressed = Buffer.concat([Buffer.from([prefix]), coordX]);
      try {
        const cardEphemeral = secp256k1.keyFromPublic(compressed);
        const shared = hostKey.derive(cardEphemeral.getPublic());
        sharedX = shared.toArrayLike(Buffer as any, 'be', 32) as Buffer;
        break;
      } catch { /* wrong parity */ }
    }
    if (!sharedX) throw new Error('Could not reconstruct card ephemeral pubkey');

    // 5. Derive session and MAC keys
    this.sessionKey = hmacSha1(sharedX, Buffer.from('sc_key')).subarray(0, 16);
    this.macKey     = hmacSha1(sharedX, Buffer.from('sc_mac')).subarray(0, 20);
    this.counter    = 0;

    // 6. Verify sig2 against authentikey (card identity verification)
    if (this.authentikeyPubkey) {
      const sig2Payload = Buffer.concat([uint16BE(32), coordX, uint16BE(sig1.length), sig1]);
      const sha256 = createHash('sha256').update(sig2Payload).digest();
      const authKey = secp256k1.keyFromPublic(this.authentikeyPubkey);
      const valid = authKey.verify(sha256, sig2);
      if (!valid) throw new Error('Authentikey signature verification failed — untrusted card');
    }
  }

  async send(
    transceive: Transceiver,
    ins: number, p1: number, p2: number,
    innerData?: Buffer
  ): Promise<number[]> {
    this.counter++;
    // Build IV: 12 random bytes + 4-byte counter with odd last byte
    const ivRandom  = Buffer.alloc(12); crypto.getRandomValues(ivRandom);
    const ivCounter = Buffer.alloc(4);
    ivCounter.writeUInt32BE(this.counter, 0);
    const iv = Buffer.concat([ivRandom, ivCounter]);
    if ((iv[15] & 0x01) === 0) iv[15] |= 0x01; // enforce odd last byte

    // Build inner plaintext
    const hasData   = innerData && innerData.length > 0;
    const plaintext = hasData
      ? Buffer.from([CLA, ins, p1, p2, innerData!.length, ...innerData!])
      : Buffer.from([CLA, ins, p1, p2, 0x00]);

    const padded    = pkcs7Pad(plaintext);
    const encrypted = aes128cbcEncrypt(this.sessionKey, iv, padded);

    const macInput = Buffer.concat([iv, uint16BE(encrypted.length), encrypted]);
    const mac      = hmacSha1(this.macKey, macInput).subarray(0, 20);

    const payload  = Buffer.concat([
      iv, uint16BE(encrypted.length), encrypted, uint16BE(20), mac
    ]);

    const resp = await transceive(buildApdu(INS.PROCESS_SECURE_CHANNEL, 0, 0, payload));

    // Decrypt response if it has a body
    const s = swOf(resp);
    const body = dataOf(resp);
    if (body.length === 0) return resp; // inner command had no response data
    if (body.length < 18) throw new Error('Encrypted response too short');

    const respIv       = body.subarray(0, 16);
    const respDataSize = body.readUInt16BE(16);
    const respCipher   = body.subarray(18, 18 + respDataSize);
    const decrypted    = pkcs7Unpad(aes128cbcDecrypt(this.sessionKey, respIv, respCipher));

    // Reconstruct: [decrypted data][SW1][SW2]
    return [...decrypted, (s >> 8) & 0xff, s & 0xff];
  }
}

// ── Top-level NFC session ─────────────────────────────────────────────────────

export async function signSolanaTransaction(
  messageBytes: Buffer,
  pin: string
): Promise<{ sig: Buffer; pubkey: Buffer }> {
  await NfcManager.start();
  await NfcManager.requestTechnology(NfcTech.IsoDep);

  try {
    const transceive: Transceiver = (apdu) => NfcManager.isoDepHandler.transceive(apdu);

    // 1. Select
    await selectApplet(transceive);

    // 2. Status check
    const status = await getStatus(transceive);
    if (!status.setupDone) throw new Error('Card not set up');
    if (!status.isSeeded)  throw new Error('Seed not imported');
    if (status.pinTriesLeft === 0) throw new Error('PIN blocked');

    // 3. Secure channel
    const sc = new SecureChannel();
    await sc.exportAuthentikey(transceive);
    await sc.handshake(transceive);

    // 4. PIN verification — MUST go through the secure channel
    const pinBuf = Buffer.from(pin, 'utf8');
    const pinResp = await sc.send(transceive, INS.VERIFY_PIN, 0, 0, pinBuf);
    if (swOf(pinResp) !== 0x9000) {
      const tries = swOf(pinResp) & 0x0f;
      throw new Error(`Wrong PIN — ${tries} tries remaining`);
    }

    // 5. Sign the transaction message
    //
    // INS_SIGN_TX is NOT gated by the secure channel — the message and the
    // signature are both public on-chain. Plaintext is fine for most threat
    // models. Two modes are shown:
    //
    //   (A) Plaintext — simpler, lower latency. Recommended default.
    //   (B) Wrapped   — defense-in-depth: the HMAC detects a physically-present
    //                   MITM substituting the message before the card signs it.
    //                   Each chunk incurs encrypt/MAC overhead.

    // --- Mode A: plaintext sign ---
    return await signTx(transceive, messageBytes);

    // --- Mode B: wrapped sign (swap the above return for this block) ---
    // const wrappedTransceive: Transceiver = (apdu) => sc.send(
    //   transceive,
    //   apdu[1],                                   // INS
    //   apdu[2],                                   // P1
    //   apdu[3],                                   // P2
    //   apdu.length > 5 ? Buffer.from(apdu.slice(5, -1)) : undefined,  // data
    // );
    // return await signTx(wrappedTransceive, messageBytes);

  } finally {
    NfcManager.cancelTechnologyRequest();
  }
}
```

---

## 10. Error Handling

### 10.1 Status Word Reference

**Standard:**

| SW       | Meaning                                                       |
|----------|---------------------------------------------------------------|
| `0x9000` | Success                                                       |
| `0xFF00` | Factory reset complete (only from `INS_RESET_TO_FACTORY`)     |
| `0x63Cx` | Wrong PIN or PUK — `x` = retries remaining (0–5)             |
| `0x6D00` | Unknown instruction (INS not recognized)                      |
| `0x6E00` | CLA not `0xB0`                                                |
| `0x6A82` | Applet AID not found (not installed)                          |

**Application:**

| SW       | Constant              | Meaning                                                |
|----------|-----------------------|--------------------------------------------------------|
| `0x9C03` | SETUP_ALREADY_DONE    | `INS_SETUP` called on an already-set-up card           |
| `0x9C04` | SETUP_NOT_DONE        | Command requires setup; call `INS_SETUP` first         |
| `0x9C05` | UNSUPPORTED_FEATURE   | Feature not available on this card                     |
| `0x9C06` | UNAUTHORIZED          | PIN not verified in current session                    |
| `0x9C0C` | IDENTITY_BLOCKED      | PIN or PUK retry counter exhausted                     |
| `0x9C0F` | INVALID_PARAMETER     | Bad data length, format, or unhardened path index      |
| `0x9C14` | SEED_NOT_IMPORTED     | Requires seed; call `INS_IMPORT_SEED` first            |
| `0x9C20` | NOT_IMPLEMENTED       | Not implemented (should not occur in release builds)   |

**Secure channel:**

| SW       | Constant                   | Meaning                                                  |
|----------|----------------------------|----------------------------------------------------------|
| `0x9C21` | SC_UNINITIALIZED           | `INS_PROCESS_SECURE_CHANNEL` before handshake            |
| `0x9C22` | SC_REQUIRED                | Command requires secure channel                          |
| `0x9C23` | SC_WRONG_MAC               | HMAC verification failed (tampered data or wrong key)    |
| `0x9C24` | SC_WRONG_IV                | IV counter not strictly increasing or last byte not odd  |

**Diagnostic (internal card errors, should not occur in production):**

| SW Range | Meaning                                                           |
|----------|-------------------------------------------------------------------|
| `0x9C5x` | CryptoException during decryption (`x` = JavaCard reason code)   |
| `0x9C60` | ArrayIndexOutOfBoundsException during decryption                  |
| `0x9C61` | NullPointerException during decryption                            |
| `0x9C6F` | Other exception during decryption                                 |
| `0x9C7x` | CryptoException during command dispatch                           |
| `0x9C80` | ArrayIndexOutOfBoundsException during dispatch                    |
| `0x9C81` | NullPointerException during dispatch                              |
| `0x9C8F` | Other exception during dispatch                                   |

### 10.2 Handling Common Scenarios

```typescript
function interpretSW(swValue: number, context: string): Error {
  switch (true) {
    case swValue === 0x9000: return null!;  // success
    case (swValue & 0xfff0) === 0x63c0: {
      const tries = swValue & 0x0f;
      return new Error(`Wrong PIN/PUK — ${tries} ${tries === 1 ? 'try' : 'tries'} remaining`);
    }
    case swValue === 0x9c0c: return new Error('PIN/PUK blocked — card is permanently locked');
    case swValue === 0x9c04: return new Error('Card not set up — call SETUP first');
    case swValue === 0x9c06: return new Error('Not authenticated — verify PIN first');
    case swValue === 0x9c14: return new Error('No seed imported — call IMPORT_SEED first');
    case swValue === 0x9c0f: return new Error(`Invalid parameter in ${context}`);
    case swValue === 0x9c21: return new Error('Secure channel not initialized');
    case swValue === 0x9c23: return new Error('Secure channel MAC verification failed');
    case swValue === 0x9c24: return new Error('Secure channel IV rejected');
    case swValue === 0x6a82: return new Error('Applet not installed on this card');
    default:
      return new Error(`${context} failed: SW=0x${swValue.toString(16).toUpperCase()}`);
  }
}
```

### 10.3 NFC-Specific Error Handling

```typescript
try {
  // NFC operation
} catch (err: any) {
  if (err?.message?.includes('Tag was lost') || err?.message?.includes('NFC tag was lost')) {
    // Card moved away mid-operation. Re-request technology and retry from SELECT.
  }
  if (err?.message?.includes('Not supported') || err?.message?.includes('NFC not supported')) {
    // Device doesn't have NFC hardware or it's disabled.
  }
}
```

---

## 11. Timing and UX

| Operation                          | Approximate Duration |
|------------------------------------|----------------------|
| SELECT applet                      | < 50 ms              |
| INS_GET_STATUS                     | < 50 ms              |
| INS_EXPORT_AUTHENTIKEY             | < 50 ms              |
| INS_INIT_SECURE_CHANNEL (ECDH)     | ~200–500 ms          |
| INS_VERIFY_PIN                     | < 50 ms              |
| INS_IMPORT_SEED (SLIP-0010 derive) | ~2,700 ms            |
| INS_GET_PUBLIC_KEY (default path)  | ~2,700 ms            |
| INS_GET_PUBLIC_KEY (non-default)   | ~5,400 ms            |
| INS_SIGN_TX (Ed25519 sign)         | ~1,440 ms            |
| Full sign flow (after seed import) | ~2,500 ms total      |

**UX recommendations:**

- Show a "Hold card steady..." UI during the entire NFC session — especially during `IMPORT_SEED` and `SIGN_TX`, which are the longest operations.
- Display a progress indicator for multi-step flows (setup, handshake, PIN, sign).
- If the card disconnects mid-sign (user moves phone), prompt to "Hold card and try again" — the card cleans up automatically.
- Use vibration or sound feedback when the NFC connection is established and when signing completes.
- Do not attempt to cancel or abort an in-progress card operation — simply drop the NFC session if needed; the card will recover on the next tap.

---

## 12. Security Considerations

### 12.1 Sensitive data over NFC

- `INS_VERIFY_PIN`, `INS_CHANGE_PIN`, `INS_UNBLOCK_PIN`, and `INS_IMPORT_SEED` **must** be sent inside the secure channel — the card rejects them with `0x9C22` otherwise. These carry secrets (PIN, PUK, seed) on the wire.
- `INS_SIGN_TX` is not gated by the secure channel. Neither its input (a public Solana transaction message) nor its output (signature + pubkey, both published on-chain) is confidential. Plaintext is the default recommendation.
- Consider wrapping `INS_SIGN_TX` only if your threat model includes a physically-present MITM attacker capable of injecting a rogue antenna between phone and card. The card has no display and signs whatever arrives; the HMAC in the secure channel is the only transport-layer defense against a swapped message. This does not protect against a compromised host app (which holds the session keys).

### 12.2 Authentikey pinning

Store the 65-byte authentikey public key (from `INS_EXPORT_AUTHENTIKEY`) persistently in your app after the first successful setup. On every subsequent session:

1. Fetch the authentikey again.
2. Compare it to the stored value.
3. Reject the session if it differs — this would indicate a different (possibly attacker-controlled) card.

The authentikey is persistent across power cycles and is wiped only by factory reset, so it uniquely identifies the card.

### 12.3 sig2 verification

Always verify `sig2` during the secure channel handshake. Skipping this check means you cannot confirm the encrypted channel was established with the genuine card — a malicious intermediary could substitute its own ECDH key.

### 12.4 PIN management

- Never store the PIN in plaintext on the device. At most hold it in memory for the duration of one NFC session.
- Present the PIN entry UI fresh on every NFC tap rather than caching the PIN between sessions.
- Implement exponential back-off or lockout in the app UI if `pin_tries_left` is low, to prevent accidentally exhausting the retry counter.
- If `pin_tries_left` drops to `1`, warn the user prominently before attempting another PIN verification.

### 12.5 Seed handling

The host app is responsible for:
1. Generating or accepting the BIP-39 mnemonic.
2. Running PBKDF2-HMAC-SHA512 (2048 iterations, 64-byte output) to derive the seed.
3. Sending the 64-byte seed to the card inside the secure channel.
4. **Never persisting the mnemonic or seed on the device** once it has been loaded to the card.

The card stores only the SLIP-0010-derived master key and chain code, not the original seed. After `INS_IMPORT_SEED`, the seed bytes are not recoverable from the card.

### 12.6 APDU size limit

Each APDU data field is limited to **255 bytes**. The `INS_SIGN_TX` chunking handles this transparently, but if you build custom command wrappers, enforce this limit. Sending more than 255 bytes in a single APDU will be rejected by the card reader, not the applet.

### 12.7 Transaction message vs full transaction

Send only the serialized **message** bytes to `INS_SIGN_TX` — not the full signed transaction. In `@solana/web3.js`:

```typescript
// Correct:
const msgBytes = transaction.serializeMessage();

// Wrong (includes existing signatures, feePayer, etc.):
// const rawTx = transaction.serialize();
```

---

## Appendix A: Quick Reference

```
AID:  53 6F 6C 61 6E 61 00   ("Solana\x00")
CLA:  0xB0

INS_SETUP                   0x2A   Set PIN + PUK (once only)
INS_GET_STATUS              0x3C   Read card state (12 bytes)
INS_CARD_LABEL              0x3D   Get/set label (P1: 0=get, 1=set)
INS_VERIFY_PIN              0x42   Authenticate for session
INS_CHANGE_PIN              0x44   Replace PIN (PIN required)
INS_UNBLOCK_PIN             0x46   Reset PIN via PUK
INS_IMPORT_SEED             0x6C   Import 64-byte BIP-39 seed (PIN required)
INS_GET_PUBLIC_KEY          0x6D   Derive + return Ed25519 pubkey (PIN required)
INS_SIGN_TX                 0x6F   Sign Solana tx (PIN required, multi-chunk)
INS_EXPORT_AUTHENTIKEY      0x73   Get 65-byte SECP256K1 identity pubkey
INS_RESET_SEED              0x77   Wipe seed (PIN required)
INS_INIT_SECURE_CHANNEL     0x81   ECDH handshake
INS_PROCESS_SECURE_CHANNEL  0x82   Send encrypted command
INS_RESET_TO_FACTORY        0xFF   Wipe everything (PIN required, returns 0xFF00)

Standard Solana path m/44'/501'/0':
  depth=3  [0x8000002C] [0x800001F5] [0x80000000]

INS_SIGN_TX notes:
  - No path bytes in APDU — always signs at m/44'/501'/0'
  - Response (last chunk only): [64-byte signature][32-byte pubkey] = 96 bytes total
  - Chunk size recommendation: 200 bytes per APDU (fits comfortably under 255-byte limit)
```

## Appendix B: Solana Address Derivation

The card returns a raw 32-byte Ed25519 public key. The Solana address is the **Base58** encoding of those 32 bytes (no checksum, no version byte):

```typescript
import { PublicKey } from '@solana/web3.js';

const pubkeyBytes: Buffer = /* 32 bytes from card */;
const address: string = new PublicKey(pubkeyBytes).toBase58();
```

## Appendix C: BIP-39 Seed Derivation (Host Side)

```typescript
import * as bip39 from 'bip39';

const mnemonic = 'word1 word2 ... word24';
const passphrase = '';  // optional BIP-39 passphrase

// Validate
if (!bip39.validateMnemonic(mnemonic)) throw new Error('Invalid mnemonic');

// Derive 64-byte seed
const seed: Buffer = await bip39.mnemonicToSeed(mnemonic, passphrase);
// seed is the PBKDF2-HMAC-SHA512 output — send directly to INS_IMPORT_SEED
```

The card performs HMAC-SHA512 with key `"ed25519 seed"` and the seed bytes as the message (SLIP-0010 master key derivation) internally — the host sends the raw PBKDF2 output.
