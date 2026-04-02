# TapiocaApplet — Protocol Reference

Host-platform-agnostic APDU protocol reference for the TapiocaApplet JavaCard hardware wallet. Covers the full wire protocol: command format, card lifecycle, every command, secure channel, and all status words.

---

## Table of Contents

1. [APDU Format](#apdu-format)
2. [Applet Selection](#applet-selection)
3. [Card Lifecycle](#card-lifecycle)
4. [PIN Session Model](#pin-session-model)
5. [Command Reference](#command-reference)
6. [Secure Channel Protocol](#secure-channel-protocol)
7. [Transaction Signing Flow](#transaction-signing-flow)
8. [Status Word Reference](#status-word-reference)
9. [Quick Reference](#quick-reference)

---

## APDU Format

### Command APDU

```
[CLA] [INS] [P1] [P2] [Lc] [Data...] [Le]
```

| Field | Size | Description                                      |
| ----- | ---- | ------------------------------------------------ |
| CLA   | 1    | Always `0xB0` for TapiocaApplet                  |
| INS   | 1    | Instruction code                                 |
| P1    | 1    | Parameter 1 (command-specific)                   |
| P2    | 1    | Parameter 2 (always `0x00` unless noted)         |
| Lc    | 1    | Length of Data field (omit or `0x00` if no data) |
| Data  | Lc   | Command payload                                  |
| Le    | 1    | Expected response length (always `0x00` = max)   |

### Response APDU

```
[Data...] [SW1] [SW2]
```

| Field   | Size     | Description                      |
| ------- | -------- | -------------------------------- |
| Data    | variable | Response payload (may be empty)  |
| SW1 SW2 | 2        | Status word — `0x9000` = success |

### APDU size limits

Standard (short) APDUs are used throughout. Each individual APDU data field is limited to **255 bytes**. For messages larger than this, use the multi-chunk streaming protocol (see [INS_SIGN_TX](#ins_sign_tx-0x6f)).

---

## Applet Selection

Before issuing any command, select the applet via ISO 7816-4 SELECT:

```
CLA=0x00  INS=0xA4  P1=0x04  P2=0x00  Lc=0x07  Data=[53 6F 6C 61 6E 61 00]  Le=0x00
```

The AID is `53 6F 6C 61 6E 61 00` (ASCII "Solana" + `0x00`).

Expected response: `SW = 0x9000`. Returns `0x6A82` if the applet is not installed.

**The applet must be re-selected at the start of every new transport session** (every NFC tap, every new PC/SC connection). A new session always starts with no PIN validation and no secure channel.

---

## Card Lifecycle

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

**Fresh card**: Only `INS_GET_STATUS`, `INS_EXPORT_AUTHENTIKEY`, and `INS_INIT_SECURE_CHANNEL` are available. All others return `0x9C04` (SW_SETUP_NOT_DONE).

**Setup done**: PIN and PUK are set. PIN verification and label operations are available. Signing returns `0x9C14` (SW_SEED_NOT_IMPORTED).

**Seeded**: BIP-39 seed has been imported. All commands available.

---

## PIN Session Model

PIN validation is **per-session** — it resets on every applet deselect (every disconnect). After reconnecting, the PIN must be re-verified.

| Parameter    | Default | Range            |
| ------------ | ------- | ---------------- |
| PIN length   | —       | 4–16 bytes       |
| PIN attempts | 5       | set at INS_SETUP |
| PUK length   | —       | 4–16 bytes       |
| PUK attempts | 3       | set at INS_SETUP |

- After exhausting PIN retries, use `INS_UNBLOCK_PIN` with the PUK to set a new PIN.
- After exhausting PUK retries, the card is permanently locked. Factory reset is unavailable (it also requires PIN). The applet must be reinstalled.

---

## Command Reference

All commands use `CLA = 0xB0`. All return `SW = 0x9000` on success unless noted.

---

### INS_GET_STATUS (0x3C)

**Authentication:** None. Works before setup.

**Request:** `B0 3C 00 00 00`

**Response (12 bytes):**

| Offset | Size | Field          | Description                                   |
| ------ | ---- | -------------- | --------------------------------------------- |
| 0      | 1    | proto_major    | Protocol version major (`0x00`)               |
| 1      | 1    | proto_minor    | Protocol version minor (`0x01`)               |
| 2      | 1    | app_major      | Applet version major (`0x00`)                 |
| 3      | 1    | app_minor      | Applet version minor (`0x01`)                 |
| 4      | 1    | pin_tries_left | Remaining PIN attempts (`0` if not setup)     |
| 5      | 1    | pin_tries_max  | Max PIN attempts (`5`)                        |
| 6      | 1    | puk_tries_left | Remaining PUK attempts (`0` if not setup)     |
| 7      | 1    | puk_tries_max  | Max PUK attempts (`3`)                        |
| 8      | 1    | is_seeded      | `0x01` if seed imported, `0x00` otherwise     |
| 9      | 1    | secure_channel | `0x01` if SC session active, `0x00` otherwise |
| 10     | 1    | setup_done     | `0x01` if setup complete, `0x00` otherwise    |
| 11     | 1    | reserved       | Always `0x00`                                 |

---

### INS_SETUP (0x2A)

**Authentication:** None. Can only be called once (subsequent calls return `0x9C03`).

**Request data:**

```
[pin_len (1)] [pin (4–16 bytes)] [puk_len (1)] [puk (4–16 bytes)]
```

**Response:** `SW 0x9000`

**Errors:** `0x9C03` — setup already done.

**Example** — PIN = `31 32 33 34` (4 bytes), PUK = `41 42 43 44 45 46` (6 bytes):

```
B0 2A 00 00 0C  04 31 32 33 34  06 41 42 43 44 45 46  00
```

---

### INS_VERIFY_PIN (0x42)

**Authentication:** Requires setup done.

**Request data:** PIN bytes (4–16 bytes, raw — not length-prefixed).

**Response:** `SW 0x9000` on success.

**Errors:**

- `0x63Cx` — wrong PIN; `x` = remaining tries (e.g., `0x63C4` = 4 tries left)
- `0x9C0C` — PIN blocked

**Example** — PIN `31 32 33 34`:

```
B0 42 00 00 04  31 32 33 34  00
```

---

### INS_CHANGE_PIN (0x44)

**Authentication:** Requires PIN verified in current session.

**Request data:**

```
[old_len (1)] [old_pin] [new_len (1)] [new_pin]
```

**Errors:** `0x9C06` — PIN not verified; `0x63Cx` — old PIN wrong.

---

### INS_UNBLOCK_PIN (0x46)

**Authentication:** None (the PUK itself provides authentication).

**Request data:**

```
[puk_len (1)] [puk] [new_pin_len (1)] [new_pin]
```

**Errors:** `0x63Cx` — wrong PUK; `0x9C0C` — PUK blocked (permanent lockout).

---

### INS_IMPORT_SEED (0x6C)

**Authentication:** Requires PIN verified.

**Request:** `B0 6C 00 00 40 [64-byte BIP-39 seed] 00`

The 64-byte seed is the standard BIP-39 output:

```
PBKDF2(HMAC-SHA512, mnemonic_words, "mnemonic" + passphrase, iterations=2048, dklen=64)
```

**Response:** 32-byte Ed25519 public key at the default Solana path `m/44'/501'/0'`.

**Timing:** ~2,700 ms (SLIP-0010 derivation on-card is computationally expensive).

**Notes:**

- Replaces any previously imported seed.
- Send this command inside the secure channel to protect the seed over NFC.

---

### INS_RESET_SEED (0x77)

**Authentication:** Requires PIN verified.

**Request:** `B0 77 00 00 00`

Wipes the master key and chain code. Card returns to "setup done, not seeded" state.

---

### INS_GET_PUBLIC_KEY (0x6D)

**Authentication:** Requires PIN verified and seed imported.

**Request data:**

```
[depth (1)] [index_0 (4 BE)] [index_1 (4 BE)] ... [index_{depth-1} (4 BE)]
```

All indexes must be hardened: bit 31 set (`0x80000000 | n`). Returns `0x9C0F` if any index is not hardened.

**Response:** 32-byte Ed25519 public key at the requested path.

**Timing:** ~2,700 ms (full SLIP-0010 derivation from master key).

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

---

### INS_SIGN_TX (0x6F)

**Authentication:** Requires PIN verified and seed imported.

Signs a Solana transaction message using Ed25519. Supports multi-chunk streaming for messages up to 1,200 bytes.

**P1 flags:**

| P1     | Meaning                                  |
| ------ | ---------------------------------------- |
| `0x81` | Single-chunk (first + last)              |
| `0x01` | First chunk of a multi-chunk message     |
| `0x00` | Continuation chunk                       |
| `0x80` | Last chunk — response contains signature |

**First chunk data (P1 = `0x01` or `0x81`):**

```
[depth (1)] [index_0 (4 BE)] ... [index_{depth-1} (4 BE)] [message bytes...]
```

**Continuation / last chunk data (P1 = `0x00` or `0x80`):**

```
[message bytes...]
```

**Response** (last chunk only): 64-byte Ed25519 signature.

**Timing:** ~4,200 ms total (derivation ~2,700 ms on first chunk + signing ~1,440 ms on last chunk).

**What to sign:** The serialized Solana transaction _message_ — not the full transaction. This is the output of `transaction.serializeMessage()` in `@solana/web3.js`, or equivalently the bytes that get hashed for signing in the Solana protocol.

**Maximum message size:** 1,200 bytes (covers the Solana network limit of ~1,168 bytes).

**Single-chunk example** (100-byte message at `m/44'/501'/0'`):

```
→ B0 6F 81 00 [Lc]  03 80 00 00 2C 80 00 01 F5 80 00 00 00 [100 message bytes]  00
← [64-byte signature]  90 00
```

**Multi-chunk example** (500-byte message):

```
→ B0 6F 01 00 [Lc]  03 80 00 00 2C 80 00 01 F5 80 00 00 00 [first message bytes]
→ B0 6F 00 00 [Lc]  [next message bytes]
→ B0 6F 80 00 [Lc]  [final message bytes]
← [64-byte signature]  90 00
```

If the NFC session is interrupted mid-stream, the partial signing state is cleared on deselect. Restart from the first chunk on the next session.

---

### INS_CARD_LABEL (0x3D)

**GET (P1 = `0x00`):** No authentication required.

**Request:** `B0 3D 00 00 00`

**Response:** `[label_len (1)] [label bytes (0–64)]`

**SET (P1 = `0x01`):** Requires PIN verified.

**Request data:** `[label_len (1)] [label bytes (0–64)]`

Label is UTF-8 encoded, max 64 bytes. Set `label_len = 0x00` to clear.

---

### INS_EXPORT_AUTHENTIKEY (0x73)

**Authentication:** None. Works before setup.

**Request:** `B0 73 00 00 00`

**Response:** 65-byte uncompressed SECP256K1 public key (`0x04` prefix + 32-byte X + 32-byte Y).

The authentikey is a persistent on-card identity keypair that survives power cycles (but is wiped by factory reset). It is used to anchor the secure channel handshake.

---

### INS_INIT_SECURE_CHANNEL (0x81)

**Authentication:** None. Works before setup.

**Request data:** 65-byte uncompressed SECP256K1 public key (host's ephemeral public key).

**Response:**

```
[coordX_size (2 BE)] [coordX (32)] [sig1_size (2 BE)] [sig1 (~72)] [sig2_size (2 BE)] [sig2 (~72)]
```

Typical total response size: ~176 bytes. See [Secure Channel Protocol](#secure-channel-protocol) for full details.

---

### INS_PROCESS_SECURE_CHANNEL (0x82)

**Authentication:** Requires active secure channel session (handshake completed).

**Request data:** Encrypted command payload (see [Wrapping Commands](#wrapping-commands)).

**Response:** Encrypted response data, or empty if the inner command produces no output. The SW code reflects the inner command's result.

---

### INS_RESET_TO_FACTORY (0xFF)

**Authentication:** Requires PIN verified.

**Request:** `B0 FF 00 00 00`

**Response:** `SW 0xFF00` (special status word indicating reset complete — not `0x9000`).

Wipes everything: PIN, PUK, seed, master key, card label, authentikey, secure channel state. The applet returns to fresh/uninitialized state; `INS_SETUP` must be called again.

---

## Secure Channel Protocol

The secure channel provides confidentiality and integrity for APDU communication. It uses AES-128 CBC encryption and HMAC-SHA1 message authentication, with session keys derived from a SECP256K1 ECDH exchange.

The secure channel is **currently optional** — all commands work without it. However, commands that transmit sensitive data (PIN, seed) should be wrapped in the secure channel.

**The channel is cleared on every applet deselect.** There is no resumption — each new session requires a full handshake.

---

### Handshake Flow

```
Host                                         Card
 │                                            │
 │  INS_EXPORT_AUTHENTIKEY                    │
 │ ─────────────────────────────────────────> │
 │ <─────────────────────────────────────────  │
 │  65-byte authentikey pubkey                │
 │                                            │
 │  Generate ephemeral SECP256K1 keypair      │
 │                                            │
 │  INS_INIT_SECURE_CHANNEL                   │
 │  [65-byte host ephemeral pubkey]           │
 │ ─────────────────────────────────────────> │
 │                                            │  Card generates ephemeral keypair
 │                                            │  ECDH: shared = card_ephemeral_priv × host_pub
 │                                            │  Derive session_key, mac_key from shared_X
 │ <─────────────────────────────────────────  │
 │  [coordX_size(2) | coordX(32)             │
 │   | sig1_size(2) | sig1(~72)              │
 │   | sig2_size(2) | sig2(~72)]             │
 │                                            │
 │  Reconstruct card ephemeral pubkey         │
 │  from coordX (try both Y parities)        │
 │  ECDH: shared = host_priv × card_ephemeral_pub
 │  Derive session_key, mac_key from shared_X │
 │                                            │
 │  Verify sig2 against authentikey           │
 │  (confirms response came from this card)   │
 │                                            │
 │  Channel is active.                        │
```

---

### Session Key Derivation

From the 32-byte ECDH shared X-coordinate:

```
session_key = HMAC-SHA1(key=shared_X, data="sc_key")[0:16]   // AES-128 key (16 bytes)
mac_key     = HMAC-SHA1(key=shared_X, data="sc_mac")[0:20]   // MAC key (20 bytes)
```

HMAC-SHA1 outputs 20 bytes. `session_key` uses the first 16 bytes only. `mac_key` uses all 20 bytes.

---

### Reconstructing the Ephemeral Public Key

The card returns only the 32-byte X-coordinate of its ephemeral public key. Reconstruct the full point by trying both Y parities:

```
for parity in [0x02, 0x03]:
    compressed = [parity] + coordX
    try:
        pubkey = decode_compressed_secp256k1(compressed)
        shared_X = ECDH(host_private_key, pubkey).x
        break   // use this shared_X
    except:
        continue
```

One of the two parities will always produce a valid point.

---

### Signature Verification

The handshake response includes two ECDSA-SHA256 signatures (DER-encoded, typically 70–72 bytes each):

**sig1 (self-signature):** Signs `[coordX_size(2) | coordX(32)]` with the card's ephemeral private key. Confirms the card generated the ephemeral key it returned.

**sig2 (authentikey cross-signature):** Signs `[coordX_size(2) | coordX(32) | sig1_size(2) | sig1]` with the persistent authentikey private key. **This is the important one** — it proves the response came from the card with the known authentikey identity.

To verify sig2:

```
message = response[0 : 2 + 32 + 2 + sig1_size]
verify_ecdsa_sha256(authentikey_pubkey, sig2, message)
```

---

### Wrapping Commands

Once the handshake is complete, wrap any command inside `INS_PROCESS_SECURE_CHANNEL (0x82)`:

**Building an encrypted command:**

```
1. Construct inner APDU plaintext:
   [CLA=0xB0] [INS] [P1] [P2] [Lc] [Data...]
   (If no data: Lc = 0x00, no Data bytes)

2. PKCS#7 pad to AES block size (16 bytes):
   pad_len = 16 - (len(plaintext) % 16)
   padded  = plaintext + bytes([pad_len] * pad_len)

3. Generate IV (16 bytes):
   iv[0:12]  = 12 random bytes
   iv[12:16] = 4-byte big-endian counter (must be strictly > card's last seen counter)
   iv[15]   |= 0x01   // last byte must be odd

4. Encrypt:
   encrypted = AES-128-CBC-encrypt(session_key, iv, padded)

5. Compute MAC:
   mac_input = iv(16) + uint16_BE(len(encrypted)) + encrypted
   mac = HMAC-SHA1(mac_key, mac_input)   // 20 bytes

6. Assemble payload:
   payload = iv(16) + uint16_BE(len(encrypted)) + encrypted + uint16_BE(20) + mac(20)

7. Send:
   CLA=0xB0  INS=0x82  P1=0x00  P2=0x00  Lc=len(payload)  Data=payload  Le=0x00
```

**IV counter rules:**

- The 4-byte counter at `iv[12:16]` must be strictly greater than the last counter the card accepted.
- Simplest approach: start at `1`, increment by `1` per command.
- `iv[15]` must be odd (bit 0 set). If the counter makes it even, OR with `0x01`.

**Decrypting the response:**

If the inner command produces output data, the card's response is encrypted:

```
[IV(16)] [data_size(2 BE)] [AES-CBC-ciphertext]
```

To decrypt:

```
1. iv         = response[0:16]
2. data_size  = uint16_BE(response[16:18])
3. ciphertext = response[18 : 18 + data_size]
4. padded     = AES-128-CBC-decrypt(session_key, iv, ciphertext)
5. plaintext  = padded[0 : len(padded) - padded[-1]]   // remove PKCS#7 pad
```

If the inner command produces no response data (e.g., `INS_VERIFY_PIN` on success), the outer response body is empty — check only the SW.

The card generates its own response IV. You do not need to track it — only your outgoing counter matters.

---

## Transaction Signing Flow

Complete wire-level sequence for signing a Solana transaction:

```
1.  SELECT applet  (AID: 53 6F 6C 61 6E 61 00)
2.  INS_GET_STATUS → check setup_done and is_seeded
3.  INS_EXPORT_AUTHENTIKEY → get card identity pubkey
4.  INS_INIT_SECURE_CHANNEL → ECDH handshake, derive session keys
5.  INS_VERIFY_PIN (wrapped in secure channel)
6.  INS_IMPORT_SEED (wrapped, first session only) → 64-byte BIP-39 seed
7.  Build Solana transaction, serialize the message bytes
8.  INS_SIGN_TX (wrapped or plain) with path m/44'/501'/0' and message bytes
    — single-chunk if message ≤ ~240 bytes (accounting for path prefix)
    — multi-chunk otherwise
9.  Receive 64-byte Ed25519 signature
10. Attach signature to transaction and broadcast
```

### Solana Address from Public Key

The card returns a raw 32-byte Ed25519 public key. The Solana address is the Base58 encoding of these 32 bytes:

```
address = base58_encode(pubkey_32_bytes)
```

### BIP-39 Seed Generation (host-side)

The host is responsible for converting a BIP-39 mnemonic to the 64-byte seed before calling `INS_IMPORT_SEED`:

```
seed = PBKDF2(
    hash       = HMAC-SHA512,
    password   = mnemonic words joined by spaces,
    salt       = "mnemonic" + optional_passphrase,
    iterations = 2048,
    dklen      = 64
)
```

---

## Status Word Reference

### Standard success / failure

| SW       | Name              | Meaning                                   |
| -------- | ----------------- | ----------------------------------------- |
| `0x9000` | OK                | Command succeeded                         |
| `0xFF00` | RESET_TO_FACTORY  | Factory reset complete (not `0x9000`)     |
| `0x63Cx` | PIN_FAILED        | Wrong PIN or PUK; `x` = retries remaining |
| `0x6D00` | INS_NOT_SUPPORTED | Unknown instruction code                  |
| `0x6E00` | CLA_NOT_SUPPORTED | CLA byte is not `0xB0`                    |
| `0x6A82` | APP_NOT_FOUND     | Applet AID not found (SELECT failed)      |

### Application status words

| SW       | Name                | Meaning                                             |
| -------- | ------------------- | --------------------------------------------------- |
| `0x9C03` | SETUP_ALREADY_DONE  | INS_SETUP called on an already-setup card           |
| `0x9C04` | SETUP_NOT_DONE      | Command requires setup; call INS_SETUP first        |
| `0x9C05` | UNSUPPORTED_FEATURE | Feature not available                               |
| `0x9C06` | UNAUTHORIZED        | PIN not verified in current session                 |
| `0x9C0C` | IDENTITY_BLOCKED    | PIN or PUK retry counter exhausted                  |
| `0x9C0F` | INVALID_PARAMETER   | Bad data format, length, or non-hardened path index |
| `0x9C14` | SEED_NOT_IMPORTED   | Command requires a seed; call INS_IMPORT_SEED first |
| `0x9C20` | NOT_IMPLEMENTED     | Placeholder — should not occur in released builds   |

### Secure channel status words

| SW       | Name             | Meaning                                                  |
| -------- | ---------------- | -------------------------------------------------------- |
| `0x9C21` | SC_UNINITIALIZED | INS_PROCESS_SECURE_CHANNEL before handshake              |
| `0x9C22` | SC_REQUIRED      | Command requires secure channel                          |
| `0x9C23` | SC_WRONG_MAC     | HMAC verification failed (tampered data or wrong key)    |
| `0x9C24` | SC_WRONG_IV      | IV counter not strictly increasing, or last byte not odd |

### Diagnostic status words

These are produced by the card's internal error handlers when a `0x6F00` (unexpected exception) would otherwise occur. They should not appear in normal operation — treat them as bugs.

| SW range | Meaning                                                        |
| -------- | -------------------------------------------------------------- |
| `0x9C5x` | CryptoException during decryption (`x` = JavaCard reason code) |
| `0x9C60` | ArrayIndexOutOfBoundsException during decryption               |
| `0x9C61` | NullPointerException during decryption                         |
| `0x9C6F` | Other exception during decryption                              |
| `0x9C7x` | CryptoException during command dispatch                        |
| `0x9C80` | ArrayIndexOutOfBoundsException during dispatch                 |
| `0x9C81` | NullPointerException during dispatch                           |
| `0x9C8F` | Other exception during dispatch                                |

---

## Quick Reference

```
AID:  53 6F 6C 61 6E 61 00   ("Solana\x00")
CLA:  0xB0

INS_SETUP                   0x2A   Set PIN + PUK (once only)
INS_GET_STATUS              0x3C   Read card state (12 bytes)
INS_CARD_LABEL              0x3D   Get/set label  (P1: 0=get, 1=set)
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
```
