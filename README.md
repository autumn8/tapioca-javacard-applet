# TapiocaApplet

A JavaCard applet that turns an NXP JCOP 4 smart card into a Solana hardware wallet. The card stores a BIP-39 seed, derives Ed25519 keys via SLIP-0010, and signs Solana transactions entirely on-card — private keys never leave the chip.

Target hardware: **J3R180** (JCOP 4, ~180 KB EEPROM). Production target: **J3R452** (JCOP 4.5, ~452 KB EEPROM).

---

## Features

- **Ed25519 signing** — software Ed25519 via JCMathLib + JCEd25519 (Phase 1); native NXP Ed25519 (Phase 2)
- **SLIP-0010 HD derivation** — hardened-only paths, standard Solana BIP-44 path `m/44'/501'/account'`
- **PIN + PUK access control** — 5 PIN tries, 3 PUK tries; session authentication
- **Secure channel** — AES-128 CBC + HMAC-SHA1 encrypted APDU communication
- **Multi-chunk transaction streaming** — standard 255-byte APDUs, iOS NFC compatible
- **Card label** — user-defined UTF-8 identifier (up to 64 bytes)
- **Factory reset** — secure wipe of all keys and state

---

## Hardware

| Property        | J3R180 (Phase 1)                         | J3R452 (Phase 2)             |
| --------------- | ---------------------------------------- | ---------------------------- |
| Platform        | NXP JCOP 4                               | NXP JCOP 4.5                 |
| JavaCard spec   | 3.0.5                                    | 3.0.5 + NXP extensions       |
| EEPROM          | ~180 KB (~85 KB user)                    | ~452 KB                      |
| RAM (transient) | ~8 KB                                    | ~16 KB                       |
| Interface       | ISO 7816 + ISO 14443-4 (NFC)             | ISO 7816 + ISO 14443-4 (NFC) |
| Ed25519         | Software (JCMathLib) — confirmed working | Native NXP — pending SDK     |
| Keygen time     | ~2,700 ms                                | < 1 s (estimated)            |
| Sign time       | ~1,440 ms                                | < 1 s (estimated)            |

---

## Repository Structure

```
tapioca-javacard-applet/
├── src/org/tapioca/applet/
│   ├── TapiocaApplet.java       Main applet — APDU dispatch, PIN, lifecycle
│   ├── Slip10.java              SLIP-0010 Ed25519 HD key derivation
│   ├── SolanaTransaction.java   EEPROM accumulator for multi-chunk signing
│   ├── Ed25519Signer.java       Ed25519 abstraction (JCMathLib → native swap point)
│   ├── SecureChannel.java       AES-128 CBC + HMAC-SHA1 secure channel
│   ├── HmacSha512.java          HMAC-SHA512 for SLIP-0010 derivation
│   ├── HmacSha160.java          HMAC-SHA1 for secure channel MAC
│   └── Secp256k1.java           secp256k1 params for authentikey / ECDH
├── test/
│   ├── milestones/
│   │   ├── test_milestone11.py  PIN, setup, factory reset tests (48 tests)
│   │   ├── test_milestone12.py  SLIP-0010 derivation + pubkey tests (14 tests)
│   │   ├── test_milestone13.py  INS_SIGN_TX + signature verification tests (8 tests)
│   │   ├── test_phase3_sc.py    Secure channel full protocol tests (12 tests)
│   │   └── requirements.txt     Python test dependencies
│   └── e2e/                     TypeScript card test CLI (Node.js + pcsclite)
├── sdks/jc305u3_kit/            JavaCard 3.0.5 SDK (bundled)
├── lib/
│   ├── ant-javacard.jar         ant-javacard build plugin
│   └── jced25519/               JCEd25519 + JCMathLib (cloned by setup.sh)
├── build.xml                    Ant build — patch, compile, convert
├── setup.sh                     One-time setup — clones JCEd25519
├── gp.jar                       GlobalPlatformPro — card install / delete tool
├── gp.exe                       GlobalPlatformPro (Windows binary)
├── PLAN.md                      Full design and implementation plan
├── PROTOCOL.md                  Complete APDU protocol reference
└── REACT_NATIVE_INTEGRATION.md  React Native NFC integration guide
```

---

## Quick Start

### Prerequisites

- **JDK 11** — required by the JavaCard converter toolchain. JDK 17+ breaks the build.

  ```sh
  export JAVA_HOME=/opt/homebrew/opt/openjdk@11   # macOS Homebrew
  ```

- **Apache Ant**

  ```sh
  brew install ant   # macOS
  ```

### 1. Clone and set up dependencies

```sh
git clone <repo-url> solana-applet
cd solana-applet
bash setup.sh
```

`setup.sh` clones [JCEd25519](https://github.com/dufkan/JCEd25519) (includes JCMathLib) into `lib/jced25519/`.

### 2. Build

```sh
JAVA_HOME=/opt/homebrew/opt/openjdk@11 ant
```

Output: `TapiocaApplet-0.1.cap`

```sh
ant clean   # remove build artifacts
ant info    # verify prerequisites without building
```

### 3. Install onto card

Connect the card via a PC/SC reader (or USB smart card reader), then:

```sh
java -jar gp.jar --install TapiocaApplet-0.1.cap
```

To delete a previously installed version first:

```sh
java -jar gp.jar --delete 536F6C616E61
java -jar gp.jar --install TapiocaApplet-0.1.cap
```

The applet AID is `536F6C616E6100` ("Solana\x00" in ASCII).

---

## Running Tests

### Milestone Tests

Tests use Python + pcsclite (PC/SC reader required). Set up a virtual environment:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r test/milestones/requirements.txt
```

Run each milestone suite in order:

```sh
python test/milestones/test_milestone11.py   # PIN management, setup, factory reset
python test/milestones/test_milestone12.py   # SLIP-0010 key derivation, public keys
python test/milestones/test_milestone13.py   # Transaction signing, Ed25519 verification
python test/milestones/test_phase3_sc.py     # Secure channel protocol
```

All suites target the first PC/SC reader found. Connect the card before running.

---

### CLI End to End Tests

The `test/e2e/` directory contains TypeScript tools for real-card interaction via a PC/SC reader. Requires Node.js 18+ and `pcsclite`:

```sh
brew install pcsc-lite   # macOS
cd test/e2e && npm install
```

**Provision a fresh card** — builds the applet, reinstalls it, sets up PIN/PUK, imports a generated (or provided) seed, and writes `card-info.json`:

```sh
npm run setup-fresh-card                          # generate new 24-word mnemonic
npm run setup-fresh-card -- --pin 5678 --puk 9999
npm run setup-fresh-card -- "word1 word2 ..." --pin 5678
```

`card-info.json` (gitignored) contains the mnemonic, derived Solana address, PIN, and PUK in plaintext — devnet/testing use only.

**Sign a real devnet transaction** — airdrops SOL if needed, builds a transfer, streams it to the card for signing, and broadcasts it:

```sh
npm start "<12-or-24-word bip39 mnemonic>"
npm start "<mnemonic>" -- --pin 5678
```

See [test/e2e/README.md](test/e2e/README.md) for full details.

---

## APDU Protocol Reference

### CLA byte: `0xB0`

### Command Catalog

| Command                      | INS    | Auth required | Description                           |
| ---------------------------- | ------ | ------------- | ------------------------------------- |
| `INS_SETUP`                  | `0x2A` | No            | Initialize card — set PIN/PUK         |
| `INS_GET_STATUS`             | `0x3C` | No            | Card version, PIN state, seed status  |
| `INS_CARD_LABEL`             | `0x3D` | PIN (write)   | Get or set UTF-8 card label           |
| `INS_VERIFY_PIN`             | `0x42` | No            | Authenticate; unlocks session         |
| `INS_CHANGE_PIN`             | `0x44` | PIN           | Replace PIN                           |
| `INS_UNBLOCK_PIN`            | `0x46` | No            | Reset PIN using PUK                   |
| `INS_IMPORT_SEED`            | `0x6C` | PIN           | Store 64-byte BIP-39 seed             |
| `INS_RESET_SEED`             | `0x77` | PIN           | Wipe seed, keep PIN state             |
| `INS_GET_PUBLIC_KEY`         | `0x6D` | PIN           | Derive Ed25519 pubkey at path         |
| `INS_SIGN_TX`                | `0x6F` | PIN           | Stream + sign Solana transaction      |
| `INS_EXPORT_AUTHENTIKEY`     | `0x73` | No            | Export 65-byte secp256k1 identity key |
| `INS_INIT_SECURE_CHANNEL`    | `0x81` | No            | ECDH handshake for secure channel     |
| `INS_PROCESS_SECURE_CHANNEL` | `0x82` | No            | Encrypted command envelope            |
| `INS_RESET_TO_FACTORY`       | `0xFF` | PIN           | Wipe everything                       |

### INS_SIGN_TX chunking

`INS_SIGN_TX` always signs with the key derived at `m/44'/501'/0'` during `INS_IMPORT_SEED` — no derivation path is sent in the APDU. Solana messages can be up to ~1168 bytes; P1 flags stream them:

| P1     | Meaning                                                          |
| ------ | ---------------------------------------------------------------- |
| `0x01` | First chunk — resets the accumulator; data is message bytes only |
| `0x00` | Continuation chunk                                               |
| `0x80` | Last chunk — response is signature + pubkey                      |
| `0x81` | First AND last (single-chunk message)                            |

Chunk data format (all chunks):

```
[message bytes ...]
```

Response (last chunk only): 96 bytes — `[signature (64)] [public key (32)]`. The returned pubkey lets clients verify the signature without a separate `INS_GET_PUBLIC_KEY` call.

Signing is fixed to the default Solana path; `INS_GET_PUBLIC_KEY` can still derive other paths for read-only use but the card always restores the default signing key afterward.

### Key status words

| SW       | Meaning                              |
| -------- | ------------------------------------ |
| `0x9000` | Success                              |
| `0x63Cx` | PIN/PUK failed — x = tries remaining |
| `0x9C04` | Setup not done                       |
| `0x9C06` | Unauthorized (PIN not verified)      |
| `0x9C0C` | Card blocked (PIN exhausted)         |
| `0x9C0F` | Invalid parameter                    |
| `0x9C14` | Seed not imported                    |
| `0x9C21` | Secure channel not initialized       |
| `0x9C23` | Secure channel wrong MAC             |
| `0xFF00` | Factory reset complete               |

---

## Secure Channel

The applet implements AES-128 CBC + HMAC-SHA1 encrypted communication, compatible with the Satochip secure channel protocol.

**Handshake flow:**

1. `INS_EXPORT_AUTHENTIKEY` — get card's persistent secp256k1 identity pubkey
2. `INS_INIT_SECURE_CHANNEL` — send host ephemeral pubkey; receive card ephemeral pubkey + two ECDSA signatures
3. Verify both signatures; derive session keys from ECDH shared secret
4. Wrap all subsequent commands with `INS_PROCESS_SECURE_CHANNEL`

Session keys (derived via HMAC-SHA1 from ECDH shared secret):

- `sc_enc` — 16-byte AES-128 key (CBC encryption)
- `sc_mac` — 20-byte HMAC-SHA1 key (MAC)
- `sc_iv` — 16-byte IV (incremented per command)

See [PROTOCOL.md](PROTOCOL.md) for the complete wire-level protocol reference.

---

## Implementation Phases

| Phase     | Status   | Description                                          |
| --------- | -------- | ---------------------------------------------------- |
| Phase 1.1 | Complete | PIN, setup, factory reset, GET_STATUS, card label    |
| Phase 1.2 | Complete | Seed import, SLIP-0010 derivation, public key export |
| Phase 1.3 | Complete | INS_SIGN_TX — multi-chunk Ed25519 signing            |
| Phase 3   | Complete | Secure channel — AES-128 CBC + HMAC-SHA1             |

---

## Known Limitations

- **Not constant-time**: JCEd25519's software Ed25519 is vulnerable to timing side-channels. Acceptable for development and use cases without physical attacker access. Phase 2 (J3R452 native Ed25519) is constant-time.
- **Blind signing**: The card has no display and cannot verify transaction contents. The host app is responsible for showing what the user is signing.
- **No physical confirmation**: No button on the card — PIN verification is the sole authorization gate.
- **J3R180 only**: The card must be used alone. A second applet sharing the card's TRANSIENT_RESET RAM pool can exhaust the shared pool and cause `0x6F00` errors.

---

## Dependencies

| Dependency                                                                               | Source                   | License |
| ---------------------------------------------------------------------------------------- | ------------------------ | ------- |
| [JCEd25519](https://github.com/dufkan/JCEd25519)                                         | Cloned by `setup.sh`     | MIT     |
| [JCMathLib](https://github.com/OpenCryptoProject/JCMathLib)                              | Bundled inside JCEd25519 | MIT     |
| [ant-javacard](https://github.com/martinpaljak/ant-javacard)                             | `lib/ant-javacard.jar`   | MIT     |
| [oracle_javacard_sdks jc305u3_kit](https://github.com/martinpaljak/oracle_javacard_sdks) | `sdks/jc305u3_kit/`      | Oracle  |
| [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro)                   | `gp.jar`                 | LGPL    |

---

## License

GNU AGPL v3
