#!/usr/bin/env python3
"""
TapiocaApplet Milestone 1.2 — SLIP-0010 key derivation test.

Verifies:
  - INS_IMPORT_SEED derives and stores master key
  - INS_GET_PUBLIC_KEY returns correct Ed25519 pubkey at given path
  - Derived address at m/44'/501'/0' matches a known-good reference

Known-good vector: SLIP-0010 spec test vector #1
  Seed (hex): 000102030405060708090a0b0c0d0e0f
  m:         key = 2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7
             cc  = 90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb
  m/0':      key = 68e0fe46dfb67e368c55a09d5bc6f6e2d6b6db62fb4d9a3d1a03dc528ee89f7d
  m/0'/1':   key = b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2

Note: INS_IMPORT_SEED takes a 64-byte BIP-39 seed (PBKDF2-HMAC-SHA512 output).
For SLIP-0010 test vectors the seed IS the 16-byte value above, padded to 64 bytes
with zeros (or just use the 16-byte seed as-is for testing deriveMaster).
We derive the pubkey from known SLIP-0010 private key scalars using PyNaCl to
produce a reference value to compare against card output.

Dependencies: pyscard, PyNaCl
  python3 -m venv .venv && source .venv/bin/activate
  pip install pyscard pynacl
"""

import sys
import time

try:
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes
except ImportError:
    print("ERROR: pyscard not installed. Run: pip install pyscard")
    sys.exit(1)

try:
    import nacl.signing
    import nacl.encoding
    NACL_AVAILABLE = True
except ImportError:
    print("WARNING: PyNaCl not installed — pubkey cross-checks skipped.")
    NACL_AVAILABLE = False

import hashlib
import hmac
import struct

# ── Card constants ────────────────────────────────────────────────────────────
CLA = 0xB0
INS_SETUP            = 0x2A
INS_GET_STATUS       = 0x3C
INS_VERIFY_PIN       = 0x42
INS_RESET_TO_FACTORY = 0xFF
INS_IMPORT_SEED      = 0x6C
INS_RESET_SEED       = 0x77
INS_GET_PUBLIC_KEY   = 0x6D

SW_OK                  = 0x9000
SW_SETUP_NOT_DONE      = 0x9C04
SW_UNAUTHORIZED        = 0x9C06
SW_SEED_NOT_IMPORTED   = 0x9C14
SW_INVALID_PARAMETER   = 0x9C0F
SW_RESET_TO_FACTORY    = 0xFF00

APPLET_AID = toBytes("536F6C616E6100")
DEFAULT_PIN = [0x31, 0x32, 0x33, 0x34]          # "1234"
DEFAULT_PUK = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46]

PASS = 0
FAIL = 0

# ── APDU helpers ──────────────────────────────────────────────────────────────
def sw(r):   return (r[-2] << 8) | r[-1]
def data(r): return bytes(r[:-2])

def result(name, ok, detail=""):
    global PASS, FAIL
    s = "PASS" if ok else "FAIL"
    line = f"  [{s}] {name}"
    if detail: line += f"  ({detail})"
    print(line)
    if ok: PASS += 1
    else:  FAIL += 1
    return ok

def _apdu(conn, ins, p1, p2, payload=None):
    if payload:
        apdu = [CLA, ins, p1, p2, len(payload)] + list(payload) + [0x00]
    else:
        apdu = [CLA, ins, p1, p2, 0x00]
    resp, sw1, sw2 = conn.transmit(apdu)
    return resp + [sw1, sw2]

def select(conn):
    apdu = [0x00, 0xA4, 0x04, 0x00, len(APPLET_AID)] + list(APPLET_AID)
    resp, sw1, sw2 = conn.transmit(apdu)
    return [sw1, sw2]

def setup(conn, pin, puk):
    payload = bytes([len(pin)] + list(pin) + [len(puk)] + list(puk))
    return _apdu(conn, INS_SETUP, 0x00, 0x00, payload)

def verify_pin(conn, pin):
    return _apdu(conn, INS_VERIFY_PIN, 0x00, 0x00, bytes(pin))

def import_seed(conn, seed):
    return _apdu(conn, INS_IMPORT_SEED, 0x00, 0x00, seed)

def reset_seed(conn):
    return _apdu(conn, INS_RESET_SEED, 0x00, 0x00)

def get_public_key(conn, path_indexes):
    """path_indexes: list of ints, each must be >= 0x80000000 (hardened)."""
    depth = len(path_indexes)
    payload = bytes([depth])
    for idx in path_indexes:
        payload += struct.pack(">I", idx)
    return _apdu(conn, INS_GET_PUBLIC_KEY, 0x00, 0x00, payload)

def reset_to_factory(conn):
    return _apdu(conn, INS_RESET_TO_FACTORY, 0x00, 0x00)

# ── SLIP-0010 reference implementation ───────────────────────────────────────
def slip10_master(seed: bytes):
    h = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    return h[:32], h[32:]   # (IL, IR) = (private_key, chain_code)

def slip10_child(parent_key: bytes, parent_chain: bytes, index: int):
    assert index >= 0x80000000, "Ed25519 SLIP-0010 requires hardened indexes"
    data = b"\x00" + parent_key + struct.pack(">I", index)
    h = hmac.new(parent_chain, data, hashlib.sha512).digest()
    return h[:32], h[32:]

def slip10_derive(seed: bytes, path: list):
    key, chain = slip10_master(seed)
    for idx in path:
        key, chain = slip10_child(key, chain, idx)
    return key, chain

def ed25519_pubkey_from_scalar(scalar32: bytes) -> bytes:
    """Compute Ed25519 pubkey from SLIP-0010 private key scalar (32 bytes)."""
    if not NACL_AVAILABLE:
        return None
    # PyNaCl SigningKey takes the 32-byte seed directly (it does the expansion)
    sk = nacl.signing.SigningKey(scalar32)
    return bytes(sk.verify_key)

# ── Test data ─────────────────────────────────────────────────────────────────
# SLIP-0010 spec test vector 1: seed = 000102...0f (16 bytes), padded to 64
SLIP10_SEED_16  = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
SLIP10_SEED_64  = SLIP10_SEED_16.ljust(64, b'\x00')   # padded with zeros for 64-byte import

# Expected master key from SLIP-0010 spec (Ed25519 chain, Test Vector 1):
EXPECTED_MASTER_KEY = bytes.fromhex(
    "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7")
EXPECTED_MASTER_CC  = bytes.fromhex(
    "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb")

# Standard Solana BIP-44 path
SOLANA_PATH = [0x8000002C, 0x800001F5, 0x80000000]  # m/44'/501'/0'

# ── Tests ─────────────────────────────────────────────────────────────────────

def do_setup_and_verify(conn):
    select(conn)
    r = setup(conn, DEFAULT_PIN, DEFAULT_PUK)
    assert sw(r) == SW_OK, f"setup failed: {sw(r):04X}"
    r = verify_pin(conn, DEFAULT_PIN)
    assert sw(r) == SW_OK, f"pin verify failed: {sw(r):04X}"

def do_factory_reset(conn):
    r = verify_pin(conn, DEFAULT_PIN)
    assert sw(r) == SW_OK
    r = reset_to_factory(conn)
    assert sw(r) == SW_RESET_TO_FACTORY

def verify_reference_vectors():
    """Confirm our Python SLIP-0010 master derivation matches the spec test vector."""
    print("[ref] Verifying Python SLIP-0010 reference vectors ...")
    key, cc = slip10_master(SLIP10_SEED_16)
    assert key == EXPECTED_MASTER_KEY, f"master key mismatch: {key.hex()}"
    assert cc  == EXPECTED_MASTER_CC,  f"master cc mismatch:  {cc.hex()}"
    # Child derivation is verified by cross-checking card output against this Python
    # implementation rather than against a separate hardcoded expected value.
    print("  [ref] Master key derivation correct.\n")

def test_import_seed_requires_pin(conn):
    print("\n[1] INS_IMPORT_SEED requires PIN")
    do_setup_and_verify(conn)
    select(conn)  # deselects PIN
    r = import_seed(conn, SLIP10_SEED_64)
    result("import without PIN → SW_UNAUTHORIZED", sw(r) == SW_UNAUTHORIZED,
           f"got {sw(r):04X}")

def test_import_seed_length_check(conn):
    print("\n[2] INS_IMPORT_SEED rejects wrong seed length")
    verify_pin(conn, DEFAULT_PIN)
    r = import_seed(conn, b'\x00' * 32)  # 32 bytes instead of 64
    result("32-byte seed rejected → SW_INVALID_PARAMETER", sw(r) == SW_INVALID_PARAMETER)

def test_import_seed_success(conn):
    print("\n[3] INS_IMPORT_SEED — SLIP-0010 test vector")
    verify_pin(conn, DEFAULT_PIN)

    t0 = time.time()
    r = import_seed(conn, SLIP10_SEED_64)
    elapsed = time.time() - t0

    result(f"import succeeds (SW 9000)  [{elapsed:.1f}s]", sw(r) == SW_OK)

    if sw(r) == SW_OK:
        card_pubkey = data(r)
        result("response length == 32", len(card_pubkey) == 32,
               f"got {len(card_pubkey)}")

        # The card derives m/44'/501'/0' internally during importSeed
        # and returns that pubkey. Compute reference pubkey.
        ref_key, _ = slip10_derive(SLIP10_SEED_64, SOLANA_PATH)
        ref_pubkey = ed25519_pubkey_from_scalar(ref_key)

        if ref_pubkey is not None:
            match = card_pubkey == ref_pubkey
            result("pubkey matches m/44'/501'/0' reference",
                   match,
                   f"\n      card: {card_pubkey.hex()}\n      ref:  {ref_pubkey.hex()}")
        else:
            print("    [SKIP] PyNaCl not available — skipping pubkey cross-check")

def test_get_public_key(conn):
    print("\n[4] INS_GET_PUBLIC_KEY — various paths")
    verify_pin(conn, DEFAULT_PIN)

    # Test paths and compare to reference implementation
    paths = [
        ([],                      "m (master)"),
        ([0x80000000],            "m/0'"),
        (SOLANA_PATH,             "m/44'/501'/0'"),
    ]

    for path_indexes, path_str in paths:
        ref_key, _ = slip10_derive(SLIP10_SEED_64, path_indexes)
        ref_pubkey = ed25519_pubkey_from_scalar(ref_key)

        t0 = time.time()
        r = get_public_key(conn, path_indexes)
        elapsed = time.time() - t0

        ok_sw = sw(r) == SW_OK
        result(f"{path_str}: SW 9000  [{elapsed:.1f}s]", ok_sw)

        if ok_sw and ref_pubkey is not None:
            card_pubkey = data(r)
            match = card_pubkey == ref_pubkey
            result(f"{path_str}: pubkey matches reference",
                   match,
                   f"\n      card: {card_pubkey.hex()}\n      ref:  {ref_pubkey.hex()}")

def test_seed_not_imported_guard(conn):
    print("\n[5] INS_GET_PUBLIC_KEY blocked without seed")
    do_factory_reset(conn)
    select(conn)
    r = setup(conn, DEFAULT_PIN, DEFAULT_PUK)
    assert sw(r) == SW_OK
    verify_pin(conn, DEFAULT_PIN)

    r = get_public_key(conn, SOLANA_PATH)
    result("GET_PUBLIC_KEY without seed → SW_SEED_NOT_IMPORTED", sw(r) == SW_SEED_NOT_IMPORTED)

def test_reset_seed(conn):
    print("\n[6] INS_RESET_SEED")
    # Re-import seed first
    verify_pin(conn, DEFAULT_PIN)
    r = import_seed(conn, SLIP10_SEED_64)
    assert sw(r) == SW_OK

    r = reset_seed(conn)
    result("reset_seed succeeds (SW 9000)", sw(r) == SW_OK)

    r = get_public_key(conn, SOLANA_PATH)
    result("GET_PUBLIC_KEY after reset → SW_SEED_NOT_IMPORTED", sw(r) == SW_SEED_NOT_IMPORTED)

    # Cleanup
    do_factory_reset(conn)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    verify_reference_vectors()

    rs = readers()
    if not rs:
        print("ERROR: No smart card readers found.")
        sys.exit(1)
    print(f"Using reader: {rs[0]}\n")
    conn = rs[0].createConnection()
    conn.connect()

    r = select(conn)
    if sw(r) != SW_OK:
        print(f"ERROR: SELECT failed SW={sw(r):04X}")
        print("       Is TapiocaApplet-0.1.cap installed?")
        sys.exit(1)

    # Pre-flight: ensure clean state
    from smartcard.util import toHexString
    print(f"TapiocaApplet selected (AID: {toHexString(APPLET_AID)})")
    status_r = _apdu(conn, INS_GET_STATUS, 0x00, 0x00)
    status = data(status_r)
    if status[10] == 0x01:
        print("Card already set up — resetting...")
        verify_pin(conn, DEFAULT_PIN)
        r = reset_to_factory(conn)
        assert sw(r) == SW_RESET_TO_FACTORY
        select(conn)

    test_import_seed_requires_pin(conn)
    test_import_seed_length_check(conn)
    test_import_seed_success(conn)
    test_get_public_key(conn)
    test_seed_not_imported_guard(conn)
    test_reset_seed(conn)

    total = PASS + FAIL
    print(f"\n{'='*50}")
    print(f"Results: {PASS}/{total} passed", end="")
    if FAIL:
        print(f"  ({FAIL} FAILED)")
    else:
        print("  — ALL PASS")
    print('='*50)
    sys.exit(0 if FAIL == 0 else 1)

if __name__ == "__main__":
    main()
