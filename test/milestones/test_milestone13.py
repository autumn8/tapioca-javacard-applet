#!/usr/bin/env python3
"""
TapiocaApplet Milestone 1.3 — INS_SIGN_TX test suite.

Tests:
  1. PIN guard — signing without PIN returns SW_UNAUTHORIZED
  2. Seed guard — signing without seed returns SW_SEED_NOT_IMPORTED
  3. Single-chunk sign (P1=0x81) — short message, verify signature with PyNaCl
  4. Multi-chunk sign — message split across 3 APDUs, verify signature
  5. Max-size message — 1168-byte message split across 6 chunks
  6. Continuation-without-first guard — stale continuation returns SW_INVALID_PARAMETER
  7. Invalid path (non-hardened index) — returns SW_INVALID_PARAMETER

Dependencies: pyscard, PyNaCl
  python3 -m venv .venv && source .venv/bin/activate
  pip install pyscard pynacl
"""

import sys
import time
import struct
import hashlib
import hmac

try:
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes
except ImportError:
    print("ERROR: pyscard not installed.  pip install pyscard")
    sys.exit(1)

try:
    import nacl.signing
    import nacl.encoding
    NACL_AVAILABLE = True
except ImportError:
    print("WARNING: PyNaCl not installed — signature verification skipped.  pip install pynacl")
    NACL_AVAILABLE = False

# ── Card constants ────────────────────────────────────────────────────────────
CLA = 0xB0
INS_SETUP            = 0x2A
INS_GET_STATUS       = 0x3C
INS_VERIFY_PIN       = 0x42
INS_RESET_TO_FACTORY = 0xFF
INS_IMPORT_SEED      = 0x6C
INS_RESET_SEED       = 0x77
INS_GET_PUBLIC_KEY   = 0x6D
INS_SIGN_TX          = 0x6F

# INS_SIGN_TX P1 flags
P1_FIRST        = 0x01
P1_LAST         = 0x80
P1_FIRST_LAST   = 0x81   # single-chunk: first + last
P1_CONTINUATION = 0x00

SW_OK                  = 0x9000
SW_SETUP_NOT_DONE      = 0x9C04
SW_UNAUTHORIZED        = 0x9C06
SW_SEED_NOT_IMPORTED   = 0x9C14
SW_INVALID_PARAMETER   = 0x9C0F
SW_RESET_TO_FACTORY    = 0xFF00

APPLET_AID  = toBytes("536F6C616E6100")
DEFAULT_PIN = [0x31, 0x32, 0x33, 0x34]
DEFAULT_PUK = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46]

# SLIP-0010 test seed (16-byte vector, padded to 64 for import)
SLIP10_SEED_16 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
SLIP10_SEED_64 = SLIP10_SEED_16.ljust(64, b'\x00')

SOLANA_PATH = [0x8000002C, 0x800001F5, 0x80000000]  # m/44'/501'/0'

PASS = 0
FAIL = 0

# ── APDU helpers ──────────────────────────────────────────────────────────────
def sw_val(r):   return (r[-2] << 8) | r[-1]
def resp_data(r): return bytes(r[:-2])

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

def reset_to_factory(conn):
    return _apdu(conn, INS_RESET_TO_FACTORY, 0x00, 0x00)

def get_status(conn):
    return _apdu(conn, INS_GET_STATUS, 0x00, 0x00)

# ── SLIP-0010 reference ───────────────────────────────────────────────────────
def slip10_master(seed: bytes):
    h = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    return h[:32], h[32:]

def slip10_child(parent_key: bytes, parent_chain: bytes, index: int):
    data = b"\x00" + parent_key + struct.pack(">I", index)
    h = hmac.new(parent_chain, data, hashlib.sha512).digest()
    return h[:32], h[32:]

def slip10_derive(seed: bytes, path: list):
    key, chain = slip10_master(seed)
    for idx in path:
        key, chain = slip10_child(key, chain, idx)
    return key, chain

def ed25519_pubkey(scalar32: bytes) -> bytes | None:
    if not NACL_AVAILABLE:
        return None
    return bytes(nacl.signing.SigningKey(scalar32).verify_key)

def ed25519_verify(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    if not NACL_AVAILABLE:
        return None
    try:
        nacl.signing.VerifyKey(pubkey).verify(message, signature)
        return True
    except Exception:
        return False

# ── INS_SIGN_TX helpers ───────────────────────────────────────────────────────

def _build_first_chunk_payload(path_indexes: list, message_bytes: bytes, max_data: int = 240) -> tuple:
    """
    Return (first_payload, remaining_message).
    The first payload contains [depth][path...][message_start...] up to max_data bytes.
    """
    depth = len(path_indexes)
    path_bytes = bytes([depth])
    for idx in path_indexes:
        path_bytes += struct.pack(">I", idx)
    header_len = len(path_bytes)  # 1 + depth*4
    msg_capacity = max_data - header_len
    first_msg = message_bytes[:msg_capacity]
    rest_msg  = message_bytes[msg_capacity:]
    return path_bytes + first_msg, rest_msg

def sign_tx(conn, path_indexes: list, message: bytes, chunk_size: int = 200) -> bytes:
    """
    Stream message to INS_SIGN_TX across as many APDUs as needed.
    Returns the 64-byte signature bytes.
    """
    # Compute max message bytes in first chunk (path header uses 1 + depth*4 bytes)
    depth = len(path_indexes)
    path_overhead = 1 + depth * 4
    first_capacity = chunk_size - path_overhead

    # Split message
    first_msg   = message[:first_capacity]
    remaining   = message[first_capacity:]

    # Build and send chunks
    chunks = []
    # Remaining broken into chunk_size pieces
    for i in range(0, len(remaining), chunk_size):
        chunks.append(remaining[i:i+chunk_size])

    path_bytes = bytes([depth])
    for idx in path_indexes:
        path_bytes += struct.pack(">I", idx)

    if not chunks:
        # Single chunk: first + last
        payload = path_bytes + first_msg
        r = _apdu(conn, INS_SIGN_TX, P1_FIRST_LAST, 0x00, payload)
        assert sw_val(r) == SW_OK, f"single-chunk sign failed: {sw_val(r):04X}"
        sig = resp_data(r)
        assert len(sig) == 64, f"expected 64-byte sig, got {len(sig)}"
        return sig
    else:
        # First chunk (not last)
        payload = path_bytes + first_msg
        r = _apdu(conn, INS_SIGN_TX, P1_FIRST, 0x00, payload)
        assert sw_val(r) == SW_OK, f"first chunk failed: {sw_val(r):04X}"

        # Middle chunks
        for chunk in chunks[:-1]:
            r = _apdu(conn, INS_SIGN_TX, P1_CONTINUATION, 0x00, chunk)
            assert sw_val(r) == SW_OK, f"continuation chunk failed: {sw_val(r):04X}"

        # Last chunk
        r = _apdu(conn, INS_SIGN_TX, P1_LAST, 0x00, chunks[-1])
        assert sw_val(r) == SW_OK, f"last chunk failed: {sw_val(r):04X}"
        sig = resp_data(r)
        assert len(sig) == 64, f"expected 64-byte sig, got {len(sig)}"
        return sig

# ── Setup helpers ─────────────────────────────────────────────────────────────

def do_setup_and_seed(conn):
    """Fresh setup + PIN verify + seed import. Returns (pubkey bytes)."""
    select(conn)
    r = setup(conn, DEFAULT_PIN, DEFAULT_PUK)
    assert sw_val(r) == SW_OK, f"setup failed {sw_val(r):04X}"
    r = verify_pin(conn, DEFAULT_PIN)
    assert sw_val(r) == SW_OK
    r = import_seed(conn, SLIP10_SEED_64)
    assert sw_val(r) == SW_OK, f"import_seed failed {sw_val(r):04X}"
    return resp_data(r)   # 32-byte pubkey at m/44'/501'/0'

def do_factory_reset(conn):
    verify_pin(conn, DEFAULT_PIN)
    r = reset_to_factory(conn)
    assert sw_val(r) == SW_RESET_TO_FACTORY

# ── Tests ─────────────────────────────────────────────────────────────────────

def test_pin_guard(conn):
    print("\n[1] INS_SIGN_TX requires PIN")
    do_setup_and_seed(conn)
    select(conn)     # drops PIN validation
    msg = b"test message for sign"
    payload = bytes([len(SOLANA_PATH)])
    for idx in SOLANA_PATH:
        payload += struct.pack(">I", idx)
    payload += msg
    r = _apdu(conn, INS_SIGN_TX, P1_FIRST_LAST, 0x00, payload)
    result("sign without PIN → SW_UNAUTHORIZED", sw_val(r) == SW_UNAUTHORIZED,
           f"got {sw_val(r):04X}")

def test_seed_guard(conn):
    print("\n[2] INS_SIGN_TX requires seed")
    do_factory_reset(conn)
    select(conn)
    r = setup(conn, DEFAULT_PIN, DEFAULT_PUK)
    assert sw_val(r) == SW_OK
    verify_pin(conn, DEFAULT_PIN)
    # No seed imported
    msg = b"test message"
    payload = bytes([len(SOLANA_PATH)])
    for idx in SOLANA_PATH:
        payload += struct.pack(">I", idx)
    payload += msg
    r = _apdu(conn, INS_SIGN_TX, P1_FIRST_LAST, 0x00, payload)
    result("sign without seed → SW_SEED_NOT_IMPORTED", sw_val(r) == SW_SEED_NOT_IMPORTED,
           f"got {sw_val(r):04X}")

def test_single_chunk_sign(conn):
    print("\n[3] Single-chunk sign (P1=0x81)")
    do_factory_reset(conn)
    pubkey = do_setup_and_seed(conn)
    verify_pin(conn, DEFAULT_PIN)

    # Use a simple test message
    message = b"Hello Solana"

    t0 = time.time()
    sig = sign_tx(conn, SOLANA_PATH, message, chunk_size=200)
    elapsed = time.time() - t0

    result(f"single-chunk sign returns 64 bytes  [{elapsed:.1f}s]", len(sig) == 64,
           f"got {len(sig)}")

    if NACL_AVAILABLE:
        # Derive reference pubkey for SOLANA_PATH
        ref_key, _ = slip10_derive(SLIP10_SEED_64, SOLANA_PATH)
        ref_pubkey = ed25519_pubkey(ref_key)
        ok = ed25519_verify(ref_pubkey, message, sig)
        result("signature verifies with PyNaCl", ok,
               f"pubkey={ref_pubkey.hex()[:16]}...  sig={sig.hex()[:16]}...")
    else:
        print("    [SKIP] PyNaCl not available")

def test_multi_chunk_sign(conn):
    print("\n[4] Multi-chunk sign (3 APDUs)")
    verify_pin(conn, DEFAULT_PIN)

    # Message long enough to force 3 chunks with chunk_size=100
    # First chunk: depth(1) + path(12) + 87 bytes = 100 bytes
    # Second chunk: 100 bytes
    # Third chunk: remaining
    message = bytes(range(256)) + b"extra bytes to pad to 300 total" + bytes(13)  # 300 bytes
    assert len(message) == 300

    t0 = time.time()
    sig = sign_tx(conn, SOLANA_PATH, message, chunk_size=100)
    elapsed = time.time() - t0

    result(f"multi-chunk (300-byte msg) returns 64 bytes  [{elapsed:.1f}s]", len(sig) == 64)

    if NACL_AVAILABLE:
        ref_key, _ = slip10_derive(SLIP10_SEED_64, SOLANA_PATH)
        ref_pubkey = ed25519_pubkey(ref_key)
        ok = ed25519_verify(ref_pubkey, message, sig)
        result("300-byte signature verifies with PyNaCl", ok)
    else:
        print("    [SKIP] PyNaCl not available")

def test_max_size_sign(conn):
    print("\n[5] Max-size sign (~1168-byte Solana message cap)")
    verify_pin(conn, DEFAULT_PIN)

    # Simulate a max-size Solana transaction message
    message = bytes(range(256)) * 4 + bytes(range(144))   # 1168 bytes
    assert len(message) == 1168

    t0 = time.time()
    sig = sign_tx(conn, SOLANA_PATH, message, chunk_size=200)
    elapsed = time.time() - t0

    result(f"max-size sign (1168 bytes) returns 64 bytes  [{elapsed:.1f}s]", len(sig) == 64)

    if NACL_AVAILABLE:
        ref_key, _ = slip10_derive(SLIP10_SEED_64, SOLANA_PATH)
        ref_pubkey = ed25519_pubkey(ref_key)
        ok = ed25519_verify(ref_pubkey, message, sig)
        result("1168-byte signature verifies with PyNaCl", ok)
    else:
        print("    [SKIP] PyNaCl not available")

def test_continuation_without_first(conn):
    print("\n[6] Continuation without first chunk → SW_INVALID_PARAMETER")
    # Re-select to clear txSignActive
    select(conn)
    verify_pin(conn, DEFAULT_PIN)

    # Send a continuation (P1=0x00) without a preceding first chunk
    r = _apdu(conn, INS_SIGN_TX, P1_CONTINUATION, 0x00, b"orphan bytes")
    result("orphan continuation → SW_INVALID_PARAMETER",
           sw_val(r) == SW_INVALID_PARAMETER, f"got {sw_val(r):04X}")

def test_non_hardened_index(conn):
    print("\n[7] Non-hardened index in path → SW_INVALID_PARAMETER")
    verify_pin(conn, DEFAULT_PIN)

    bad_path = [0x0000002C, 0x800001F5, 0x80000000]  # first index non-hardened
    payload  = bytes([len(bad_path)])
    for idx in bad_path:
        payload += struct.pack(">I", idx)
    payload += b"test message"

    r = _apdu(conn, INS_SIGN_TX, P1_FIRST_LAST, 0x00, payload)
    result("non-hardened path index → SW_INVALID_PARAMETER",
           sw_val(r) == SW_INVALID_PARAMETER, f"got {sw_val(r):04X}")

def test_sign_at_master_path(conn):
    print("\n[8] Sign at master path (depth=0)")
    verify_pin(conn, DEFAULT_PIN)

    message = b"Signing with master key"
    payload = bytes([0x00]) + message   # depth=0, no path indexes
    r = _apdu(conn, INS_SIGN_TX, P1_FIRST_LAST, 0x00, payload)
    ok_sw = sw_val(r) == SW_OK
    result("depth-0 sign returns SW 9000", ok_sw, f"got {sw_val(r):04X}")

    if ok_sw and NACL_AVAILABLE:
        sig = resp_data(r)
        ref_key, _ = slip10_derive(SLIP10_SEED_64, [])
        ref_pubkey = ed25519_pubkey(ref_key)
        ok = ed25519_verify(ref_pubkey, message, sig)
        result("master-path signature verifies", ok)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    rs = readers()
    if not rs:
        print("ERROR: No smart card readers found.")
        sys.exit(1)
    print(f"Using reader: {rs[0]}\n")
    conn = rs[0].createConnection()
    conn.connect()

    r = select(conn)
    if sw_val(r) != SW_OK:
        print(f"ERROR: SELECT failed SW={sw_val(r):04X}")
        print("       Is TapiocaApplet-0.1.cap installed?")
        sys.exit(1)

    from smartcard.util import toHexString
    print(f"TapiocaApplet selected (AID: {toHexString(APPLET_AID)})")

    # Pre-flight: ensure clean state
    status_r = get_status(conn)
    status   = resp_data(status_r)
    if status[10] == 0x01:
        print("Card already set up — resetting to factory...")
        verify_pin(conn, DEFAULT_PIN)
        r = reset_to_factory(conn)
        assert sw_val(r) == SW_RESET_TO_FACTORY
        select(conn)

    test_pin_guard(conn)
    test_seed_guard(conn)
    test_single_chunk_sign(conn)
    test_multi_chunk_sign(conn)
    test_max_size_sign(conn)
    test_continuation_without_first(conn)
    test_non_hardened_index(conn)
    test_sign_at_master_path(conn)

    # Cleanup
    do_factory_reset(conn)

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
