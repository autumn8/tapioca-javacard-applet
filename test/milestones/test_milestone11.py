#!/usr/bin/env python3
"""
TapiocaApplet Milestone 1.1 — PIN management test suite.

Requires:
  - pyscard  : pip install pyscard
  - TapiocaApplet-0.1.cap installed on J3R180 via GlobalPlatformPro

Usage:
  python3 test_milestone11.py

All tests run sequentially. The applet is reset to factory after each logical
group so tests are independent.

Install command (before first run):
  gp --install TapiocaApplet-0.1.cap
"""

import sys
from smartcard.System import readers
from smartcard.util import toHexString, toBytes

# ── Constants ────────────────────────────────────────────────────────────────
CLA = 0xB0

INS_SETUP            = 0x2A
INS_GET_STATUS       = 0x3C
INS_RESET_TO_FACTORY = 0xFF
INS_VERIFY_PIN       = 0x42
INS_CHANGE_PIN       = 0x44
INS_UNBLOCK_PIN      = 0x46
INS_IMPORT_SEED      = 0x6C
INS_RESET_SEED       = 0x77
INS_GET_PUBLIC_KEY   = 0x6D
INS_SIGN_TX          = 0x6F

SW_OK                  = 0x9000
SW_SETUP_NOT_DONE      = 0x9C04
SW_SETUP_ALREADY_DONE  = 0x9C03
SW_UNAUTHORIZED        = 0x9C06
SW_IDENTITY_BLOCKED    = 0x9C0C
SW_INVALID_PARAMETER   = 0x9C0F
SW_NOT_IMPLEMENTED     = 0x9C20
SW_RESET_TO_FACTORY    = 0xFF00
SW_PIN_FAILED_BASE     = 0x63C0  # | tries_remaining

APPLET_AID = toBytes("536F6C616E6100")

# ── Test state ────────────────────────────────────────────────────────────────
PASS = 0
FAIL = 0

def result(name, ok, detail=""):
    global PASS, FAIL
    status = "PASS" if ok else "FAIL"
    line = f"  [{status}] {name}"
    if detail:
        line += f"  ({detail})"
    print(line)
    if ok:
        PASS += 1
    else:
        FAIL += 1
    return ok

# ── APDU helpers ──────────────────────────────────────────────────────────────
def sw(response):
    """Extract status word as int."""
    return (response[-2] << 8) | response[-1]

def data(response):
    """Return response data (everything except final 2 SW bytes)."""
    return response[:-2]

def _apdu(conn, ins, p1, p2, payload=None):
    """Build and send a CLA=0xB0 APDU, return full response bytes."""
    if payload:
        apdu = [CLA, ins, p1, p2, len(payload)] + list(payload) + [0x00]
    else:
        apdu = [CLA, ins, p1, p2, 0x00]
    resp, sw1, sw2 = conn.transmit(apdu)
    return resp + [sw1, sw2]

def select(conn):
    apdu = [0x00, 0xA4, 0x04, 0x00, len(APPLET_AID)] + APPLET_AID
    resp, sw1, sw2 = conn.transmit(apdu)
    return [sw1, sw2]

def setup(conn, pin, puk):
    payload = [len(pin)] + list(pin) + [len(puk)] + list(puk)
    return _apdu(conn, INS_SETUP, 0x00, 0x00, bytes(payload))

def get_status(conn):
    return _apdu(conn, INS_GET_STATUS, 0x00, 0x00)

def verify_pin(conn, pin):
    return _apdu(conn, INS_VERIFY_PIN, 0x00, 0x00, bytes(pin))

def change_pin(conn, old_pin, new_pin):
    payload = [len(old_pin)] + list(old_pin) + [len(new_pin)] + list(new_pin)
    return _apdu(conn, INS_CHANGE_PIN, 0x00, 0x00, bytes(payload))

def unblock_pin(conn, puk, new_pin):
    payload = [len(puk)] + list(puk) + [len(new_pin)] + list(new_pin)
    return _apdu(conn, INS_UNBLOCK_PIN, 0x00, 0x00, bytes(payload))

def reset_to_factory(conn):
    return _apdu(conn, INS_RESET_TO_FACTORY, 0x00, 0x00)

def do_setup(conn):
    """Helper: fresh select + setup with default PIN/PUK."""
    select(conn)
    r = setup(conn, DEFAULT_PIN, DEFAULT_PUK)
    assert sw(r) == SW_OK, f"setup failed: {sw(r):04X}"

def do_factory_reset(conn):
    """Helper: verify PIN then reset. Leaves card in post-reset state."""
    r = verify_pin(conn, DEFAULT_PIN)
    assert sw(r) == SW_OK
    r = reset_to_factory(conn)
    assert sw(r) == SW_RESET_TO_FACTORY

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_PIN = [0x31, 0x32, 0x33, 0x34]          # "1234"
DEFAULT_PUK = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46]  # "ABCDEF"
NEW_PIN     = [0x39, 0x38, 0x37, 0x36]          # "9876"
WRONG_PIN   = [0xFF, 0xFF, 0xFF, 0xFF]
WRONG_PUK   = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

# ── Test groups ───────────────────────────────────────────────────────────────

def test_get_status_before_setup(conn):
    print("\n[1] GET_STATUS before setup")
    select(conn)
    r = get_status(conn)
    ok = sw(r) == SW_OK
    result("SW == 9000", ok)
    if ok:
        d = data(r)
        result("response length == 12", len(d) == 12, f"got {len(d)}")
        result("protocol_major == 0x00", d[0] == 0x00)
        result("protocol_minor == 0x01", d[1] == 0x01)
        result("applet_major == 0x00",   d[2] == 0x00)
        result("applet_minor == 0x01",   d[3] == 0x01)
        result("pin_tries == 0x00 (no setup)", d[4] == 0x00)
        result("puk_tries == 0x00 (no setup)", d[6] == 0x00)
        result("is_seeded == 0x00",  d[8]  == 0x00)
        result("setup_done == 0x00", d[10] == 0x00)

def test_setup(conn):
    print("\n[2] SETUP")
    select(conn)
    r = setup(conn, DEFAULT_PIN, DEFAULT_PUK)
    result("first setup succeeds (SW 9000)", sw(r) == SW_OK)

    r = setup(conn, DEFAULT_PIN, DEFAULT_PUK)
    result("second setup returns SW_SETUP_ALREADY_DONE", sw(r) == SW_SETUP_ALREADY_DONE)

    # Verify status now reflects setup
    r = get_status(conn)
    d = data(r)
    result("GET_STATUS after setup: setup_done == 0x01", d[10] == 0x01)
    result("GET_STATUS: pin_tries_left == 5",  d[4] == 5)
    result("GET_STATUS: pin_tries_max == 5",   d[5] == 5)
    result("GET_STATUS: puk_tries_left == 3",  d[6] == 3)
    result("GET_STATUS: puk_tries_max == 3",   d[7] == 3)

def test_setup_invalid(conn):
    print("\n[3] SETUP — invalid PIN lengths")
    # Short PIN (< 4 bytes)
    select(conn)
    r = setup(conn, [0x31, 0x32, 0x33], DEFAULT_PUK)  # len=3
    result("PIN len 3 rejected (SW_INVALID_PARAMETER)", sw(r) == SW_INVALID_PARAMETER)

    # Long PIN (> 16 bytes)
    r = setup(conn, list(range(17)), DEFAULT_PUK)  # len=17
    result("PIN len 17 rejected (SW_INVALID_PARAMETER)", sw(r) == SW_INVALID_PARAMETER)

def test_verify_pin(conn):
    print("\n[4] VERIFY_PIN")
    do_setup(conn)

    r = verify_pin(conn, DEFAULT_PIN)
    result("correct PIN accepted (SW 9000)", sw(r) == SW_OK)

    # Reset session
    select(conn)
    r = verify_pin(conn, WRONG_PIN)
    tries = sw(r) & 0x0F
    result("wrong PIN returns 0x63Cx",      (sw(r) & 0xFFF0) == SW_PIN_FAILED_BASE)
    result("tries_left decremented to 4",   tries == 4)

    r = get_status(conn)
    d = data(r)
    result("GET_STATUS reflects tries_left=4", d[4] == 4)

def test_commands_require_setup(conn):
    print("\n[5] Commands blocked before setup")
    select(conn)
    for ins_name, ins_val in [("VERIFY_PIN", INS_VERIFY_PIN),
                               ("CHANGE_PIN", INS_CHANGE_PIN),
                               ("UNBLOCK_PIN", INS_UNBLOCK_PIN)]:
        r = _apdu(conn, ins_val, 0x00, 0x00, bytes([0x31, 0x32, 0x33, 0x34]))
        result(f"{ins_name} → SW_SETUP_NOT_DONE", sw(r) == SW_SETUP_NOT_DONE)

def test_change_pin(conn):
    print("\n[6] CHANGE_PIN")
    do_setup(conn)

    # Must verify PIN first
    r = change_pin(conn, DEFAULT_PIN, NEW_PIN)
    result("change without verify → SW_UNAUTHORIZED", sw(r) == SW_UNAUTHORIZED)

    verify_pin(conn, DEFAULT_PIN)

    # Change to new PIN
    r = change_pin(conn, DEFAULT_PIN, NEW_PIN)
    result("change PIN succeeds", sw(r) == SW_OK)

    # Old PIN no longer works
    select(conn)
    r = verify_pin(conn, DEFAULT_PIN)
    result("old PIN rejected after change", (sw(r) & 0xFFF0) == SW_PIN_FAILED_BASE)

    # New PIN works
    select(conn)
    r = verify_pin(conn, NEW_PIN)
    result("new PIN accepted", sw(r) == SW_OK)

    # Restore for factory reset
    change_pin(conn, NEW_PIN, DEFAULT_PIN)
    do_factory_reset(conn)

def test_pin_lockout_and_unblock(conn):
    print("\n[7] PIN lockout and UNBLOCK_PIN")
    do_setup(conn)

    # Exhaust all 5 tries
    for i in range(5):
        select(conn)
        verify_pin(conn, WRONG_PIN)

    r = verify_pin(conn, DEFAULT_PIN)
    result("PIN blocked after 5 failures → SW_IDENTITY_BLOCKED", sw(r) == SW_IDENTITY_BLOCKED)

    r = get_status(conn)
    result("GET_STATUS shows tries_left=0", data(r)[4] == 0)

    # Wrong PUK
    r = unblock_pin(conn, WRONG_PUK, NEW_PIN)
    result("wrong PUK decrements PUK counter", (sw(r) & 0xFFF0) == SW_PIN_FAILED_BASE)

    # Correct PUK — unblocks and sets new PIN
    r = unblock_pin(conn, DEFAULT_PUK, NEW_PIN)
    result("unblock with correct PUK succeeds (SW 9000)", sw(r) == SW_OK)

    r = get_status(conn)
    d = data(r)
    result("PIN tries_left restored to 5 after unblock", d[4] == 5)

    # New PIN works
    select(conn)
    r = verify_pin(conn, NEW_PIN)
    result("new PIN accepted after unblock", sw(r) == SW_OK)

    # Cleanup
    change_pin(conn, NEW_PIN, DEFAULT_PIN)
    do_factory_reset(conn)

def test_puk_lockout(conn):
    print("\n[8] PUK lockout")
    do_setup(conn)

    # Lock PIN first
    for _ in range(5):
        select(conn)
        verify_pin(conn, WRONG_PIN)

    # Exhaust all 3 PUK tries
    for _ in range(3):
        unblock_pin(conn, WRONG_PUK, NEW_PIN)

    r = unblock_pin(conn, DEFAULT_PUK, NEW_PIN)
    result("PUK blocked → SW_IDENTITY_BLOCKED", sw(r) == SW_IDENTITY_BLOCKED)

    # Only way out is factory reset — but that requires PIN (which is blocked)
    # so the card is effectively bricked. Just verify the state.
    r = get_status(conn)
    d = data(r)
    result("PUK tries_left == 0", d[6] == 0)

    # Re-install to recover (not tested here — would require gp)
    print("    (card will need re-install to recover from full PUK lockout)")

def test_reset_to_factory(conn):
    print("\n[9] RESET_TO_FACTORY")
    do_setup(conn)

    r = reset_to_factory(conn)
    result("reset without PIN → SW_UNAUTHORIZED", sw(r) == SW_UNAUTHORIZED)

    verify_pin(conn, DEFAULT_PIN)
    r = reset_to_factory(conn)
    result("reset with valid PIN → SW_RESET_TO_FACTORY (0xFF00)", sw(r) == SW_RESET_TO_FACTORY)

    # Card should be back to pre-setup state
    r = get_status(conn)
    d = data(r)
    result("GET_STATUS after reset: setup_done == 0x00", d[10] == 0x00)
    result("GET_STATUS after reset: is_seeded == 0x00",  d[8]  == 0x00)
    result("GET_STATUS after reset: pin_tries == 0x00",  d[4]  == 0x00)

    r = verify_pin(conn, DEFAULT_PIN)
    result("commands blocked after factory reset → SW_SETUP_NOT_DONE", sw(r) == SW_SETUP_NOT_DONE)

def test_stub_commands(conn):
    print("\n[10] Phase 1.2/1.3 stubs return SW_NOT_IMPLEMENTED")
    do_setup(conn)
    verify_pin(conn, DEFAULT_PIN)

    for name, ins in [("IMPORT_SEED",    INS_IMPORT_SEED),
                      ("RESET_SEED",     INS_RESET_SEED),
                      ("GET_PUBLIC_KEY", INS_GET_PUBLIC_KEY),
                      ("SIGN_TX",        INS_SIGN_TX)]:
        r = _apdu(conn, ins, 0x00, 0x00)
        result(f"{name} → SW_NOT_IMPLEMENTED (0x9C20)", sw(r) == SW_NOT_IMPLEMENTED)

    do_factory_reset(conn)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    rs = readers()
    if not rs:
        print("ERROR: No smart card readers found. Connect reader and try again.")
        sys.exit(1)

    print(f"Using reader: {rs[0]}")
    conn = rs[0].createConnection()
    conn.connect()

    r = select(conn)
    if sw(r) != SW_OK:
        print(f"ERROR: Failed to select TapiocaApplet — SW={sw(r):04X}")
        print("       Is TapiocaApplet-0.1.cap installed?")
        print("       java -jar gp.jar --install solana/TapiocaApplet-0.1.cap")
        sys.exit(1)
    print(f"TapiocaApplet selected (AID: {toHexString(APPLET_AID)})")

    # ── Pre-flight: ensure card is in clean (pre-setup) state ────────────────
    r = get_status(conn)
    if data(r)[10] == 0x01:
        print("Card already set up — resetting to factory with default PIN...")
        r = verify_pin(conn, DEFAULT_PIN)
        if sw(r) != SW_OK:
            print(f"ERROR: Card is set up but default PIN rejected (SW={sw(r):04X}).")
            print("       Re-install the applet:")
            print("         java -jar gp.jar --delete 536F6C616E6100")
            print("         java -jar gp.jar --delete 536F6C616E61")
            print("         java -jar gp.jar --install solana/TapiocaApplet-0.1.cap")
            sys.exit(1)
        r = reset_to_factory(conn)
        assert sw(r) == SW_RESET_TO_FACTORY, f"factory reset failed: {sw(r):04X}"
        select(conn)
        print("Card reset to factory state.\n")

    # Run all test groups
    test_get_status_before_setup(conn)
    test_setup(conn)

    # Reset to clean state for remaining tests
    verify_pin(conn, DEFAULT_PIN)
    reset_to_factory(conn)

    test_setup_invalid(conn)
    test_commands_require_setup(conn)
    test_verify_pin(conn)

    # Reset between groups
    select(conn)
    verify_pin(conn, DEFAULT_PIN)
    reset_to_factory(conn)

    test_change_pin(conn)
    test_pin_lockout_and_unblock(conn)

    # Tests 9 & 10 run before PUK lockout (which bricks the card)
    select(conn)
    test_reset_to_factory(conn)
    select(conn)
    test_stub_commands(conn)

    # PUK lockout is last — bricks the card; re-install needed for next run
    select(conn)
    test_puk_lockout(conn)
    print("\n  Note: card needs re-install before next test run (PUK locked):")
    print("       java -jar gp.jar --delete 536F6C616E61")
    print("       java -jar gp.jar --install solana/TapiocaApplet-0.1.cap")

    # ── Summary ───────────────────────────────────────────────────────────────
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
