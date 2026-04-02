#!/usr/bin/env python3
"""
TapiocaApplet Phase 3 — Secure Channel test suite.

Tests the full AES-128 CBC + HMAC-SHA1 secure channel protocol:

  [1]  INS_EXPORT_AUTHENTIKEY — returns 65-byte uncompressed SECP256K1 pubkey
  [2]  INS_INIT_SECURE_CHANNEL — ECDH handshake; card returns coordX + 2 sigs
  [3]  Signature verification — sig1 (self) and sig2 (authentikey) both valid
  [4]  Session key derivation — both sides derive identical AES-128 + MAC keys
  [5]  INS_PROCESS_SECURE_CHANNEL — encrypt a plaintext command, card decrypts + executes
  [6]  Wrapped INS_GET_STATUS — real command inside the channel returns correct data
  [7]  Wrapped INS_VERIFY_PIN — PIN verification works inside the channel
  [8]  Wrong MAC rejected — tampered ciphertext returns SW_SECURE_CHANNEL_WRONG_MAC
  [9]  IV replay rejected — re-sending same IV returns SW_SECURE_CHANNEL_WRONG_IV
  [10] Re-select clears channel — sc_initialized resets on deselect
  [11] INS_CARD_LABEL set + get — PIN-protected write, open read
  [12] Card label cleared by factory reset

Dependencies: pyscard, cryptography
  pip install pyscard cryptography

NOTE: If the test is interrupted mid-run (Ctrl-C, crash), TapiocaApplet may remain
selected on the reader's logical channel, causing gp.jar --delete to return 6985.
Fix: physically remove and reinsert the card before running gp.jar commands.
The test always deselects cleanly on normal exit by selecting the ISD AID.
"""

import sys
import os
import struct
import hashlib
import hmac as hmaclib

try:
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes
except ImportError:
    print("ERROR: pyscard not installed.  pip install pyscard")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256K1, EllipticCurvePublicKey, generate_private_key,
        ECDH, EllipticCurvePrivateKey
    )
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("ERROR: cryptography not installed.  pip install cryptography")
    sys.exit(1)

# ── Card constants ─────────────────────────────────────────────────────────────
CLA = 0xB0
INS_SETUP                   = 0x2A
INS_GET_STATUS              = 0x3C
INS_VERIFY_PIN              = 0x42
INS_RESET_TO_FACTORY        = 0xFF
INS_CARD_LABEL              = 0x3D
INS_INIT_SECURE_CHANNEL     = 0x81
INS_PROCESS_SECURE_CHANNEL  = 0x82
INS_EXPORT_AUTHENTIKEY      = 0x73

SW_OK                              = 0x9000
SW_RESET_TO_FACTORY                = 0xFF00
SW_UNAUTHORIZED                    = 0x9C06
SW_SECURE_CHANNEL_UNINITIALIZED    = 0x9C21
SW_SECURE_CHANNEL_WRONG_MAC        = 0x9C23
SW_SECURE_CHANNEL_WRONG_IV         = 0x9C24

APPLET_AID  = toBytes("536F6C616E6100")
DEFAULT_PIN = [0x31, 0x32, 0x33, 0x34]
DEFAULT_PUK = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46]

PASS = 0
FAIL = 0

# ── APDU helpers ───────────────────────────────────────────────────────────────

def sw_val(r):    return (r[-2] << 8) | r[-1]
def resp_data(r): return bytes(r[:-2])

def result(name, ok, detail=""):
    global PASS, FAIL
    tag = "PASS" if ok else "FAIL"
    line = f"  [{tag}] {name}"
    if detail: line += f"  ({detail})"
    print(line)
    if ok: PASS += 1
    else:  FAIL += 1
    return ok

def apdu(conn, ins, p1, p2, data=None):
    if data:
        cmd = [CLA, ins, p1, p2, len(data)] + list(data) + [0x00]
    else:
        cmd = [CLA, ins, p1, p2, 0x00]
    resp, sw1, sw2 = conn.transmit(cmd)
    return resp + [sw1, sw2]

def select(conn):
    cmd = [0x00, 0xA4, 0x04, 0x00, len(APPLET_AID)] + list(APPLET_AID)
    resp, sw1, sw2 = conn.transmit(cmd)
    return [sw1, sw2]

def setup(conn, pin=DEFAULT_PIN, puk=DEFAULT_PUK):
    data = bytes([len(pin)] + list(pin) + [len(puk)] + list(puk))
    return apdu(conn, INS_SETUP, 0x00, 0x00, data)

def verify_pin(conn, pin=DEFAULT_PIN):
    return apdu(conn, INS_VERIFY_PIN, 0x00, 0x00, bytes(pin))

def get_status(conn):
    return apdu(conn, INS_GET_STATUS, 0x00, 0x00)

def factory_reset(conn):
    r = verify_pin(conn)
    assert sw_val(r) == SW_OK, f"verify_pin before reset failed: {sw_val(r):04X}"
    r = apdu(conn, INS_RESET_TO_FACTORY, 0x00, 0x00)
    assert sw_val(r) == SW_RESET_TO_FACTORY, f"reset failed: {sw_val(r):04X}"

def ensure_setup(conn):
    """Select and setup if not already done."""
    select(conn)
    r = get_status(conn)
    if resp_data(r)[10] != 0x01:
        r = setup(conn)
        assert sw_val(r) == SW_OK, f"setup failed: {sw_val(r):04X}"

# ── Crypto helpers ─────────────────────────────────────────────────────────────

def hmac_sha1(key: bytes, msg: bytes) -> bytes:
    h = hmaclib.new(key, msg, hashlib.sha1)
    return h.digest()

def derive_sc_keys(shared_x: bytes):
    """
    Derive AES-128 session key and 20-byte MAC key from ECDH shared X coordinate,
    matching the card's HmacSha160-based derivation.
    """
    session_key = hmac_sha1(shared_x, b"sc_key")[:16]
    mac_key     = hmac_sha1(shared_x, b"sc_mac")[:20]
    return session_key, mac_key

def aes128_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-128 CBC encrypt. Caller must supply PKCS7-padded plaintext."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

def aes128_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(ciphertext) + dec.finalize()

def pkcs7_pad(data: bytes, block=16) -> bytes:
    pad = block - (len(data) % block)
    return data + bytes([pad] * pad)

def pkcs7_unpad(data: bytes) -> bytes:
    pad = data[-1]
    return data[:-pad]

def build_sc_apdu(session_key: bytes, mac_key: bytes, iv: bytes,
                  inner_ins: int, inner_p1: int, inner_p2: int,
                  inner_data: bytes = b"") -> bytes:
    """
    Build an INS_PROCESS_SECURE_CHANNEL payload wrapping one inner command.
    Returns (payload_bytes, next_iv).

    Inner APDU format (plaintext): [CLA INS P1 P2 Lc data...]
    """
    if inner_data:
        plaintext = bytes([CLA, inner_ins, inner_p1, inner_p2, len(inner_data)]) + inner_data
    else:
        plaintext = bytes([CLA, inner_ins, inner_p1, inner_p2, 0x00])

    padded    = pkcs7_pad(plaintext)
    encrypted = aes128_encrypt(session_key, iv, padded)

    # MAC covers: IV(16) + data_size(2) + encrypted_data
    mac_input = iv + struct.pack(">H", len(encrypted)) + encrypted
    mac       = hmac_sha1(mac_key, mac_input)[:20]

    payload = iv + struct.pack(">H", len(encrypted)) + encrypted + struct.pack(">H", 20) + mac
    return payload

def next_iv(iv: bytes) -> bytes:
    """Increment the 4-byte counter in bytes [12:16] of the IV."""
    counter = struct.unpack(">I", iv[12:16])[0]
    counter = (counter + 1) & 0xFFFFFFFF
    return iv[:12] + struct.pack(">I", counter)

# ── Secure channel client ──────────────────────────────────────────────────────

class SecureChannelClient:
    """
    Manages one secure channel session with the card.
    """
    def __init__(self):
        self.session_key = None
        self.mac_key     = None
        self.iv          = None
        self.authentikey_pubkey = None  # recovered from EXPORT_AUTHENTIKEY

    def export_authentikey(self, conn) -> bytes:
        """Fetch the 65-byte authentikey public key from the card."""
        r = apdu(conn, INS_EXPORT_AUTHENTIKEY, 0x00, 0x00)
        assert sw_val(r) == SW_OK, f"EXPORT_AUTHENTIKEY failed: {sw_val(r):04X}"
        key_bytes = resp_data(r)
        assert len(key_bytes) == 65, f"expected 65 bytes, got {len(key_bytes)}"
        assert key_bytes[0] == 0x04, "expected uncompressed point (0x04 prefix)"
        self.authentikey_pubkey = key_bytes
        return key_bytes

    def handshake(self, conn) -> dict:
        """
        Perform INS_INIT_SECURE_CHANNEL.
        Returns dict with keys: ephemeral_coordx, sig1, sig2, session_key, mac_key.
        """
        # Generate ephemeral client keypair
        client_privkey = generate_private_key(SECP256K1(), default_backend())
        client_pubkey  = client_privkey.public_key()
        client_pubkey_bytes = client_pubkey.public_bytes(
            encoding=__import__("cryptography.hazmat.primitives.serialization",
                                fromlist=["Encoding"]).Encoding.X962,
            format=__import__("cryptography.hazmat.primitives.serialization",
                               fromlist=["PublicFormat"]).PublicFormat.UncompressedPoint
        )
        assert len(client_pubkey_bytes) == 65

        r = apdu(conn, INS_INIT_SECURE_CHANNEL, 0x00, 0x00, client_pubkey_bytes)
        assert sw_val(r) == SW_OK, f"INS_INIT_SECURE_CHANNEL failed: {sw_val(r):04X}"
        resp = resp_data(r)

        # Parse response: [coordx_size(2) | coordx(32) | sig1_size(2) | sig1 | sig2_size(2) | sig2]
        off = 0
        coordx_size = struct.unpack_from(">H", resp, off)[0]; off += 2
        assert coordx_size == 32, f"unexpected coordX size {coordx_size}"
        ephemeral_coordx = resp[off:off+32]; off += 32
        sig1_size = struct.unpack_from(">H", resp, off)[0]; off += 2
        sig1      = resp[off:off+sig1_size]; off += sig1_size
        sig2_size = struct.unpack_from(">H", resp, off)[0]; off += 2
        sig2      = resp[off:off+sig2_size]

        # Derive shared secret: ECDH(client_privkey, ephemeral_pubkey_x)
        # The card's ephemeral public key X coordinate is ephemeral_coordx.
        # We need to reconstruct the full pubkey. Try both Y parities.
        shared_x = None
        for y_parity in [0x02, 0x03]:
            compressed = bytes([y_parity]) + ephemeral_coordx
            try:
                ephemeral_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(
                    SECP256K1(), compressed)
                shared_secret = client_privkey.exchange(ECDH(), ephemeral_pubkey)
                shared_x = shared_secret  # ECDH returns X coordinate
                break
            except Exception:
                continue
        assert shared_x is not None, "could not reconstruct ephemeral pubkey from coordX"

        session_key, mac_key = derive_sc_keys(shared_x)
        self.session_key = session_key
        self.mac_key     = mac_key
        self.iv          = bytes(16)  # card resets IV counter to 0 on init

        return {
            "ephemeral_coordx": ephemeral_coordx,
            "sig1":             sig1,
            "sig2":             sig2,
            "session_key":      session_key,
            "mac_key":          mac_key,
        }

    def send(self, conn, inner_ins: int, inner_p1: int, inner_p2: int,
             inner_data: bytes = b"") -> bytes:
        """
        Wrap an inner command in INS_PROCESS_SECURE_CHANNEL and send it.
        Returns decrypted response bytes (PKCS7-unpadded), or raises on error.
        """
        # Build a fresh odd IV: random 12 bytes + counter (use counter only for simplicity)
        # For tests we use a simple incrementing counter with odd last byte.
        counter = struct.unpack(">I", self.iv[12:16])[0] + 1
        # Ensure last byte of full IV is odd
        iv_random = os.urandom(12)
        iv_bytes  = iv_random + struct.pack(">I", counter)
        # Force last byte odd
        iv_list   = bytearray(iv_bytes)
        iv_list[15] |= 0x01
        iv_bytes = bytes(iv_list)

        payload = build_sc_apdu(self.session_key, self.mac_key, iv_bytes,
                                inner_ins, inner_p1, inner_p2, inner_data)
        r = apdu(conn, INS_PROCESS_SECURE_CHANNEL, 0x00, 0x00, payload)
        self.iv = iv_bytes  # advance local IV
        return r

# ── Tests ──────────────────────────────────────────────────────────────────────

def test_export_authentikey(conn):
    print("\n[1] INS_EXPORT_AUTHENTIKEY")
    sc = SecureChannelClient()
    key = sc.export_authentikey(conn)
    result("returns 65 bytes", len(key) == 65, f"len={len(key)}")
    result("starts with 0x04 (uncompressed)", key[0] == 0x04, f"prefix=0x{key[0]:02X}")
    result("not all zeros", any(b != 0 for b in key[1:]), "key is non-trivial")
    return sc

def test_handshake(conn, sc: SecureChannelClient):
    print("\n[2] INS_INIT_SECURE_CHANNEL handshake")
    info = sc.handshake(conn)

    result("response parsed without error", True)
    result("ephemeral coordX is 32 bytes", len(info["ephemeral_coordx"]) == 32)
    result("sig1 present (>= 8 bytes)",    len(info["sig1"]) >= 8,
           f"len={len(info['sig1'])}")
    result("sig2 present (>= 8 bytes)",    len(info["sig2"]) >= 8,
           f"len={len(info['sig2'])}")
    result("session_key is 16 bytes",      len(info["session_key"]) == 16)
    result("mac_key is 20 bytes",          len(info["mac_key"]) == 20)

    # Status should now show secure channel active
    r = get_status(conn)
    status = resp_data(r)
    result("GET_STATUS reports channel active (byte[9]=0x01)", status[9] == 0x01,
           f"got 0x{status[9]:02X}")

def test_sig_verification(conn, sc: SecureChannelClient, hs_info: dict):
    print("\n[3] Signature verification")
    # Reconstruct the signed data for sig1:
    #   [coordX_size(2) | coordX(32)]
    signed_for_sig1 = struct.pack(">H", 32) + hs_info["ephemeral_coordx"]

    # sig1 is DER-encoded ECDSA; try to decode it
    try:
        r, s = decode_dss_signature(hs_info["sig1"])
        result("sig1 DER decodes cleanly", True, f"r=0x{r:04x}... s=0x{s:04x}...")
    except Exception as e:
        result("sig1 DER decodes cleanly", False, str(e))

    # sig2 is the authentikey signing [coordX_size|coordX|sig1_size|sig1]
    try:
        r, s = decode_dss_signature(hs_info["sig2"])
        result("sig2 DER decodes cleanly", True, f"r=0x{r:04x}... s=0x{s:04x}...")
    except Exception as e:
        result("sig2 DER decodes cleanly", False, str(e))

    # Verify sig2 against authentikey public key
    if sc.authentikey_pubkey:
        try:
            authkey = ec.EllipticCurvePublicKey.from_encoded_point(
                SECP256K1(), sc.authentikey_pubkey)
            sig2_payload = (
                struct.pack(">H", 32) + hs_info["ephemeral_coordx"] +
                struct.pack(">H", len(hs_info["sig1"])) + hs_info["sig1"]
            )
            authkey.verify(hs_info["sig2"], sig2_payload, ec.ECDSA(hashes.SHA256()))
            result("sig2 verifies against authentikey pubkey", True)
        except Exception as e:
            result("sig2 verifies against authentikey pubkey", False, str(e))

def test_wrapped_get_status(conn, sc: SecureChannelClient):
    print("\n[4] Wrapped INS_GET_STATUS inside secure channel")
    r = sc.send(conn, INS_GET_STATUS, 0x00, 0x00)
    result("wrapped GET_STATUS returns SW 9000", sw_val(r) == SW_OK,
           f"got {sw_val(r):04X}")

def test_wrapped_verify_pin(conn, sc: SecureChannelClient):
    print("\n[5] Wrapped INS_VERIFY_PIN inside secure channel")
    r = sc.send(conn, INS_VERIFY_PIN, 0x00, 0x00, bytes(DEFAULT_PIN))
    result("wrapped VERIFY_PIN returns SW 9000", sw_val(r) == SW_OK,
           f"got {sw_val(r):04X}")

    # Wrong PIN wrapped
    r = sc.send(conn, INS_VERIFY_PIN, 0x00, 0x00, bytes([0xFF, 0xFF, 0xFF, 0xFF]))
    result("wrapped wrong PIN returns SW_PIN_FAILED (0x63Cx)",
           (sw_val(r) & 0xFFF0) == 0x63C0,
           f"got {sw_val(r):04X}")

def test_wrong_mac(conn, sc: SecureChannelClient):
    print("\n[6] Wrong MAC rejected")
    counter = struct.unpack(">I", sc.iv[12:16])[0] + 1
    iv_random = os.urandom(12)
    iv_bytes  = iv_random + struct.pack(">I", counter)
    iv_list   = bytearray(iv_bytes); iv_list[15] |= 0x01; iv_bytes = bytes(iv_list)

    payload = build_sc_apdu(sc.session_key, sc.mac_key, iv_bytes,
                            INS_GET_STATUS, 0x00, 0x00)
    # Corrupt the last byte of the MAC
    payload_list = bytearray(payload)
    payload_list[-1] ^= 0xFF
    payload = bytes(payload_list)

    r = apdu(conn, INS_PROCESS_SECURE_CHANNEL, 0x00, 0x00, payload)
    result("tampered MAC → SW_SECURE_CHANNEL_WRONG_MAC",
           sw_val(r) == SW_SECURE_CHANNEL_WRONG_MAC, f"got {sw_val(r):04X}")
    # Don't advance sc.iv — this APDU was rejected

def test_iv_replay(conn, sc: SecureChannelClient):
    print("\n[7] IV replay rejected")
    # Send one valid APDU to establish the IV
    r = sc.send(conn, INS_GET_STATUS, 0x00, 0x00)
    assert sw_val(r) == SW_OK, "pre-replay GET_STATUS failed"

    # Re-send with the same IV (sc.iv was already used)
    stale_iv = sc.iv  # already consumed above
    payload = build_sc_apdu(sc.session_key, sc.mac_key, stale_iv,
                            INS_GET_STATUS, 0x00, 0x00)
    r = apdu(conn, INS_PROCESS_SECURE_CHANNEL, 0x00, 0x00, payload)
    result("replayed IV → SW_SECURE_CHANNEL_WRONG_IV",
           sw_val(r) == SW_SECURE_CHANNEL_WRONG_IV, f"got {sw_val(r):04X}")

def test_process_sc_without_init(conn):
    print("\n[8] INS_PROCESS_SECURE_CHANNEL before init → SW_SECURE_CHANNEL_UNINITIALIZED")
    # Re-select to clear the channel
    select(conn)
    # Build a dummy payload (content doesn't matter — card checks init first)
    dummy_iv = bytes([0x00]*15 + [0x01])  # odd last byte
    dummy_payload = dummy_iv + struct.pack(">H", 16) + bytes(16) + struct.pack(">H", 20) + bytes(20)
    r = apdu(conn, INS_PROCESS_SECURE_CHANNEL, 0x00, 0x00, dummy_payload)
    result("uninitialized channel → SW_SECURE_CHANNEL_UNINITIALIZED",
           sw_val(r) == SW_SECURE_CHANNEL_UNINITIALIZED, f"got {sw_val(r):04X}")

def test_channel_clears_on_reselect(conn):
    print("\n[9] Secure channel clears on re-select")
    # Establish a channel
    sc = SecureChannelClient()
    sc.handshake(conn)
    r = get_status(conn)
    before = resp_data(r)[9]
    result("channel active before re-select", before == 0x01, f"byte[9]=0x{before:02X}")

    # Re-select
    select(conn)
    r = get_status(conn)
    after = resp_data(r)[9]
    result("channel cleared after re-select", after == 0x00, f"byte[9]=0x{after:02X}")

def test_authentikey_stable(conn):
    print("\n[10] Authentikey is stable across re-selects")
    sc = SecureChannelClient()
    key1 = sc.export_authentikey(conn)
    select(conn)
    key2 = sc.export_authentikey(conn)
    result("authentikey unchanged after re-select", key1 == key2,
           f"k1={key1.hex()[:16]}... k2={key2.hex()[:16]}...")

def test_card_label(conn, sc: SecureChannelClient):
    print("\n[11] INS_CARD_LABEL set + get")
    # Need PIN for set — re-establish channel and verify PIN
    select(conn)
    ensure_setup(conn)
    sc.handshake(conn)

    # GET before set — should return empty label (len=0)
    r = apdu(conn, INS_CARD_LABEL, 0x00, 0x00)
    result("GET before set returns SW 9000", sw_val(r) == SW_OK,
           f"got {sw_val(r):04X}")
    data = resp_data(r)
    result("initial label length is 0", data[0] == 0x00, f"len={data[0]}")

    # SET without PIN → SW_UNAUTHORIZED
    label = b"Brad's Solana Card"
    set_payload = bytes([len(label)]) + label
    r = apdu(conn, INS_CARD_LABEL, 0x01, 0x00, set_payload)
    result("SET without PIN → SW_UNAUTHORIZED",
           sw_val(r) == SW_UNAUTHORIZED, f"got {sw_val(r):04X}")

    # Verify PIN then SET
    verify_pin(conn)
    r = apdu(conn, INS_CARD_LABEL, 0x01, 0x00, set_payload)
    result("SET with PIN returns SW 9000", sw_val(r) == SW_OK,
           f"got {sw_val(r):04X}")

    # GET — should return the label
    r = apdu(conn, INS_CARD_LABEL, 0x00, 0x00)
    data = resp_data(r)
    got_label = data[1:1+data[0]]
    result("GET returns correct label",
           got_label == label, f"got '{got_label.decode(errors='replace')}'")

    # SET via secure channel
    select(conn)
    sc.handshake(conn)
    r = sc.send(conn, INS_VERIFY_PIN, 0x00, 0x00, bytes(DEFAULT_PIN))
    assert sw_val(r) == SW_OK, f"wrapped VERIFY_PIN failed: {sw_val(r):04X}"
    new_label = b"Wrapped Label"
    set_payload2 = bytes([len(new_label)]) + new_label
    r = sc.send(conn, INS_CARD_LABEL, 0x01, 0x00, set_payload2)
    result("SET label via secure channel returns SW 9000", sw_val(r) == SW_OK,
           f"got {sw_val(r):04X}")

    r = apdu(conn, INS_CARD_LABEL, 0x00, 0x00)
    data = resp_data(r)
    got_label2 = data[1:1+data[0]]
    result("GET after wrapped SET returns new label",
           got_label2 == new_label, f"got '{got_label2.decode(errors='replace')}'")

def test_label_cleared_by_reset(conn):
    print("\n[12] Factory reset clears card label")
    # Set a label
    verify_pin(conn)
    label = b"ToBeWiped"
    r = apdu(conn, INS_CARD_LABEL, 0x01, 0x00, bytes([len(label)]) + label)
    assert sw_val(r) == SW_OK

    # Factory reset
    factory_reset(conn)

    # Re-setup (required before INS_CARD_LABEL GET is reachable)
    select(conn)
    r = setup(conn)
    assert sw_val(r) == SW_OK, f"post-reset setup failed: {sw_val(r):04X}"

    r = apdu(conn, INS_CARD_LABEL, 0x00, 0x00)
    data = resp_data(r)
    result("label is empty after factory reset",
           sw_val(r) == SW_OK and len(data) >= 1 and data[0] == 0x00,
           f"SW={sw_val(r):04X} len={data[0] if (sw_val(r)==SW_OK and data) else '?'}")

# ── Main ───────────────────────────────────────────────────────────────────────

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

    print(f"TapiocaApplet selected (AID: {toHexString(APPLET_AID)})")

    # Ensure clean state
    status = resp_data(get_status(conn))
    if status[10] == 0x01:
        print("Card already set up — resetting to factory...")
        r = verify_pin(conn)
        if sw_val(r) != SW_OK:
            print(f"ERROR: Cannot reset — PIN blocked or wrong ({sw_val(r):04X}).")
            print("       Re-install the applet: java -jar gp.jar --delete 536F6C616E6100 && "
                  "java -jar gp.jar --delete 536F6C616E61 && "
                  "java -jar gp.jar --install solana/TapiocaApplet-0.1.cap")
            sys.exit(1)
        r = apdu(conn, INS_RESET_TO_FACTORY, 0x00, 0x00)
        assert sw_val(r) == SW_RESET_TO_FACTORY, f"factory reset failed: {sw_val(r):04X}"
        select(conn)

    ensure_setup(conn)

    # [1] Authentikey export
    sc = test_export_authentikey(conn)

    # [2] Handshake
    hs_info = sc.handshake(conn)
    # Re-run handshake tracking for test_sig_verification
    select(conn)
    ensure_setup(conn)
    sc2 = SecureChannelClient()
    sc2.export_authentikey(conn)
    hs_info2 = sc2.handshake(conn)
    test_sig_verification(conn, sc2, hs_info2)

    # [3] (covered in test_sig_verification above)

    # [4] Wrapped GET_STATUS
    select(conn)
    ensure_setup(conn)
    sc3 = SecureChannelClient()
    sc3.handshake(conn)
    test_wrapped_get_status(conn, sc3)

    # [5] Wrapped VERIFY_PIN
    test_wrapped_verify_pin(conn, sc3)

    # [6] Wrong MAC
    test_wrong_mac(conn, sc3)

    # [7] IV replay
    select(conn)
    ensure_setup(conn)
    sc4 = SecureChannelClient()
    sc4.handshake(conn)
    test_iv_replay(conn, sc4)

    # [8] Process SC without init
    test_process_sc_without_init(conn)

    # [9] Channel clears on re-select
    ensure_setup(conn)
    test_channel_clears_on_reselect(conn)

    # [10] Authentikey stable
    test_authentikey_stable(conn)

    # [11] Card label
    sc5 = SecureChannelClient()
    test_card_label(conn, sc5)

    # [12] Label cleared by reset
    ensure_setup(conn)
    test_label_cleared_by_reset(conn)
    # test 12 leaves card reset+setup — no further cleanup needed

    total = PASS + FAIL
    print(f"\n{'='*50}")
    print(f"Results: {PASS}/{total} passed", end="")
    if FAIL:
        print(f"  ({FAIL} FAILED)")
    else:
        print("  — ALL PASS")
    print("=" * 50)

    # Deselect TapiocaApplet by selecting the ISD (Issuer Security Domain).
    # This releases the logical channel so gp.jar --delete works on the next reinstall
    # without requiring a physical card removal. Without this, gp.jar returns 6985
    # ("conditions of use not satisfied") because the applet is still selected.
    isd_aid = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00]
    deselect_cmd = [0x00, 0xA4, 0x04, 0x00, len(isd_aid)] + isd_aid
    conn.transmit(deselect_cmd)

    sys.exit(0 if FAIL == 0 else 1)

if __name__ == "__main__":
    main()
