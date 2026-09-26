"""
Shared crypto for the DIY Vaulted Passkeys tooling.

Implements the enroller side of RFC 9180 HPKE in Auth mode with
DHKEM-X448, HKDF-SHA512 and AES-256-GCM, exactly matching
pico-keys-sdk/src/vault.c's vault_hpke_auth_decap(). This has been
validated against the real, unmodified vault.c (only the embedded CA
constant swapped) compiled with the polhenarejos/mbedtls EdDSA fork -
see the round-trip test notes in the conversation this was built from.

Also implements the Kvault recovery-envelope format (Argon2id + AES-GCM)
so you have something durable to back up besides "remember the bytes".
"""
import hashlib
import hmac
import json
import struct
import base64
import datetime

from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

NH = 64  # HKDF-SHA512 hash size
NK = 32  # AES-256-GCM key size
NN = 12  # AES-GCM nonce size
X448_BYTES = 56

KEM_SUITE_ID = b"KEM" + bytes([0x00, 0x21])
HPKE_SUITE_ID = b"HPKE" + bytes([0x00, 0x21, 0x00, 0x03, 0x00, 0x02])
VAULT_ENROLLMENT_HPKE_INFO = b"PicoKeys Vault enrollment v2"


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * NH
    return hmac.new(salt, ikm, hashlib.sha512).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, prev, counter = b"", b"", 1
    while len(out) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha512).digest()
        out += prev
        counter += 1
    return out[:length]


def labeled_extract(suite_id: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return hkdf_extract(salt, b"HPKE-v1" + suite_id + label + ikm)


def labeled_expand(suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled_info = struct.pack(">H", length) + b"HPKE-v1" + suite_id + label + info
    return hkdf_expand(prk, labeled_info, length)


def pub_bytes(private_key: x448.X448PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def x448_dh(private_key: x448.X448PrivateKey, peer_public_bytes: bytes) -> bytes:
    return private_key.exchange(x448.X448PublicKey.from_public_bytes(peer_public_bytes))


def hpke_auth_encap_seal(device_public: bytes, sender_private: x448.X448PrivateKey,
                          info: bytes, aad: bytes, plaintext: bytes):
    """RFC 9180 AuthEncap + Seal. Returns (enc, ciphertext_with_tag)."""
    esk = x448.X448PrivateKey.generate()
    enc = pub_bytes(esk)
    sender_public = pub_bytes(sender_private)

    dh = x448_dh(esk, device_public) + x448_dh(sender_private, device_public)
    kem_context = enc + device_public + sender_public

    eae_prk = labeled_extract(KEM_SUITE_ID, b"", b"eae_prk", dh)
    shared_secret = labeled_expand(KEM_SUITE_ID, eae_prk, b"shared_secret", kem_context, NH)

    psk_id_hash = labeled_extract(HPKE_SUITE_ID, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(HPKE_SUITE_ID, b"", b"info_hash", info)
    key_schedule_context = bytes([0x02]) + psk_id_hash + info_hash  # mode_auth = 0x02

    secret = labeled_extract(HPKE_SUITE_ID, shared_secret, b"secret", b"")
    key = labeled_expand(HPKE_SUITE_ID, secret, b"key", key_schedule_context, NK)
    base_nonce = labeled_expand(HPKE_SUITE_ID, secret, b"base_nonce", key_schedule_context, NN)

    ciphertext = AESGCM(key).encrypt(base_nonce, plaintext, aad)
    return enc, ciphertext


def build_enrollment_packet(cert_der: bytes, sender_private: x448.X448PrivateKey,
                             device_public: bytes, challenge: bytes,
                             kvault: bytes, label: str = "") -> bytes:
    """Matches picokeys_vault_enrollment_decode()'s expected wire format:
    [u16 cert_len][cert DER][enc: 56 bytes][ciphertext(kvault[+len+label]) || 16-byte tag]
    """
    label_bytes = label.encode()
    if len(label_bytes) > 64:
        raise ValueError("label too long (max 64 bytes)")
    plain = kvault + bytes([len(label_bytes)]) + label_bytes if label else kvault
    info = VAULT_ENROLLMENT_HPKE_INFO + challenge
    enc, ciphertext = hpke_auth_encap_seal(device_public, sender_private, info, cert_der, plain)
    return struct.pack(">H", len(cert_der)) + cert_der + enc + ciphertext


def vault_id(kvault: bytes) -> bytes:
    return hashlib.sha256(b"PicoKeys Vault ID v1" + kvault).digest()


# --- Kvault recovery envelope (local backup file, passphrase-protected) ---

def _derive_passphrase(passphrase: str, salt: bytes) -> bytes:
    return Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=64 * 1024).derive(passphrase.encode())


def create_enrollment_envelope(passphrase: str, kvault: bytes, leaf_key: x448.X448PrivateKey,
                                leaf_cert_der: bytes, label: str, device_serial: str) -> dict:
    import os
    salt = os.urandom(16)
    nonce = os.urandom(12)
    plain = json.dumps({
        "version": 1,
        "kvault": base64.b64encode(kvault).decode(),
        "x448_private": base64.b64encode(
            leaf_key.private_bytes_raw()
        ).decode(),
        "certificate": base64.b64encode(leaf_cert_der).decode(),
        "label": label,
        "device_serial": device_serial,
        "vault_id": vault_id(kvault).hex(),
        "created": datetime.datetime.utcnow().isoformat() + "Z",
    }, separators=(",", ":")).encode()
    ciphertext = AESGCM(_derive_passphrase(passphrase, salt)).encrypt(nonce, plain, b"PicoKeys Kvault envelope v1")
    return {
        "version": 1, "label": label, "device_serial": device_serial,
        "vault_id": vault_id(kvault).hex(),
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def open_enrollment_envelope(value: dict, passphrase: str) -> dict:
    salt = base64.b64decode(value["salt"])
    nonce = base64.b64decode(value["nonce"])
    plain = AESGCM(_derive_passphrase(passphrase, salt)).decrypt(
        nonce, base64.b64decode(value["ciphertext"]), b"PicoKeys Kvault envelope v1"
    )
    return json.loads(plain)
