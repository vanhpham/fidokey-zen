#!/usr/bin/env python3
"""
picovault.py - DIY client for Pico Fido's "Vaulted Passkeys" (PKV1) vendor
commands, talking raw CTAP2 vendor commands over CTAPHID (fido2 library).
This is the replacement for PicoKeyApp's vault screen; it requires your
device to run firmware built with -DENABLE_EDDSA=1 and (for enroll) your
own CA spliced into vault.c via vault_ca.py.

Requires: pip install fido2 cryptography

Subcommands:
  status                                  read vault status (no PIN needed)
  serial                                  print this device's hardware serial
  enroll   --leaf-key K --leaf-cert C --passphrase ... [--label ...]
  export   --credential-id HEX --algorithm N --out blob.bin
  import   --in blob.bin
  unenroll --confirm                      erase the vault (destructive)
  list-credentials --rp-id example.com    find a credential_id to export
"""
import argparse
import getpass
import os
import struct
import sys

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import x448
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, CredentialManagement
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.ctap import CtapError
from fido2 import cbor

import vault_crypto

CTAPHID_VENDOR_FIRST = 0x40
CTAP_VENDOR_CBOR = CTAPHID_VENDOR_FIRST + 1
CMD_VAULT = 0x05

VAULT_STATUS = 0x01
VAULT_ENROLL_BEGIN = 0x02
VAULT_ENROLL_FINISH = 0x03
VAULT_EXPORT = 0x04
VAULT_IMPORT = 0x05
VAULT_UNENROLL = 0x06

REQUIRED_PERMISSIONS = ClientPin.PERMISSION.AUTHENTICATOR_CFG | ClientPin.PERMISSION.CREDENTIAL_MGMT


def get_pin():
    """PICO_FIDO_PIN lets you pre-set the PIN before a timing-critical
    button-hold ceremony (enroll), so there is nothing left to type while
    you're holding the physical button. Only use it in a trusted shell --
    it stays in that process's environment for its lifetime."""
    return os.environ.get("PICO_FIDO_PIN") or getpass.getpass("PIN: ")


def get_device():
    dev = next(CtapHidDevice.list_devices(), None)
    if not dev:
        sys.exit("No CTAPHID FIDO device found. Is the key plugged in?")
    return dev


def get_pin_token(dev, pin):
    protocol = PinProtocolV2()
    client_pin = ClientPin(Ctap2(dev), protocol)
    token = client_pin.get_pin_token(pin, permissions=REQUIRED_PERMISSIONS)
    return protocol, token


def vendor_call(dev, subcommand, params=None, pin=None):
    arguments = {1: subcommand}
    raw_params = cbor.encode(params) if params is not None else b""
    if params is not None:
        arguments[2] = params
    if pin is not None:
        protocol, token = pin
        arguments[3] = protocol.VERSION
        arguments[4] = protocol.authenticate(token, b"\xff" * 32 + b"\x0d" + bytes([subcommand]) + raw_params)
    try:
        response = dev.call(CTAP_VENDOR_CBOR, bytes([CMD_VAULT]) + cbor.encode(arguments))
    except CtapError as error:
        return error.code, {}
    if not response:
        return 0, {}
    return response[0], cbor.decode(response[1:]) if len(response) > 1 else {}


def require_ok(code, response, what):
    if code != 0:
        sys.exit(f"{what} failed: CTAP error 0x{code:02x} {response!r}")


def cmd_status(args):
    dev = get_device()
    code, response = vendor_call(dev, VAULT_STATUS)
    require_ok(code, response, "status")
    vid = response.get(1, b"")
    if vid:
        print(f"Enrolled. vault_id = {vid.hex()}")
    else:
        print("Not enrolled (no vault on this device).")
    print(f"Enrollment protocol version: {response.get(6)}")


def cmd_serial(args):
    # The vault vendor commands don't expose the serial (they check it
    # internally). Read it via the rescue applet's SELECT response instead.
    try:
        from smartcard.System import readers
    except ImportError:
        sys.exit("Reading the serial needs pyscard: pip install pyscard")
    rs = readers()
    if not rs:
        sys.exit("No PC/SC reader found for the rescue CCID interface.")
    reader = next((r for r in rs if "pico" in str(r).lower() or "fido" in str(r).lower()), rs[0])
    conn = reader.createConnection()
    conn.connect()
    aid = [0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21]
    data, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, len(aid)] + aid)
    if (sw1, sw2) != (0x90, 0x00):
        sys.exit(f"SELECT failed: {sw1:02X}{sw2:02X}")
    data = bytes(data)
    if len(data) < 12:
        sys.exit(f"unexpected SELECT response: {data.hex()}")
    mcu, product, ver_major, ver_minor = data[0], data[1], data[2], data[3]
    serial = data[4:12]
    print(f"MCU={mcu} product={product} version={ver_major}.{ver_minor}")
    print(f"Serial (use this for --serial in vault_ca.py make-leaf): {serial.hex().upper()}")


def cmd_enroll(args):
    dev = get_device()
    pin = get_pin()
    pin_ctx = get_pin_token(dev, pin)

    with open(args.leaf_key, "rb") as f:
        leaf_key = load_pem_private_key(f.read(), password=None)
    if not isinstance(leaf_key, x448.X448PrivateKey):
        sys.exit("--leaf-key must be an X448 private key (from vault_ca.py make-leaf)")
    with open(args.leaf_cert, "rb") as f:
        leaf_cert_der = f.read()
    x509.load_der_x509_certificate(leaf_cert_der)  # sanity check

    code, response = vendor_call(dev, VAULT_ENROLL_BEGIN, pin=pin_ctx)
    require_ok(code, response, "enroll begin")
    device_public = response[1]
    challenge = response[2]
    if len(device_public) != 56 or len(challenge) != 32:
        sys.exit("unexpected ENROLL_BEGIN response shape")

    import os
    kvault = os.urandom(32)
    packet = vault_crypto.build_enrollment_packet(leaf_cert_der, leaf_key, device_public, challenge,
                                                    kvault, label=args.label or "")

    code, response = vendor_call(dev, VAULT_ENROLL_FINISH, {1: packet}, pin_ctx)
    require_ok(code, response, "enroll finish")
    returned_vault_id = response.get(1)
    expected = vault_crypto.vault_id(kvault)
    if returned_vault_id != expected:
        sys.exit(f"vault_id mismatch! device={returned_vault_id.hex() if returned_vault_id else None} "
                 f"expected={expected.hex()} -- something is wrong, do NOT trust this enrollment.")

    print(f"Enrolled. vault_id = {expected.hex()}")

    passphrase = args.passphrase or getpass.getpass("Passphrase to protect the local Kvault backup file: ")
    envelope = vault_crypto.create_enrollment_envelope(passphrase, kvault, leaf_key, leaf_cert_der,
                                                        args.label or "", args.serial or "")
    import json
    with open(args.out, "w") as f:
        json.dump(envelope, f, indent=2)
    print(f"Kvault recovery envelope written to {args.out}")
    print("BACK THIS FILE UP (and remember the passphrase) -- without it, PKV1 blobs exported")
    print("from this vault can never be decrypted again, even if you still own this device.")


def cmd_export(args):
    dev = get_device()
    pin = get_pin()
    pin_ctx = get_pin_token(dev, pin)
    credential_id = bytes.fromhex(args.credential_id)
    code, response = vendor_call(dev, VAULT_EXPORT, {1: credential_id, 3: args.algorithm}, pin_ctx)
    require_ok(code, response, "export")
    blob = response[1]
    with open(args.out, "wb") as f:
        f.write(blob)
    print(f"Exported {len(blob)}-byte PKV1 blob to {args.out}")


def cmd_import(args):
    dev = get_device()
    pin = get_pin()
    pin_ctx = get_pin_token(dev, pin)
    with open(args.file, "rb") as f:
        blob = f.read()
    code, response = vendor_call(dev, VAULT_IMPORT, {1: blob}, pin_ctx)
    require_ok(code, response, "import")
    print("Imported OK. The credential should now show up under its original RP.")


def cmd_unenroll(args):
    if not args.confirm:
        sys.exit("This permanently erases the vault key on this device (any un-exported PKV1 "
                 "blobs elsewhere become undecryptable). Pass --confirm to proceed.")
    dev = get_device()
    pin = get_pin()
    pin_ctx = get_pin_token(dev, pin)
    code, response = vendor_call(dev, VAULT_UNENROLL, pin=pin_ctx)
    require_ok(code, response, "unenroll")
    print("Vault erased.")


def cmd_list_credentials(args):
    dev = get_device()
    pin = get_pin()
    protocol, token = get_pin_token(dev, pin)
    ctap2 = Ctap2(dev)
    cm = CredentialManagement(ctap2, protocol, token)
    import hashlib
    rp_id_hash = hashlib.sha256(args.rp_id.encode()).digest()
    creds = cm.enumerate_creds(rp_id_hash)
    if not creds:
        print(f"No discoverable credentials found for rp_id={args.rp_id!r}")
        return
    for entry in creds:
        cred = entry.get(CredentialManagement.RESULT.CREDENTIAL_ID) or {}
        user = entry.get(CredentialManagement.RESULT.USER) or {}
        cred_id = cred.get("id")
        print(f"credential_id={cred_id.hex() if cred_id else '?'}  user={user.get('name')!r}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(required=True)

    p = sub.add_parser("status")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("serial", help="read the device's hardware serial (needed to issue its leaf cert)")
    p.set_defaults(func=cmd_serial)

    p = sub.add_parser("enroll")
    p.add_argument("--leaf-key", required=True)
    p.add_argument("--leaf-cert", required=True)
    p.add_argument("--label", default="")
    p.add_argument("--serial", default="")
    p.add_argument("--passphrase", default=None, help="omit to be prompted (recommended)")
    p.add_argument("--out", default="kvault_envelope.json")
    p.set_defaults(func=cmd_enroll)

    p = sub.add_parser("export")
    p.add_argument("--credential-id", required=True, help="hex-encoded credential id")
    p.add_argument("--algorithm", type=int, default=2, choices=[1, 2, 3, 4],
                    help="1=ChaChaPoly 2=AES-GCM(default) 3=both(CC first) 4=both(AES first)")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("import")
    p.add_argument("--file", required=True, dest="file")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("unenroll")
    p.add_argument("--confirm", action="store_true")
    p.set_defaults(func=cmd_unenroll)

    p = sub.add_parser("list-credentials")
    p.add_argument("--rp-id", required=True)
    p.set_defaults(func=cmd_list_credentials)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
