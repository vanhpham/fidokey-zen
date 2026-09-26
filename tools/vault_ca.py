#!/usr/bin/env python3
"""
vault_ca.py - Manage your OWN Vaulted Passkeys CA, replacing the one
embedded in pico-keys-sdk/src/vault.c (which only the official
enrollment service can sign for). This only matters if you build your
own firmware (see /workflows or the project's own build docs).

Subcommands:
  init-ca                      Create your CA keypair + self-signed cert (once).
  patch-vault-c                Splice your CA's DER cert into vault.c.
  make-leaf --serial SERIAL    Issue an enroller certificate for one device.

Usage:
    python vault_ca.py init-ca --out-dir ~/.config/picovault
    python vault_ca.py patch-vault-c --ca-cert ~/.config/picovault/ca_cert.der \
        --vault-c /path/to/pico-fido/pico-keys-sdk/src/vault.c
    python vault_ca.py make-leaf --serial 0123456789ABCDEF \
        --ca-key ~/.config/picovault/ca_key.pem --ca-cert ~/.config/picovault/ca_cert.der \
        --out-dir ~/.config/picovault
"""
import argparse
import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed448, x448
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key,
)
from cryptography.x509.oid import NameOID


def cmd_init_ca(args):
    out_dir = os.path.expanduser(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)
    key_path = os.path.join(out_dir, "ca_key.pem")
    cert_path = os.path.join(out_dir, "ca_cert.der")
    if (os.path.exists(key_path) or os.path.exists(cert_path)) and not args.force:
        sys.exit(f"Refusing to overwrite existing CA at {out_dir} (pass --force to replace it).\n"
                  "WARNING: replacing the CA invalidates every device already enrolled under the old one.")

    key = ed448.Ed448PrivateKey.generate()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, args.org),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{args.org} Vault CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=True, crl_sign=True,
                                      encipher_only=False, decipher_only=False), critical=True)
        .sign(key, None)
    )

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    os.chmod(key_path, 0o600)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(Encoding.DER))

    print(f"CA private key: {key_path}  (chmod 600 -- keep this offline/backed up; losing it means")
    print("                 you can never enroll another device under this vault identity again)")
    print(f"CA certificate:  {cert_path}")
    print()
    print("Next: python vault_ca.py patch-vault-c --ca-cert " + cert_path + " --vault-c <path to vault.c>")


def cmd_patch_vault_c(args):
    with open(os.path.expanduser(args.ca_cert), "rb") as f:
        ca_der = f.read()
    x509.load_der_x509_certificate(ca_der)  # sanity check it parses

    vault_c_path = os.path.expanduser(args.vault_c)
    with open(vault_c_path, "r") as f:
        content = f.read()

    marker = "picokeys_vault_ca_der[] = {"
    start = content.index(marker) + len(marker)
    end = content.index("};", start)
    old_region = content[start:end]

    c_bytes = ",\n    ".join(
        ", ".join(f"0x{b:02X}" for b in ca_der[i:i + 12])
        for i in range(0, len(ca_der), 12)
    )
    new_content = content[:start] + "\n    " + c_bytes + "\n" + content[end:]

    if not args.dry_run:
        backup_path = vault_c_path + ".orig-ca.bak"
        if not os.path.exists(backup_path):
            with open(backup_path, "w") as f:
                f.write(content)
            print(f"Backed up original to {backup_path}")
        with open(vault_c_path, "w") as f:
            f.write(new_content)
        print(f"Patched {vault_c_path}: replaced {len(old_region)} chars of CA DER with your own "
              f"{len(ca_der)}-byte certificate.")
        print("Now rebuild firmware with -DENABLE_EDDSA=1 and reflash.")
    else:
        print(f"[dry-run] would replace {len(old_region)} chars with your {len(ca_der)}-byte CA DER")


def cmd_make_leaf(args):
    with open(os.path.expanduser(args.ca_key), "rb") as f:
        ca_key = load_pem_private_key(f.read(), password=None)
    with open(os.path.expanduser(args.ca_cert), "rb") as f:
        ca_cert = x509.load_der_x509_certificate(f.read())

    leaf_key = x448.X448PrivateKey.generate()
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, args.org),
        x509.NameAttribute(NameOID.COMMON_NAME, f"enroller-{args.serial}"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=args.days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(args.serial)]), critical=False)
        .sign(ca_key, None)
    )

    out_dir = os.path.expanduser(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)
    key_path = os.path.join(out_dir, f"leaf_{args.serial}_key.pem")
    cert_path = os.path.join(out_dir, f"leaf_{args.serial}_cert.der")
    with open(key_path, "wb") as f:
        f.write(leaf_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    os.chmod(key_path, 0o600)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(Encoding.DER))

    print(f"Leaf (enroller) key:  {key_path}")
    print(f"Leaf (enroller) cert: {cert_path}  (SAN = {args.serial}, valid {args.days} days)")
    print()
    print("Next: python picovault.py enroll --leaf-key " + key_path + " --leaf-cert " + cert_path)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(required=True)

    p = sub.add_parser("init-ca", help="create your own vault CA (do this once)")
    p.add_argument("--out-dir", default="~/.config/picovault")
    p.add_argument("--org", default="MyOwnVault")
    p.add_argument("--force", action="store_true", help="overwrite an existing CA")
    p.set_defaults(func=cmd_init_ca)

    p = sub.add_parser("patch-vault-c", help="splice your CA cert into vault.c")
    p.add_argument("--ca-cert", required=True)
    p.add_argument("--vault-c", required=True)
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_patch_vault_c)

    p = sub.add_parser("make-leaf", help="issue an enroller cert for one device serial")
    p.add_argument("--serial", required=True, help="device serial, as picovault.py serial prints it")
    p.add_argument("--ca-key", required=True)
    p.add_argument("--ca-cert", required=True)
    p.add_argument("--out-dir", default="~/.config/picovault")
    p.add_argument("--org", default="MyOwnVault")
    p.add_argument("--days", type=int, default=3650)
    p.set_defaults(func=cmd_make_leaf)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
