# Pico Fido personal tools

This folder holds a small toolkit built for one specific ESP32-S3 Pico Fido
key, to do two things without paying for [PicoKey
App](https://www.picokeys.com/picokeyapp/):

1. **`picophy.py`** — read/change the device's runtime `phy_data` config
   (USB product string, VID/PID, LED brightness/GPIO, enabled interfaces...)
   over the CCID "rescue" applet, without rebuilding firmware.
2. **`vault_ca.py` / `vault_crypto.py` / `picovault.py` / `picofido_gui.py`**
   — a from-scratch, open re-implementation of Pico Fido's "Vaulted
   Passkeys" (PKV1) backup/restore feature, using your **own** certificate
   authority instead of the official one (see [Why a custom
   CA](#why-a-custom-ca) below).

All of this talks to the device using protocols documented in
`pico-keys-sdk/src/rescue.c`, `pico-keys-sdk/src/vault.c` and
`src/fido/fido_vault.c` (all AGPLv3/GPLv3, in this same repo) — nothing here
reverse-engineers anything closed-source.

## Requirements

```
pip install fido2 cryptography pyscard
```

- `fido2` / `pyscard` talk to the two USB interfaces the key exposes: CTAPHID
  (FIDO2 vendor commands) and CCID (the "rescue" config applet).
- **Windows:** accessing the FIDO CTAPHID interface directly (not through the
  OS's own WebAuthn API) requires the process to run **elevated
  (Administrator)** — otherwise device enumeration silently returns empty.
  This is a Windows FIDO security restriction, not a bug in these tools.
- tkinter (for `picofido_gui.py`) ships with the standard python.org and
  Microsoft Store builds of Python; nothing extra to install.

## `picophy.py` — runtime device config

```
python picophy.py list                      # list PC/SC readers
python picophy.py read                       # dump current phy_data
python picophy.py set --product "My Key"     # USB product string
python picophy.py set --brightness 10        # LED brightness (0-15)
python picophy.py set --vidpid 1209:beef     # VID:PID
python picophy.py set --led-steady true      # steady LED instead of blinking
```

Every `set` requires pressing the physical button on the key within a few
seconds (the firmware blocks on it, over CCID `INS_WRITE` on the rescue
applet). `set` always does a read-modify-write, so unspecified fields are
preserved.

## Why a custom CA

Pico Fido's Vaulted Passkeys feature (PKV1) lets you export/import
individual passkeys as encrypted blobs, so a lost/dead device doesn't lose
your resident credentials. Setting it up (the *enrollment* ceremony) is
gated by an X.509 certificate chain that must verify against a CA baked
into the firmware (`picokeys_vault_ca_der` in `pico-keys-sdk/src/vault.c`).
The official CA's private key belongs to the project's own enrollment
service (PicoKeyApp) — you can't forge a certificate against it.

Since you build your own firmware from source anyway, you can be your own
CA instead: swap that constant for one you generate and control, then issue
yourself an "enroller" certificate for your device's exact serial. The
day-to-day export/import operations are plain symmetric crypto (HKDF +
AEAD) and don't involve any CA at all — only the one-time enrollment does.

This requires firmware built with **`-DENABLE_EDDSA=1`**: the enrollment
certificate chain uses Ed448/X448 (RFC 8410 / RFC 9180 HPKE), which the
default vendored mbedtls does not support signature verification for. With
that flag, CMake fetches `github.com/polhenarejos/mbedtls` (branch
`v3.6.7-eddsa`) instead of upstream mbedtls — see
`pico-keys-sdk/cmake/deps.cmake`.

**This whole path was validated end to end**, both against a from-scratch
Python re-implementation of the device's HPKE-Auth decode function *and*
against the actual `vault.c` compiled standalone with the real mbedtls
fork, before ever touching real hardware — and then against the real
device. It has since been used successfully to enroll and to
export/import a live credential on the actual key this toolkit was built
for.

## One-time setup: your own CA

```
python vault_ca.py init-ca --out-dir ~/.picovault
```

Writes `ca_key.pem` (Ed448 private key — **back this up offline, chmod
600**; losing it means you can never enroll another device under this
identity again) and `ca_cert.der`.

Splice your CA's certificate into the firmware source:

```
python vault_ca.py patch-vault-c --ca-cert ~/.picovault/ca_cert.der \
    --vault-c ../pico-keys-sdk/src/vault.c
```

(Keeps a `.orig-ca.bak` backup of the original file next to it, once.)

Then build with EdDSA support and reflash:

```
idf.py -DENABLE_EDDSA=1 build
idf.py -p <PORT> flash
```

## Per-device enroller certificate

Read the device's hardware serial (over the rescue CCID applet):

```
python picovault.py serial
```

Issue a certificate for exactly that serial, signed by your CA:

```
python vault_ca.py make-leaf --serial <SERIAL> \
    --ca-key ~/.picovault/ca_key.pem --ca-cert ~/.picovault/ca_cert.der \
    --out-dir ~/.picovault
```

## Enrollment (one-time per device)

The firmware requires **physical presence** for this step: the ceremony
only succeeds within 60 seconds of the device powering up, *and* only
while the **BOOT button (GPIO0)** has been held continuously for at least
10 seconds (`pico-keys-sdk/src/vault.c`,
`PICOKEYS_VAULT_ENROLL_WINDOW_MS`/`PICOKEYS_VAULT_ENROLL_HOLD_MS`). This is
deliberate — nobody can silently re-enroll your vault over USB.

Practical sequence: unplug/replug the key, immediately hold BOOT, keep
holding, and once ~10s have passed run (still holding):

```
python picovault.py enroll --leaf-key ~/.picovault/leaf_<SERIAL>_key.pem \
    --leaf-cert ~/.picovault/leaf_<SERIAL>_cert.der --label "my-backup"
```

Setting `PICO_FIDO_PIN` beforehand avoids losing time to an interactive PIN
prompt inside that 60-second window:

```
$env:PICO_FIDO_PIN = "..."     # PowerShell; unset when done
```

This writes `kvault_envelope.json` — a passphrase-protected file containing
the random `Kvault` master key this vault now uses. **Back this file and
its passphrase up somewhere else.** Without it, no `.pkv1` blob exported
from this vault can ever be decrypted again, even on the original device.

## Day to day: the GUI

```
python picofido_gui.py
```

One window, six tabs — covers everything PicoKeyApp's device screens do, all
implemented directly against the open protocols in this repo (rescue CCID
applet + standard CTAP2), nothing closed-source involved:

- **Thông tin (Device Info)** — MCU/product/firmware version/serial (rescue
  applet SELECT), flash usage, Secure Boot status.
- **Cấu hình thiết bị (Device Settings)** — full `phy_data` editor over the
  rescue CCID applet: USB product string, VID/PID, LED brightness/GPIO/driver
  /color order, which USB interfaces are enabled (CCID/WebCCID/HID/keyboard
  /network), which crypto curves are enabled, and the option flags (WCID,
  smooth dimming, steady LED, skip-reset-on-power-loss). Read-modify-write,
  same as `picophy.py` but as a form; writing needs a physical button press.
- **Credentials** — list every resident credential (RP / user / credential
  id), export one to a `.pkv1` file, or delete one.
- **Sao lưu / Khôi phục (Backup / Restore)** — one button exports *every*
  credential plus the `Kvault` envelope into a single timestamped `.zip`;
  another button restores everything from such a zip. Remembers the
  envelope path and output folder between runs.
- **Enroll** — same ceremony as above, from a form; has a checkbox to
  **recover an existing `Kvault`** from a saved envelope instead of
  generating a new one, which is what you need when moving to a
  replacement board (see below).
- **PIN & Nâng cao (PIN & Advanced)** — set/change the CTAP2 PIN; standard
  `authenticatorConfig` toggles (Enterprise Attestation, Always-UV,
  minimum PIN length); factory reset (`authenticatorReset` — only works in
  the first 10 seconds after power-up, and needs a button press, per
  `src/fido/cbor_reset.c`).

Or the CLI directly: `picovault.py {status,serial,enroll,export,import,unenroll,list-credentials}`
and `picophy.py {list,read,set}`.

## Recovering onto a replacement board

If the original device is lost/broken:

1. Get the new board's serial (`picovault.py serial` against the new board).
2. Issue it a leaf certificate: `vault_ca.py make-leaf --serial <NEW_SERIAL> ...`.
3. Enroll the new board **with the old `Kvault`**, not a fresh random one —
   in the GUI, tick "Khôi phục Kvault CŨ" and point it at your saved
   `kvault_envelope.json` + passphrase.
4. Restore your `.pkv1` backups (or the backup zip) onto the new board —
   they will decrypt correctly because the underlying `Kvault` is the same.

## Files you must keep safe (outside of any git repo)

| File | Loss means |
|---|---|
| `~/.picovault/ca_key.pem` | Can never issue a new leaf cert / enroll another device under this identity |
| `~/.picovault/leaf_<serial>_key.pem` | Have to reissue (cheap, just needs the CA key) |
| `kvault_envelope.json` + its passphrase | Existing `.pkv1` backups become permanently undecryptable |
| Any `.pkv1` / backup `.zip` | Loses that specific backed-up credential (only matters if the original is also gone) |

None of these are meant to live inside this repository — `.gitignore` here
excludes the patterns this toolkit produces by default, but always check
`git status` before committing if you move files around.
