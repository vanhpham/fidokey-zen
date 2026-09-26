#!/usr/bin/env python3
"""
picophy.py - Minimal, open client for the "rescue" configuration applet
that ships inside every Pico FIDO / Pico Keys firmware.

This talks to the SAME on-device protocol that the (paid) PicoKey App
uses. It is implemented here purely from the open-source firmware code
in pico-keys-sdk/src/rescue.c and pico-keys-sdk/src/fs/phy.c (AGPLv3),
which you already build and flash yourself.

Requires: pip install pyscard

Usage examples:
    python picophy.py list
    python picophy.py read
    python picophy.py set --product "My Personal Key"
    python picophy.py set --brightness 10
    python picophy.py set --vidpid 1209:beef
    python picophy.py set --product "My Key" --brightness 8

Notes:
- `set` does a read-modify-write: it reads the current config first, so
  fields you don't pass are preserved (the firmware replaces the WHOLE
  config blob on write, it does not merge).
- Every write requires pressing the physical button on the key within a
  few seconds of the command being sent (the firmware blocks waiting for
  it). If nothing happens, press the button.
- Only fields explicitly documented in phy.h are supported. Advanced
  fields (led_gpio, up_btn, enabled_curves, enabled_usb_itf, led_driver)
  are exposed too, but the defaults are normally fine - only change them
  if you know what you're doing, a wrong GPIO can make the LED/button
  stop working until you write a correct value back.
"""
import argparse
import struct
import sys

try:
    from smartcard.System import readers
    from smartcard.util import toHexString
except ImportError:
    sys.exit("Missing dependency. Install with: pip install pyscard")

RESCUE_AID = [0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21]

CLA = 0x80
INS_WRITE = 0x1C
INS_READ = 0x1E

P1_PHY = 0x01

# --- phy.h tag numbers -------------------------------------------------
PHY_VIDPID = 0x0
PHY_LED_GPIO = 0x4
PHY_LED_BTNESS = 0x5
PHY_OPTS = 0x6
PHY_UP_BTN = 0x8
PHY_USB_PRODUCT = 0x9
PHY_ENABLED_CURVES = 0xA
PHY_ENABLED_USB_ITF = 0xB
PHY_LED_DRIVER = 0xC

PHY_OPT_WCID = 0x1
PHY_OPT_DIMM = 0x2
PHY_OPT_DISABLE_POWER_RESET = 0x4
PHY_OPT_LED_STEADY = 0x8

PHY_USB_ITF_CCID = 0x1
PHY_USB_ITF_WCID = 0x2
PHY_USB_ITF_HID = 0x4
PHY_USB_ITF_KB = 0x8
PHY_USB_ITF_LWIP = 0x10
PHY_USB_ITF_ALL = PHY_USB_ITF_CCID | PHY_USB_ITF_WCID | PHY_USB_ITF_HID | PHY_USB_ITF_KB | PHY_USB_ITF_LWIP

PHY_CURVE_SECP256R1 = 0x1
PHY_CURVE_SECP384R1 = 0x2
PHY_CURVE_SECP521R1 = 0x4
PHY_CURVE_SECP256K1 = 0x8
PHY_CURVE_BP256R1 = 0x10
PHY_CURVE_BP384R1 = 0x20
PHY_CURVE_BP512R1 = 0x40
PHY_CURVE_ED25519 = 0x80
PHY_CURVE_ED448 = 0x100
PHY_CURVE_CURVE25519 = 0x200
PHY_CURVE_CURVE448 = 0x400
PHY_CURVE_ALL = 0x7FF

PHY_LED_DRIVER_PICO = 1
PHY_LED_DRIVER_PIMORONI = 2
PHY_LED_DRIVER_WS2812 = 3
PHY_LED_DRIVER_CYW43 = 4
PHY_LED_DRIVER_NEOPIXEL = 5
PHY_LED_DRIVER_NAMES = {
    PHY_LED_DRIVER_PICO: "pico (single LED)",
    PHY_LED_DRIVER_PIMORONI: "pimoroni",
    PHY_LED_DRIVER_WS2812: "ws2812",
    PHY_LED_DRIVER_CYW43: "cyw43",
    PHY_LED_DRIVER_NEOPIXEL: "neopixel (esp32)",
}

PHY_LED_ORDER_NAMES = {0: "RGB", 1: "RBG", 2: "GRB", 3: "GBR", 4: "BRG", 5: "BGR"}

# rescue.c INS_READ subcommands beyond PHY (P1_PHY = 0x01 above)
P1_FLASH_INFO = 0x02
P1_SECURE_BOOT_STATUS = 0x03


def connect():
    rs = readers()
    if not rs:
        sys.exit("No PC/SC smart card readers found. Is the key plugged in "
                  "and does Windows show it under Smart Card Readers?")
    # Prefer a reader whose name mentions the key, else just use the first one.
    reader = next((r for r in rs if "pico" in str(r).lower() or "fido" in str(r).lower()), rs[0])
    conn = reader.createConnection()
    conn.connect()
    return conn


def transmit(conn, apdu):
    data, sw1, sw2 = conn.transmit(apdu)
    if (sw1, sw2) != (0x90, 0x00):
        raise RuntimeError(f"Card error SW={sw1:02X}{sw2:02X} apdu={toHexString(apdu)}")
    return bytes(data)


def select_rescue(conn):
    apdu = [0x00, 0xA4, 0x04, 0x00, len(RESCUE_AID)] + RESCUE_AID
    return transmit(conn, apdu)


def read_phy_raw(conn):
    # CLA INS P1 P2 Le ; Le=0 asks for up to 256 bytes back
    apdu = [CLA, INS_READ, P1_PHY, 0x00, 0x00]
    return transmit(conn, apdu)


def write_phy_raw(conn, blob: bytes):
    if len(blob) > 255:
        raise ValueError("PHY blob too large for a short APDU")
    apdu = [CLA, INS_WRITE, P1_PHY, 0x00, len(blob)] + list(blob)
    print("Press the button on the key now to confirm the write...")
    return transmit(conn, apdu)


def parse_tlv(blob: bytes) -> dict:
    fields = {}
    i = 0
    while i + 2 <= len(blob):
        tag, tlen = blob[i], blob[i + 1]
        i += 2
        val = blob[i:i + tlen]
        i += tlen
        fields[tag] = val
    return fields


def build_tlv(fields: dict) -> bytes:
    out = b""
    for tag, val in fields.items():
        out += bytes([tag, len(val)]) + val
    return out


def describe(fields: dict):
    if PHY_VIDPID in fields and len(fields[PHY_VIDPID]) == 4:
        vid, pid = struct.unpack(">HH", fields[PHY_VIDPID])
        print(f"  VID:PID        = {vid:04x}:{pid:04x}")
    if PHY_USB_PRODUCT in fields:
        product = fields[PHY_USB_PRODUCT].rstrip(b"\x00").decode(errors="replace")
        print(f"  Product string = {product!r}")
    if PHY_LED_BTNESS in fields:
        print(f"  LED brightness = {fields[PHY_LED_BTNESS][0]} (0-15)")
    if PHY_LED_GPIO in fields:
        print(f"  LED GPIO       = {fields[PHY_LED_GPIO][0]}")
    if PHY_OPTS in fields and len(fields[PHY_OPTS]) == 2:
        opts = struct.unpack(">H", fields[PHY_OPTS])[0]
        flags = []
        if opts & PHY_OPT_WCID: flags.append("WCID")
        if opts & PHY_OPT_DIMM: flags.append("DIMM")
        if opts & PHY_OPT_DISABLE_POWER_RESET: flags.append("NO_POWER_RESET")
        if opts & PHY_OPT_LED_STEADY: flags.append("LED_STEADY")
        print(f"  Options        = 0x{opts:04x} ({', '.join(flags) or 'none'})")
    if PHY_LED_DRIVER in fields:
        print(f"  LED driver     = {fields[PHY_LED_DRIVER][0]}"
              + (f", order={fields[PHY_LED_DRIVER][1]}" if len(fields[PHY_LED_DRIVER]) > 1 else ""))
    if PHY_ENABLED_USB_ITF in fields:
        print(f"  Enabled ITFs   = 0x{fields[PHY_ENABLED_USB_ITF][0]:02x}")
    if PHY_ENABLED_CURVES in fields and len(fields[PHY_ENABLED_CURVES]) == 4:
        print(f"  Enabled curves = 0x{struct.unpack('>I', fields[PHY_ENABLED_CURVES])[0]:08x}")


def cmd_list(_args):
    for r in readers():
        print(r)


def cmd_read(_args):
    conn = connect()
    select_rescue(conn)
    blob = read_phy_raw(conn)
    fields = parse_tlv(blob)
    print(f"Raw ({len(blob)} bytes): {blob.hex()}")
    describe(fields)


def cmd_set(args):
    conn = connect()
    select_rescue(conn)
    blob = read_phy_raw(conn)
    fields = parse_tlv(blob)

    if args.product is not None:
        fields[PHY_USB_PRODUCT] = args.product.encode() + b"\x00"
    if args.brightness is not None:
        if not (0 <= args.brightness <= 15):
            sys.exit("brightness must be 0-15")
        fields[PHY_LED_BTNESS] = bytes([args.brightness])
    if args.vidpid is not None:
        vid_s, pid_s = args.vidpid.split(":")
        fields[PHY_VIDPID] = struct.pack(">HH", int(vid_s, 16), int(pid_s, 16))
    if args.dimm is not None:
        opts = struct.unpack(">H", fields.get(PHY_OPTS, b"\x00\x00"))[0]
        opts = (opts | PHY_OPT_DIMM) if args.dimm else (opts & ~PHY_OPT_DIMM)
        fields[PHY_OPTS] = struct.pack(">H", opts)
    if args.led_steady is not None:
        opts = struct.unpack(">H", fields.get(PHY_OPTS, b"\x00\x00"))[0]
        opts = (opts | PHY_OPT_LED_STEADY) if args.led_steady else (opts & ~PHY_OPT_LED_STEADY)
        fields[PHY_OPTS] = struct.pack(">H", opts)

    new_blob = build_tlv(fields)
    write_phy_raw(conn, new_blob)
    print("Written. The key blinks green 3 times to confirm.")
    print("Some fields (product string, VID/PID) only take effect after a reboot/replug.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(required=True)

    p = sub.add_parser("list", help="list PC/SC readers")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("read", help="read current PHY config from the key")
    p.set_defaults(func=cmd_read)

    p = sub.add_parser("set", help="change one or more PHY fields (read-modify-write)")
    p.add_argument("--product", help="USB product string shown to the OS")
    p.add_argument("--brightness", type=int, help="LED brightness 0-15")
    p.add_argument("--vidpid", help="VID:PID in hex, e.g. 1209:beef")
    p.add_argument("--dimm", type=lambda s: s.lower() in ("1", "true", "on", "yes"),
                    help="enable/disable smooth LED dimming (true/false)")
    p.add_argument("--led-steady", dest="led_steady",
                    type=lambda s: s.lower() in ("1", "true", "on", "yes"),
                    help="keep LED steady on instead of blinking (true/false)")
    p.set_defaults(func=cmd_set)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
