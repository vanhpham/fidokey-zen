#!/usr/bin/env python3
"""
picofido_gui.py - Basic GUI for managing Pico Fido credentials and doing
Vaulted Passkeys backup/restore, built on top of picovault.py/vault_crypto.py.

Requires: pip install fido2 cryptography
(tkinter ships with standard Python on Windows; no extra install needed.)

Run:
    python picofido_gui.py
"""
import datetime
import json
import os
import tempfile
import tkinter as tk
import zipfile
from tkinter import ttk, filedialog, messagebox

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fido2.ctap2 import Ctap2, CredentialManagement
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.ctap import CtapError

import vault_crypto
import picovault

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".picofido_gui.json")


def load_config():
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass
from picovault import (
    vendor_call,
    VAULT_STATUS, VAULT_ENROLL_BEGIN, VAULT_ENROLL_FINISH, VAULT_EXPORT, VAULT_IMPORT, VAULT_UNENROLL,
    REQUIRED_PERMISSIONS,
)


# ---------------------------------------------------------------- helpers

def get_device():
    """picovault.get_device() calls sys.exit() on failure, which raises
    SystemExit -- a BaseException that slips right past `except Exception`
    and would silently kill the whole GUI window. Convert it here."""
    try:
        return picovault.get_device()
    except SystemExit as e:
        raise RuntimeError(str(e)) from None


def require_ok(code, response, what):
    """Same SystemExit -> normal exception conversion as get_device()."""
    if code != 0:
        raise RuntimeError(f"{what} failed: CTAP error 0x{code:02x} {response!r}")

def pin_token(dev, pin):
    protocol = PinProtocolV2()
    client_pin = ClientPin(Ctap2(dev), protocol)
    token = client_pin.get_pin_token(pin, permissions=REQUIRED_PERMISSIONS)
    return protocol, token


def read_device_serial():
    """Reads the hardware serial over the rescue CCID applet (pyscard)."""
    from smartcard.System import readers
    rs = readers()
    if not rs:
        raise RuntimeError("No PC/SC reader found for the rescue CCID interface.")
    reader = next((r for r in rs if "pico" in str(r).lower() or "fido" in str(r).lower()), rs[0])
    conn = reader.createConnection()
    conn.connect()
    aid = [0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21]
    data, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, len(aid)] + aid)
    if (sw1, sw2) != (0x90, 0x00):
        raise RuntimeError(f"SELECT failed: {sw1:02X}{sw2:02X}")
    data = bytes(data)
    return data[4:12].hex().upper()


# ---------------------------------------------------------------- app

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Pico Fido - Vault Manager")
        self.geometry("880x660")
        self.config_data = load_config()

        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="PIN:").pack(side="left")
        self.pin_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.pin_var, show="*", width=20).pack(side="left", padx=(4, 16))
        self.status_var = tk.StringVar(value="Chưa kiểm tra")
        ttk.Label(top, text="Trạng thái vault:").pack(side="left")
        ttk.Label(top, textvariable=self.status_var).pack(side="left", padx=(4, 16))
        ttk.Button(top, text="Kiểm tra trạng thái", command=self.on_status).pack(side="left")
        ttk.Button(top, text="Đọc serial", command=self.on_read_serial).pack(side="left", padx=(8, 0))

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        self.tab_creds = ttk.Frame(notebook)
        self.tab_backup = ttk.Frame(notebook)
        self.tab_enroll = ttk.Frame(notebook)
        notebook.add(self.tab_creds, text="Credentials")
        notebook.add(self.tab_backup, text="Sao lưu / Khôi phục")
        notebook.add(self.tab_enroll, text="Enroll")

        self._build_creds_tab()
        self._build_backup_tab()
        self._build_enroll_tab()

        ttk.Label(self, text="Log:").pack(anchor="w", padx=8)
        self.log_text = tk.Text(self, height=8, state="disabled")
        self.log_text.pack(fill="x", padx=8, pady=(0, 8))

    # ---- shared -----------------------------------------------------

    def log(self, msg):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def pin(self):
        p = self.pin_var.get()
        if not p:
            messagebox.showerror("Thiếu PIN", "Nhập PIN của thiết bị ở góc trên trước.")
            return None
        return p

    def on_status(self):
        try:
            dev = get_device()
            code, response = vendor_call(dev, VAULT_STATUS)
            require_ok(code, response, "status")
            vid = response.get(1, b"")
            self.status_var.set(f"Đã enroll (vault_id={vid[:6].hex()}...)" if vid else "Chưa enroll")
            self.log(f"status: enrolled={bool(vid)} vault_id={vid.hex() if vid else '-'} "
                     f"protocol={response.get(6)}")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))
            self.log(f"status FAILED: {e}")

    def on_read_serial(self):
        try:
            serial = read_device_serial()
            self.log(f"Serial thiết bị: {serial}")
            messagebox.showinfo("Serial", f"Serial: {serial}\n(dùng cho vault_ca.py make-leaf --serial ...)")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    # ---- Credentials tab ---------------------------------------------

    def _build_creds_tab(self):
        bar = ttk.Frame(self.tab_creds, padding=6)
        bar.pack(fill="x")
        ttk.Button(bar, text="Liệt kê tất cả", command=self.on_list_credentials).pack(side="left")
        ttk.Button(bar, text="Xuất (.pkv1) mục đã chọn", command=self.on_export_selected).pack(side="left", padx=8)
        ttk.Button(bar, text="Xóa mục đã chọn", command=self.on_delete_selected).pack(side="left")

        columns = ("rp", "user", "credential_id")
        self.tree = ttk.Treeview(self.tab_creds, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("rp", text="RP ID")
        self.tree.heading("user", text="User")
        self.tree.heading("credential_id", text="Credential ID (hex)")
        self.tree.column("rp", width=200)
        self.tree.column("user", width=150)
        self.tree.column("credential_id", width=450)
        self.tree.pack(fill="both", expand=True, padx=6, pady=6)

    def _enumerate_all_credentials(self, pin, dev=None):
        dev = dev or get_device()
        protocol, token = pin_token(dev, pin)
        ctap2 = Ctap2(dev)
        cm = CredentialManagement(ctap2, protocol, token)
        rows = []
        for rp_entry in cm.enumerate_rps():
            rp = rp_entry.get(CredentialManagement.RESULT.RP) or {}
            rp_id = rp.get("id", "?")
            rp_id_hash = rp_entry.get(CredentialManagement.RESULT.RP_ID_HASH)
            for cred_entry in cm.enumerate_creds(rp_id_hash):
                cred = cred_entry.get(CredentialManagement.RESULT.CREDENTIAL_ID) or {}
                user = cred_entry.get(CredentialManagement.RESULT.USER) or {}
                rows.append({"rp_id": rp_id, "user": user.get("name", "?"), "credential_id": cred.get("id")})
        return rows, dev, (protocol, token)

    def on_list_credentials(self):
        pin = self.pin()
        if not pin:
            return
        try:
            rows, _dev, _pin_ctx = self._enumerate_all_credentials(pin)
            for item in self.tree.get_children():
                self.tree.delete(item)
            for row in rows:
                cid = row["credential_id"] or b""
                self.tree.insert("", "end", values=(row["rp_id"], row["user"], cid.hex()))
            self.log(f"Đã liệt kê {len(rows)} credential.")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))
            self.log(f"list FAILED: {e}")

    def _selected_credential_id(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Chưa chọn", "Chọn 1 dòng trong bảng trước.")
            return None
        values = self.tree.item(sel[0], "values")
        return bytes.fromhex(values[2])

    def on_export_selected(self):
        pin = self.pin()
        if not pin:
            return
        credential_id = self._selected_credential_id()
        if credential_id is None:
            return
        out_path = filedialog.asksaveasfilename(defaultextension=".pkv1",
                                                 filetypes=[("PKV1 blob", "*.pkv1")])
        if not out_path:
            return
        try:
            dev = get_device()
            protocol, token = pin_token(dev, pin)
            code, response = vendor_call(dev, VAULT_EXPORT, {1: credential_id, 3: 2}, (protocol, token))
            require_ok(code, response, "export")
            with open(out_path, "wb") as f:
                f.write(response[1])
            self.log(f"Đã xuất {len(response[1])} bytes -> {out_path}")
            messagebox.showinfo("Xong", f"Đã xuất vào {out_path}")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))
            self.log(f"export FAILED: {e}")

    def on_delete_selected(self):
        pin = self.pin()
        if not pin:
            return
        credential_id = self._selected_credential_id()
        if credential_id is None:
            return
        if not messagebox.askyesno("Xác nhận",
                                    "Xóa credential này khỏi thiết bị? Nếu bạn chưa export/backup trước, "
                                    "thao tác này không thể hoàn tác."):
            return
        try:
            dev = get_device()
            protocol, token = pin_token(dev, pin)
            ctap2 = Ctap2(dev)
            cm = CredentialManagement(ctap2, protocol, token)
            cm.delete_cred({"id": credential_id, "type": "public-key"})
            self.log(f"Đã xóa credential {credential_id.hex()}")
            self.on_list_credentials()
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))
            self.log(f"delete FAILED: {e}")

    # ---- Backup / Restore tab ------------------------------------------

    def _build_backup_tab(self):
        frame = ttk.Frame(self.tab_backup, padding=10)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Sao lưu TẤT CẢ passkey + file Kvault envelope vào 1 file .zip duy nhất:",
                  font=("", 10, "bold")).pack(anchor="w", pady=(0, 4))

        row = ttk.Frame(frame)
        row.pack(fill="x", pady=(0, 4))
        ttk.Label(row, text="Kvault envelope:", width=16).pack(side="left")
        self.envelope_path_var = tk.StringVar(value=self._guess_envelope_path())
        ttk.Entry(row, textvariable=self.envelope_path_var, width=55).pack(side="left", padx=6)
        ttk.Button(row, text="Chọn...", command=self._pick_envelope).pack(side="left")

        row2 = ttk.Frame(frame)
        row2.pack(fill="x", pady=(0, 4))
        ttk.Label(row2, text="Lưu file zip vào:", width=16).pack(side="left")
        default_dir = self.config_data.get("last_backup_dir", os.getcwd())
        self.backup_dir_var = tk.StringVar(value=default_dir)
        ttk.Entry(row2, textvariable=self.backup_dir_var, width=55).pack(side="left", padx=6)
        ttk.Button(row2, text="Chọn...", command=self._pick_backup_dir).pack(side="left")

        self.open_after_var = tk.BooleanVar(value=self.config_data.get("open_after_backup", True))
        ttk.Checkbutton(frame, text="Mở thư mục chứa file sau khi sao lưu xong",
                        variable=self.open_after_var).pack(anchor="w", pady=(2, 8))

        self.backup_button = ttk.Button(frame, text="⬇ SAO LƯU TẤT CẢ NGAY", command=self.on_backup_zip)
        self.backup_button.pack(anchor="w")

        self.backup_progress = ttk.Progressbar(frame, mode="determinate", length=400)
        self.backup_progress.pack(anchor="w", pady=(8, 0), fill="x")
        self.backup_status_var = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.backup_status_var, foreground="#555").pack(anchor="w")

        ttk.Separator(frame).pack(fill="x", pady=16)

        ttk.Label(frame, text="Khôi phục từ 1 file .zip đã sao lưu trước đó:",
                  font=("", 10, "bold")).pack(anchor="w", pady=(0, 4))
        ttk.Button(frame, text="Khôi phục từ ZIP...", command=self.on_restore_zip).pack(anchor="w")
        ttk.Label(frame, foreground="#555",
                  text="Lưu ý: thiết bị đích phải đã được enroll với ĐÚNG Kvault trong file này\n"
                       "(dùng tab Enroll với tùy chọn 'Khôi phục Kvault cũ' nếu đây là board mới).")\
            .pack(anchor="w", pady=(8, 0))

    def _guess_envelope_path(self):
        remembered = self.config_data.get("last_envelope_path")
        if remembered and os.path.isfile(remembered):
            return remembered
        default = os.path.join(os.getcwd(), "kvault_envelope.json")
        return default if os.path.isfile(default) else ""

    def _pick_envelope(self):
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if path:
            self.envelope_path_var.set(path)

    def _pick_backup_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.backup_dir_var.set(path)

    def on_backup_zip(self):
        pin = self.pin()
        if not pin:
            return
        envelope_path = self.envelope_path_var.get()
        if not envelope_path or not os.path.isfile(envelope_path):
            if not messagebox.askyesno(
                "Không có envelope",
                "Không tìm thấy file kvault_envelope.json. Vẫn tiếp tục sao lưu passkey mà KHÔNG kèm "
                "file này? (bạn sẽ cần tự backup nó riêng, nếu không có nó thì các .pkv1 xuất ra "
                "không khôi phục được sang board mới)."
            ):
                return
            envelope_path = None

        backup_dir = self.backup_dir_var.get() or os.getcwd()
        os.makedirs(backup_dir, exist_ok=True)
        out_zip = os.path.join(backup_dir, f"pico-fido-backup-{datetime.datetime.now():%Y%m%d-%H%M%S}.zip")

        self.backup_button.configure(state="disabled")
        self.backup_progress.configure(value=0, maximum=1)
        self.backup_status_var.set("Đang kết nối thiết bị...")
        self.update_idletasks()
        try:
            rows, dev, pin_ctx = self._enumerate_all_credentials(pin)
            if not rows:
                messagebox.showwarning("Trống", "Không tìm thấy credential nào để sao lưu.")
                return
            self.backup_progress.configure(maximum=len(rows))
            manifest = {"created": datetime.datetime.utcnow().isoformat() + "Z", "items": []}
            with tempfile.TemporaryDirectory() as tmp:
                for i, row in enumerate(rows):
                    self.backup_status_var.set(f"Đang xuất {i + 1}/{len(rows)}: {row['rp_id']} ({row['user']})")
                    self.backup_progress.configure(value=i)
                    self.update_idletasks()
                    cred_id = row["credential_id"]
                    code, response = vendor_call(dev, VAULT_EXPORT, {1: cred_id, 3: 2}, pin_ctx)
                    if code != 0:
                        self.log(f"  bỏ qua {row['rp_id']}/{row['user']}: export lỗi 0x{code:02x}")
                        continue
                    blob = response[1]
                    fname = f"item_{i:03d}.pkv1"
                    with open(os.path.join(tmp, fname), "wb") as f:
                        f.write(blob)
                    manifest["items"].append({"file": fname, "rp_id": row["rp_id"], "user": row["user"],
                                               "credential_id": cred_id.hex()})
                    self.log(f"  xuất {row['rp_id']}/{row['user']} -> {fname}")
                self.backup_progress.configure(value=len(rows))
                self.backup_status_var.set("Đang đóng gói file zip...")
                self.update_idletasks()

                with open(os.path.join(tmp, "manifest.json"), "w") as f:
                    json.dump(manifest, f, indent=2)
                if envelope_path:
                    with open(envelope_path, "rb") as f:
                        envelope_bytes = f.read()
                    with open(os.path.join(tmp, "kvault_envelope.json"), "wb") as f:
                        f.write(envelope_bytes)

                with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
                    for name in os.listdir(tmp):
                        zf.write(os.path.join(tmp, name), name)

            self.config_data["last_envelope_path"] = envelope_path or self.config_data.get("last_envelope_path")
            self.config_data["last_backup_dir"] = backup_dir
            self.config_data["open_after_backup"] = self.open_after_var.get()
            save_config(self.config_data)

            self.backup_status_var.set(f"Xong: {len(manifest['items'])} credential -> {out_zip}")
            self.log(f"Đã sao lưu {len(manifest['items'])} credential"
                     f"{' + envelope' if envelope_path else ' (KHÔNG có envelope)'} -> {out_zip}")
            messagebox.showinfo("Xong", f"Đã tạo:\n{out_zip}\n\n{len(manifest['items'])} credential.")

            if self.open_after_var.get():
                try:
                    os.startfile(backup_dir)  # Windows only
                except Exception:
                    pass
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))
            self.log(f"backup FAILED: {e}")
        finally:
            self.backup_button.configure(state="normal")

    def on_restore_zip(self):
        pin = self.pin()
        if not pin:
            return
        zip_path = filedialog.askopenfilename(filetypes=[("Zip", "*.zip")])
        if not zip_path:
            return
        try:
            with tempfile.TemporaryDirectory() as tmp:
                with zipfile.ZipFile(zip_path) as zf:
                    zf.extractall(tmp)
                manifest_path = os.path.join(tmp, "manifest.json")
                if not os.path.isfile(manifest_path):
                    messagebox.showerror("File hỏng", "Không tìm thấy manifest.json trong zip.")
                    return
                with open(manifest_path) as f:
                    manifest = json.load(f)

                if not messagebox.askyesno("Xác nhận",
                                            f"Import {len(manifest['items'])} credential vào thiết bị đang cắm?"):
                    return

                dev = get_device()
                protocol, token = pin_token(dev, pin)
                ok, fail = 0, 0
                for item in manifest["items"]:
                    with open(os.path.join(tmp, item["file"]), "rb") as f:
                        blob = f.read()
                    code, response = vendor_call(dev, VAULT_IMPORT, {1: blob}, (protocol, token))
                    if code == 0:
                        ok += 1
                        self.log(f"  OK  {item['rp_id']}/{item['user']}")
                    else:
                        fail += 1
                        self.log(f"  LỖI {item['rp_id']}/{item['user']}: 0x{code:02x}")
                messagebox.showinfo("Xong", f"Import xong: {ok} thành công, {fail} lỗi.")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))
            self.log(f"restore FAILED: {e}")

    # ---- Enroll tab -----------------------------------------------------

    def _build_enroll_tab(self):
        frame = ttk.Frame(self.tab_enroll, padding=10)
        frame.pack(fill="both", expand=True)

        def file_row(label, is_save=False, filetypes=(("All", "*.*"),)):
            row = ttk.Frame(frame)
            row.pack(fill="x", pady=3)
            ttk.Label(row, text=label, width=28).pack(side="left")
            var = tk.StringVar()
            ttk.Entry(row, textvariable=var, width=45).pack(side="left", padx=6)
            cmd = (lambda: var.set(filedialog.asksaveasfilename(filetypes=filetypes) or var.get())) if is_save \
                else (lambda: var.set(filedialog.askopenfilename(filetypes=filetypes) or var.get()))
            ttk.Button(row, text="Chọn...", command=cmd).pack(side="left")
            return var

        self.leaf_key_var = file_row("Leaf key (.pem):", filetypes=[("PEM", "*.pem")])
        self.leaf_cert_var = file_row("Leaf cert (.der):", filetypes=[("DER", "*.der")])

        row = ttk.Frame(frame)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="Label:", width=28).pack(side="left")
        self.label_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.label_var, width=45).pack(side="left", padx=6)

        self.recover_var = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Khôi phục Kvault CŨ từ file (dùng khi enroll lại board mới)",
                        variable=self.recover_var).pack(anchor="w", pady=(10, 3))
        self.recover_envelope_var = file_row("  File envelope cũ:", filetypes=[("JSON", "*.json")])

        row = ttk.Frame(frame)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="Passphrase envelope:", width=28).pack(side="left")
        self.passphrase_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.passphrase_var, show="*", width=30).pack(side="left", padx=6)

        out_row = ttk.Frame(frame)
        out_row.pack(fill="x", pady=3)
        ttk.Label(out_row, text="Lưu envelope mới vào:", width=28).pack(side="left")
        self.out_envelope_var = tk.StringVar(value="kvault_envelope.json")
        ttk.Entry(out_row, textvariable=self.out_envelope_var, width=45).pack(side="left", padx=6)

        ttk.Label(frame, foreground="#a00",
                  text="Nhắc: rút cắm lại thiết bị, GIỮ nút BOOT liên tục >=10 giây, rồi khi vẫn đang giữ\n"
                       "bấm 'Bắt đầu enroll' bên dưới (trong vòng 60 giây kể từ lúc cắm lại).")\
            .pack(anchor="w", pady=(14, 6))
        ttk.Button(frame, text="Bắt đầu enroll", command=self.on_enroll).pack(anchor="w")

    def on_enroll(self):
        pin = self.pin()
        if not pin:
            return
        leaf_key_path = self.leaf_key_var.get()
        leaf_cert_path = self.leaf_cert_var.get()
        if not leaf_key_path or not leaf_cert_path:
            messagebox.showerror("Thiếu file", "Chọn leaf key + leaf cert trước (tạo bằng vault_ca.py make-leaf).")
            return
        try:
            with open(leaf_key_path, "rb") as f:
                leaf_key = load_pem_private_key(f.read(), password=None)
            if not isinstance(leaf_key, x448.X448PrivateKey):
                raise ValueError("leaf key không phải X448")
            with open(leaf_cert_path, "rb") as f:
                leaf_cert_der = f.read()
            x509.load_der_x509_certificate(leaf_cert_der)

            if self.recover_var.get():
                envelope_path = self.recover_envelope_var.get()
                passphrase = self.passphrase_var.get()
                if not envelope_path or not passphrase:
                    raise ValueError("Cần chọn file envelope cũ + nhập passphrase để khôi phục Kvault.")
                with open(envelope_path) as f:
                    value = json.load(f)
                plain = vault_crypto.open_enrollment_envelope(value, passphrase)
                import base64
                kvault = base64.b64decode(plain["kvault"])
                self.log("Đã giải mã Kvault cũ từ envelope, sẽ dùng lại Kvault này.")
            else:
                kvault = os.urandom(32)

            dev = get_device()
            protocol, token = pin_token(dev, pin)
            code, response = vendor_call(dev, VAULT_ENROLL_BEGIN, pin=(protocol, token))
            require_ok(code, response, "enroll begin")
            device_public, challenge = response[1], response[2]

            packet = vault_crypto.build_enrollment_packet(leaf_cert_der, leaf_key, device_public, challenge,
                                                            kvault, label=self.label_var.get())
            code, response = vendor_call(dev, VAULT_ENROLL_FINISH, {1: packet}, (protocol, token))
            require_ok(code, response, "enroll finish")
            expected = vault_crypto.vault_id(kvault)
            if response.get(1) != expected:
                raise RuntimeError("vault_id không khớp - KHÔNG tin tưởng enrollment này.")

            self.log(f"Enroll OK. vault_id={expected.hex()}")

            out_path = self.out_envelope_var.get() or "kvault_envelope.json"
            save_passphrase = self.passphrase_var.get() or None
            if not save_passphrase:
                import tkinter.simpledialog as sd
                save_passphrase = sd.askstring("Passphrase", "Đặt passphrase cho file envelope mới:", show="*")
            envelope = vault_crypto.create_enrollment_envelope(save_passphrase, kvault, leaf_key, leaf_cert_der,
                                                                self.label_var.get(), "")
            with open(out_path, "w") as f:
                json.dump(envelope, f, indent=2)
            self.log(f"Đã ghi envelope -> {out_path}")

            self.config_data["last_envelope_path"] = os.path.abspath(out_path)
            save_config(self.config_data)
            self.envelope_path_var.set(os.path.abspath(out_path))

            messagebox.showinfo("Enroll thành công", f"vault_id={expected.hex()}\nEnvelope: {out_path}")
        except CtapError as e:
            messagebox.showerror("CTAP lỗi", str(e))
            self.log(f"enroll FAILED: {e}")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))
            self.log(f"enroll FAILED: {e}")


if __name__ == "__main__":
    App().mainloop()
