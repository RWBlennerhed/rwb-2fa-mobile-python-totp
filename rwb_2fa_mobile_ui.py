# ============================================================
# Project: RWB 2FA Mobile UI
# Version: 0.3
# Year: 2026
#
# Author: Robert William Blennerhed
# Developed in collaboration with ChatGPT
# RWB Tech Lab
#
# Description:
# Mobile-friendly local TOTP app for Pydroid 3.
#
# New in v0.3:
# - Search
# - Sort A-Z / Z-A
# - Manual Lock
# - Import Backup
# - Export Backup
# - Duplicate Check
#
# Existing features:
# - encrypted local vault
# - add / edit / delete accounts
# - safe paste for secret
# - show/hide secret
# - copy current code
# - smart import from otpauth:// URI
# - improved startup/unlock flow
# - Android keyboard helper
# - debug account info
# - auto-lock after inactivity
#
# Important:
# Use "Paste Secret" button instead of normal Android paste
# inside the secret field to avoid duplicated paste behavior.
# ============================================================

import tkinter as tk
from tkinter import messagebox, filedialog
import base64
import hashlib
import hmac
import json
import os
import struct
import time
from urllib.parse import urlparse, parse_qs, unquote

from cryptography.fernet import Fernet

try:
    from jnius import autoclass
    ANDROID_AVAILABLE = True
except Exception:
    ANDROID_AVAILABLE = False

VAULT_FILE = "rwb_2fa_vault.dat"
AUTO_LOCK_SECONDS = 180


# ------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------
def clean_secret_text(text: str) -> str:
    return "".join(text.split()).upper()


def generate_totp(secret_base32, interval=30, digits=6):
    secret_base32 = clean_secret_text(secret_base32)

    missing_padding = len(secret_base32) % 8
    if missing_padding:
        secret_base32 += "=" * (8 - missing_padding)

    key = base64.b32decode(secret_base32, casefold=True)

    counter = int(time.time() // interval)
    msg = struct.pack(">Q", counter)

    hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()

    offset = hmac_hash[-1] & 0x0F
    truncated = hmac_hash[offset:offset + 4]
    code_int = struct.unpack(">I", truncated)[0] & 0x7FFFFFFF

    code = code_int % (10 ** digits)
    return str(code).zfill(digits)


def seconds_remaining(interval=30):
    return interval - (int(time.time()) % interval)


def derive_key_from_password(password: str) -> bytes:
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_data(data: bytes, password: str) -> bytes:
    key = derive_key_from_password(password)
    return Fernet(key).encrypt(data)


def decrypt_data(token: bytes, password: str) -> bytes:
    key = derive_key_from_password(password)
    return Fernet(key).decrypt(token)


def parse_otpauth_uri(uri: str):
    uri = uri.strip()
    parsed = urlparse(uri)

    if parsed.scheme != "otpauth":
        raise ValueError("Not a valid otpauth URI")

    qs = parse_qs(parsed.query)
    secret = clean_secret_text(qs.get("secret", [""])[0].strip())
    issuer = qs.get("issuer", [""])[0].strip()

    label = unquote(parsed.path.lstrip("/")).strip()
    if ":" in label:
        _, account_name = label.split(":", 1)
        account_name = account_name.strip()
    else:
        account_name = label if label else "Imported Account"

    if issuer and account_name:
        display_name = f"{issuer} - {account_name}"
    elif account_name:
        display_name = account_name
    elif issuer:
        display_name = issuer
    else:
        display_name = "Imported Account"

    if not secret:
        raise ValueError("No secret found in otpauth URI")

    return display_name, secret


# ------------------------------------------------------------
# APP
# ------------------------------------------------------------
class RWB2FAMobileUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RWB 2FA Mobile UI v0.3")
        self.root.geometry("520x920")
        self.root.configure(bg="#111111")

        self.accounts = []
        self.selected_index = None
        self.master_password = None
        self.is_unlocked = False
        self.unlock_window = None
        self.last_activity = time.time()

        self.search_var = tk.StringVar()
        self.sort_mode = "az"   # az / za
        self.filtered_indices = []

        self.build_ui()
        self.set_buttons_enabled(False)
        self.bind_activity_events()
        self.root.after(200, self.ask_password_and_load)

    # --------------------------------------------------------
    # ACTIVITY / AUTO LOCK
    # ------------------------------------------------------------
    def bind_activity_events(self):
        self.root.bind_all("<Button>", self.mark_activity)
        self.root.bind_all("<Key>", self.mark_activity)

    def mark_activity(self, event=None):
        self.last_activity = time.time()

    def check_auto_lock(self):
        if not self.is_unlocked:
            return

        idle = time.time() - self.last_activity
        if idle >= AUTO_LOCK_SECONDS:
            self.lock_vault()
            return

        self.root.after(5000, self.check_auto_lock)

    def lock_vault(self):
        self.accounts = []
        self.filtered_indices = []
        self.selected_index = None
        self.master_password = None
        self.is_unlocked = False
        self.set_buttons_enabled(False)
        self.listbox.delete(0, tk.END)
        self.count_label.config(text="Accounts: 0")
        self.timer_label.config(text="Locked")
        self.status_label.config(text="Vault locked")
        self.ask_password_and_load()

    # --------------------------------------------------------
    # UI HELPERS
    # ------------------------------------------------------------
    def set_buttons_enabled(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        for btn in [
            self.btn_add,
            self.btn_edit,
            self.btn_import_otpauth,
            self.btn_delete,
            self.btn_copy_code,
            self.btn_show_secret,
            self.btn_debug,
            self.btn_export,
            self.btn_import_backup,
            self.btn_lock,
            self.btn_sort,
        ]:
            btn.config(state=state)

        self.entry_search.config(state=state)

    def safe_lift_window(self, win):
        try:
            win.lift()
            win.attributes("-topmost", True)
            win.after(300, lambda: win.attributes("-topmost", False))
        except Exception:
            pass

    def show_android_keyboard(self, widget=None):
        try:
            if widget is not None:
                widget.focus_force()
                try:
                    widget.icursor("end")
                except Exception:
                    pass
        except Exception:
            pass

        if not ANDROID_AVAILABLE:
            return

        try:
            PythonActivity = autoclass("org.kivy.android.PythonActivity")
            Context = autoclass("android.content.Context")
            activity = PythonActivity.mActivity
            imm = activity.getSystemService(Context.INPUT_METHOD_SERVICE)
            current_view = activity.getCurrentFocus()

            if current_view is not None:
                imm.showSoftInput(current_view, 0)
            else:
                decor = activity.getWindow().getDecorView()
                imm.showSoftInput(decor, 0)
        except Exception:
            pass

    def bind_keyboard_support(self, entry_widget, button_widget=None):
        entry_widget.bind(
            "<Button-1>",
            lambda e: self.root.after(120, lambda: self.show_android_keyboard(entry_widget))
        )
        entry_widget.bind(
            "<FocusIn>",
            lambda e: self.root.after(120, lambda: self.show_android_keyboard(entry_widget))
        )
        if button_widget is not None:
            button_widget.config(command=lambda: self.show_android_keyboard(entry_widget))

    def show_large_message(self, title, content):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("800x600")
        win.configure(bg="#111111")
        self.safe_lift_window(win)

        text = tk.Text(
            win,
            font=("Courier New", 10),
            bg="#1d1d1d",
            fg="white",
            insertbackground="white",
            wrap="word"
        )
        text.pack(fill="both", expand=True, padx=10, pady=10)
        text.insert("1.0", content)
        text.config(state="disabled")

        tk.Button(
            win,
            text="Close",
            command=win.destroy,
            font=("Arial", 10, "bold"),
            bg="#444444",
            fg="white"
        ).pack(pady=(0, 10))

    def normalize_accounts(self, accounts_list):
        normalized = []
        for acc in accounts_list:
            name = str(acc.get("name", "")).strip()
            secret = clean_secret_text(str(acc.get("secret", "")))
            if name and secret:
                normalized.append({"name": name, "secret": secret})
        return normalized

    def account_exists(self, name, secret, ignore_index=None):
        clean_name = name.strip().lower()
        clean_secret = clean_secret_text(secret)

        for i, acc in enumerate(self.accounts):
            if ignore_index is not None and i == ignore_index:
                continue

            same_name = acc["name"].strip().lower() == clean_name
            same_secret = clean_secret_text(acc["secret"]) == clean_secret

            if same_name or same_secret:
                return True
        return False

    # --------------------------------------------------------
    # PASSWORD / LOAD / SAVE
    # ------------------------------------------------------------
    def ask_password_and_load(self):
        if self.unlock_window is not None:
            return

        win = tk.Toplevel(self.root)
        self.unlock_window = win
        win.title("Unlock Vault")
        win.geometry("820x690")
        win.configure(bg="#111111")
        win.transient(self.root)

        self.safe_lift_window(win)

        tk.Label(
            win,
            text="Enter vault password",
            font=("Arial", 10, "bold"),
            bg="#111111",
            fg="white"
        ).pack(pady=(20, 10))

        pw_row = tk.Frame(win, bg="#111111")
        pw_row.pack(fill="x", padx=20, pady=10)

        entry = tk.Entry(pw_row, font=("Arial", 10), show="*")
        entry.pack(side="left", fill="x", expand=True)

        btn_pw_kb = tk.Button(pw_row, text="⌨", width=4, bg="#444444", fg="white")
        btn_pw_kb.pack(side="left", padx=(8, 0))

        self.bind_keyboard_support(entry, btn_pw_kb)
        entry.focus_force()
        win.after(250, lambda: self.show_android_keyboard(entry))

        tk.Label(
            win,
            text="New file: password creates vault\nExisting file: password unlocks vault",
            font=("Arial", 10),
            bg="#111111",
            fg="#bbbbbb"
        ).pack(pady=5)

        def unlock():
            password = entry.get().strip()
            if not password:
                messagebox.showerror("Error", "Password required", parent=win)
                return

            self.master_password = password

            if os.path.exists(VAULT_FILE):
                try:
                    with open(VAULT_FILE, "rb") as f:
                        encrypted = f.read()
                    decrypted = decrypt_data(encrypted, password)
                    self.accounts = self.normalize_accounts(json.loads(decrypted.decode("utf-8")))
                except Exception:
                    messagebox.showerror("Error", "Wrong password or damaged vault", parent=win)
                    return
            else:
                self.accounts = []

            self.is_unlocked = True
            self.mark_activity()
            self.update_listbox()
            self.set_buttons_enabled(True)
            self.status_label.config(text="Vault unlocked")
            self.timer_label.config(text=f"Refresh in: {seconds_remaining()}")

            try:
                win.destroy()
            except Exception:
                pass

            self.unlock_window = None
            self.refresh_codes()
            self.root.after(5000, self.check_auto_lock)

        def create_new_empty_vault():
            password = entry.get().strip()
            if not password:
                messagebox.showerror("Error", "Password required", parent=win)
                return

            self.master_password = password
            self.accounts = []
            self.save_accounts()

            self.is_unlocked = True
            self.mark_activity()
            self.update_listbox()
            self.set_buttons_enabled(True)
            self.status_label.config(text="New vault created")
            self.timer_label.config(text=f"Refresh in: {seconds_remaining()}")

            try:
                win.destroy()
            except Exception:
                pass

            self.unlock_window = None
            self.refresh_codes()
            self.root.after(5000, self.check_auto_lock)

        btn_row = tk.Frame(win, bg="#111111")
        btn_row.pack(fill="x", padx=16, pady=16)

        tk.Button(
            btn_row, text="Unlock", command=unlock,
            font=("Arial", 10, "bold"), bg="#2d6cdf", fg="white", height=2
        ).pack(side="left", expand=True, fill="x", padx=4)

        if not os.path.exists(VAULT_FILE):
            tk.Button(
                btn_row, text="Create Vault", command=create_new_empty_vault,
                font=("Arial", 10, "bold"), bg="#3a9d5d", fg="white", height=2
            ).pack(side="left", expand=True, fill="x", padx=4)

        entry.bind("<Return>", lambda e: unlock())

    def save_accounts(self):
        if self.master_password is None:
            return

        cleaned = self.normalize_accounts(self.accounts)
        raw = json.dumps(cleaned, indent=2, ensure_ascii=False).encode("utf-8")
        encrypted = encrypt_data(raw, self.master_password)
        with open(VAULT_FILE, "wb") as f:
            f.write(encrypted)

    # --------------------------------------------------------
    # UI BUILD
    # ------------------------------------------------------------
    def build_ui(self):
        tk.Label(
            self.root,
            text="RWB 2FA Mobile UI v0.3",
            font=("Arial", 00, "bold"),
            bg="#111111",
            fg="white"
        ).pack(pady=(12, 6))

        self.count_label = tk.Label(
            self.root, text="Accounts: 0",
            font=("Arial", 10), bg="#111111", fg="#bbbbbb"
        )
        self.count_label.pack()

        self.timer_label = tk.Label(
            self.root, text="Locked",
            font=("Arial", 10, "bold"), bg="#111111", fg="#66ff66"
        )
        self.timer_label.pack(pady=(6, 8))

        # Search row
        search_row = tk.Frame(self.root, bg="#111111")
        search_row.pack(fill="x", padx=10, pady=(2, 6))

        self.entry_search = tk.Entry(
            search_row,
            textvariable=self.search_var,
            font=("Arial", 10),
            bg="#1d1d1d",
            fg="white",
            insertbackground="white"
        )
        self.entry_search.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.entry_search.bind("<KeyRelease>", lambda e: self.update_listbox())

        self.btn_sort = tk.Button(
            search_row,
            text="Sort A-Z",
            command=self.toggle_sort,
            font=("Arial", 10, "bold"),
            bg="#555555",
            fg="white",
            height=1
        )
        self.btn_sort.pack(side="left", padx=(0, 6))

        self.btn_lock = tk.Button(
            search_row,
            text="Lock",
            command=self.lock_vault,
            font=("Arial", 10, "bold"),
            bg="#7a2020",
            fg="white",
            height=1
        )
        self.btn_lock.pack(side="left")

        row1 = tk.Frame(self.root, bg="#111111")
        row1.pack(fill="x", padx=10, pady=4)

        self.btn_add = tk.Button(
            row1, text="Add", command=self.add_account_dialog,
            font=("Arial", 10, "bold"), bg="#2d6cdf", fg="white", height=2
        )
        self.btn_add.pack(side="left", expand=True, fill="x", padx=4)

        self.btn_edit = tk.Button(
            row1, text="Edit", command=self.edit_selected_account,
            font=("Arial", 10, "bold"), bg="#3f7fdd", fg="white", height=2
        )
        self.btn_edit.pack(side="left", expand=True, fill="x", padx=4)

        self.btn_import_otpauth = tk.Button(
            row1, text="Import", command=self.smart_import_dialog,
            font=("Arial", 10, "bold"), bg="#6b4fd3", fg="white", height=2
        )
        self.btn_import_otpauth.pack(side="left", expand=True, fill="x", padx=4)

        self.btn_delete = tk.Button(
            row1, text="Delete", command=self.delete_selected,
            font=("Arial", 10, "bold"), bg="#a83232", fg="white", height=2
        )
        self.btn_delete.pack(side="left", expand=True, fill="x", padx=4)

        row2 = tk.Frame(self.root, bg="#111111")
        row2.pack(fill="x", padx=10, pady=4)

        self.btn_copy_code = tk.Button(
            row2, text="Copy", command=self.copy_selected_code,
            font=("Arial", 10, "bold"), bg="#3a9d5d", fg="white", height=2
        )
        self.btn_copy_code.pack(side="left", expand=True, fill="x", padx=4)

        self.btn_show_secret = tk.Button(
            row2, text="Show Secret", command=self.show_selected_secret,
            font=("Arial", 10, "bold"), bg="#555555", fg="white", height=2
        )
        self.btn_show_secret.pack(side="left", expand=True, fill="x", padx=4)

        self.btn_debug = tk.Button(
            row2, text="Debug", command=self.debug_selected_account,
            font=("Arial", 10, "bold"), bg="#888800", fg="white", height=2
        )
        self.btn_debug.pack(side="left", expand=True, fill="x", padx=4)

        row3 = tk.Frame(self.root, bg="#111111")
        row3.pack(fill="x", padx=10, pady=4)

        self.btn_export = tk.Button(
            row3, text="Export", command=self.export_backup,
            font=("Arial", 10, "bold"), bg="#8a4f20", fg="white", height=2
        )
        self.btn_export.pack(side="left", expand=True, fill="x", padx=4)

        self.btn_import_backup = tk.Button(
            row3, text="Import Backup", command=self.import_backup,
            font=("Arial", 10, "bold"), bg="#205a8a", fg="white", height=2
        )
        self.btn_import_backup.pack(side="left", expand=True, fill="x", padx=4)

        list_frame = tk.Frame(self.root, bg="#111111")
        list_frame.pack(fill="both", expand=True, padx=10, pady=(8, 8))

        self.listbox = tk.Listbox(
            list_frame,
            font=("Courier New", 10),
            bg="#1d1d1d",
            fg="white",
            selectbackground="#4444aa",
            selectforeground="white",
            activestyle="none"
        )
        self.listbox.pack(side="left", fill="both", expand=True)
        self.listbox.bind("<<ListboxSelect>>", self.on_select)

        scrollbar = tk.Scrollbar(list_frame, command=self.listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.listbox.config(yscrollcommand=scrollbar.set)

        self.status_label = tk.Label(
            self.root,
            text="Waiting for vault unlock",
            font=("Arial", 10),
            bg="#111111",
            fg="#cccccc",
            anchor="w"
        )
        self.status_label.pack(fill="x", padx=10, pady=(0, 8))

    # --------------------------------------------------------
    # FILTER / SORT
    # ------------------------------------------------------------
    def toggle_sort(self):
        self.sort_mode = "za" if self.sort_mode == "az" else "az"
        self.btn_sort.config(text="Sort Z-A" if self.sort_mode == "za" else "Sort A-Z")
        self.update_listbox()
        self.mark_activity()

    def get_filtered_sorted_indices(self):
        query = self.search_var.get().strip().lower()

        pairs = []
        for i, acc in enumerate(self.accounts):
            name = acc["name"]
            if query and query not in name.lower():
                continue
            pairs.append((i, name.lower()))

        pairs.sort(key=lambda x: x[1], reverse=(self.sort_mode == "za"))
        return [i for i, _ in pairs]

    # --------------------------------------------------------
    # ACCOUNT DIALOG CORE
    # ------------------------------------------------------------
    def account_dialog(self, mode="add", index=None):
        if not self.is_unlocked:
            return

        edit_mode = (mode == "edit" and index is not None)
        acc_name = ""
        acc_secret = ""

        if edit_mode:
            acc = self.accounts[index]
            acc_name = acc["name"]
            acc_secret = clean_secret_text(acc["secret"])

        win = tk.Toplevel(self.root)
        win.title("Edit Account" if edit_mode else "Add Account")
        win.geometry("830x655")
        win.configure(bg="#111111")
        self.safe_lift_window(win)

        tk.Label(
            win, text="Account Name", font=("Arial", 10, "bold"),
            bg="#111111", fg="white"
        ).pack(pady=(12, 4))

        name_row = tk.Frame(win, bg="#111111")
        name_row.pack(fill="x", padx=12, pady=6)

        entry_name = tk.Entry(name_row, font=("Arial", 14))
        entry_name.pack(side="left", fill="x", expand=True)
        entry_name.insert(0, acc_name)

        btn_name_kb = tk.Button(name_row, text="⌨", width=4, bg="#444444", fg="white")
        btn_name_kb.pack(side="left", padx=(8, 0))

        tk.Label(
            win, text="Base32 Secret", font=("Arial", 10, "bold"),
            bg="#111111", fg="white"
        ).pack(pady=(8, 4))

        secret_row = tk.Frame(win, bg="#111111")
        secret_row.pack(fill="x", padx=12, pady=6)

        entry_secret = tk.Entry(secret_row, font=("Arial", 14), show="*")
        entry_secret.pack(side="left", fill="x", expand=True)
        entry_secret.insert(0, acc_secret)

        btn_secret_kb = tk.Button(secret_row, text="⌨", width=4, bg="#444444", fg="white")
        btn_secret_kb.pack(side="left", padx=(8, 4))

        show_secret_var = tk.BooleanVar(value=False)

        def toggle_secret():
            if show_secret_var.get():
                entry_secret.config(show="")
                btn_toggle.config(text="Hide")
            else:
                entry_secret.config(show="*")
                btn_toggle.config(text="Show")

        def flip_toggle():
            show_secret_var.set(not show_secret_var.get())
            toggle_secret()

        btn_toggle = tk.Button(
            secret_row, text="Show", width=6,
            command=flip_toggle, bg="#555555", fg="white"
        )
        btn_toggle.pack(side="left")

        self.bind_keyboard_support(entry_name, btn_name_kb)
        self.bind_keyboard_support(entry_secret, btn_secret_kb)

        entry_name.focus_force()
        win.after(250, lambda: self.show_android_keyboard(entry_name))

        def block_paste_event(event=None):
            self.status_label.config(text="Use 'Paste Secret' button for safe paste")
            return "break"

        entry_secret.bind("<Control-v>", block_paste_event)
        entry_secret.bind("<<Paste>>", block_paste_event)

        def paste_secret():
            try:
                clip = self.root.clipboard_get()
            except Exception:
                messagebox.showerror("Paste Error", "Could not read clipboard", parent=win)
                return

            clip = clean_secret_text(clip)
            if not clip:
                messagebox.showerror("Paste Error", "Clipboard is empty", parent=win)
                return

            entry_secret.delete(0, tk.END)
            entry_secret.insert(0, clip)
            self.status_label.config(text=f"Safe pasted secret ({len(clip)} chars)")
            self.mark_activity()

        def clear_secret():
            entry_secret.delete(0, tk.END)
            self.status_label.config(text="Secret field cleared")
            self.mark_activity()

        btn_row2 = tk.Frame(win, bg="#111111")
        btn_row2.pack(fill="x", padx=12, pady=(10, 4))

        tk.Button(
            btn_row2, text="Paste Secret", command=paste_secret,
            font=("Arial", 10, "bold"), bg="#6b4fd3", fg="white", height=2
        ).pack(side="left", expand=True, fill="x", padx=4)

        tk.Button(
            btn_row2, text="Clear", command=clear_secret,
            font=("Arial", 10, "bold"), bg="#666666", fg="white", height=2
        ).pack(side="left", expand=True, fill="x", padx=4)

        def save():
            name = entry_name.get().strip()
            secret = clean_secret_text(entry_secret.get())

            if not name or not secret:
                messagebox.showerror("Error", "Fill all fields", parent=win)
                return

            try:
                _ = generate_totp(secret)
            except Exception:
                messagebox.showerror("Error", "Invalid Base32 secret", parent=win)
                return

            if self.account_exists(name, secret, ignore_index=index if edit_mode else None):
                messagebox.showwarning(
                    "Duplicate",
                    "An account with the same name or secret already exists.",
                    parent=win
                )
                return

            if edit_mode:
                self.accounts[index] = {"name": name, "secret": secret}
                self.status_label.config(text=f"Updated account: {name}")
            else:
                self.accounts.append({"name": name, "secret": secret})
                self.status_label.config(text=f"Added account: {name}")

            self.save_accounts()
            self.update_listbox()
            win.destroy()
            self.mark_activity()

        tk.Button(
            win,
            text="Save Account" if not edit_mode else "Save Changes",
            command=save,
            font=("Arial", 10, "bold"),
            bg="#2d6cdf",
            fg="white"
        ).pack(pady=18)

        entry_name.bind(
            "<Return>",
            lambda e: self.root.after(120, lambda: self.show_android_keyboard(entry_secret))
        )
        entry_secret.bind("<Return>", lambda e: save())

    def add_account_dialog(self):
        self.account_dialog(mode="add")

    def edit_selected_account(self):
        if not self.is_unlocked:
            return
        if self.selected_index is None:
            messagebox.showwarning("Warning", "Select an account first")
            return
        self.account_dialog(mode="edit", index=self.selected_index)

    # --------------------------------------------------------
    # IMPORT / EXPORT
    # ------------------------------------------------------------
    def smart_import_dialog(self):
        if not self.is_unlocked:
            return

        win = tk.Toplevel(self.root)
        win.title("Smart Import")
        win.geometry("840x620")
        win.configure(bg="#111111")
        self.safe_lift_window(win)

        tk.Label(
            win, text="Paste otpauth:// link",
            font=("Arial", 10, "bold"), bg="#111111", fg="white"
        ).pack(pady=(14, 8))

        info_text = (
            "Example:\n"
            "otpauth://totp/Test:RWB?"
            "secret=EXAMPLEBASE32SECRET&issuer=Test"
        )

        tk.Label(
            win, text=info_text, font=("Arial", 10),
            bg="#111111", fg="#bbbbbb", justify="left", wraplength=400
        ).pack(padx=12, pady=(0, 8))

        text_row = tk.Frame(win, bg="#111111")
        text_row.pack(fill="both", expand=False, padx=12, pady=8)

        text_box = tk.Text(
            text_row, height=8, font=("Courier New", 10),
            bg="#1d1d1d", fg="white", insertbackground="white", wrap="word"
        )
        text_box.pack(side="left", fill="both", expand=True)

        btn_kb = tk.Button(
            text_row, text="⌨", width=4, bg="#444444", fg="white",
            command=lambda: self.show_android_keyboard(text_box)
        )
        btn_kb.pack(side="left", padx=(8, 0), anchor="n")

        text_box.bind("<Button-1>", lambda e: self.root.after(120, lambda: self.show_android_keyboard(text_box)))
        text_box.bind("<FocusIn>", lambda e: self.root.after(120, lambda: self.show_android_keyboard(text_box)))

        text_box.focus_force()
        win.after(250, lambda: self.show_android_keyboard(text_box))

        preview_name_var = tk.StringVar(value="Name: -")
        preview_secret_var = tk.StringVar(value="Secret: -")
        parsed_data = {"name": None, "secret": None}

        tk.Label(
            win, textvariable=preview_name_var,
            font=("Arial", 10, "bold"), bg="#111111", fg="#66ff66", anchor="w"
        ).pack(fill="x", padx=12, pady=(8, 2))

        tk.Label(
            win, textvariable=preview_secret_var,
            font=("Courier New", 10), bg="#111111", fg="#cccccc",
            anchor="w", justify="left", wraplength=400
        ).pack(fill="x", padx=12, pady=(2, 8))

        def parse_preview():
            raw = text_box.get("1.0", "end").strip()
            if not raw:
                messagebox.showwarning("Warning", "Paste an otpauth link first", parent=win)
                return

            try:
                name, secret = parse_otpauth_uri(raw)
                _ = generate_totp(secret)
                parsed_data["name"] = name
                parsed_data["secret"] = secret
                preview_name_var.set(f"Name: {name}")
                preview_secret_var.set(f"Secret: {secret}")
                self.status_label.config(text="otpauth link parsed successfully")
                self.mark_activity()
            except Exception as e:
                parsed_data["name"] = None
                parsed_data["secret"] = None
                preview_name_var.set("Name: -")
                preview_secret_var.set("Secret: -")
                messagebox.showerror("Parse Error", str(e), parent=win)

        def save_import():
            if not parsed_data["name"] or not parsed_data["secret"]:
                messagebox.showwarning("Warning", "Parse the otpauth link first", parent=win)
                return

            if self.account_exists(parsed_data["name"], parsed_data["secret"]):
                messagebox.showwarning("Duplicate", "This account already exists.", parent=win)
                return

            self.accounts.append({
                "name": parsed_data["name"],
                "secret": parsed_data["secret"]
            })
            self.save_accounts()
            self.update_listbox()
            self.status_label.config(text=f"Imported account: {parsed_data['name']}")
            win.destroy()
            self.mark_activity()

        btn_row = tk.Frame(win, bg="#111111")
        btn_row.pack(fill="x", padx=12, pady=10)

        tk.Button(
            btn_row, text="Parse", command=parse_preview,
            font=("Arial", 12, "bold"), bg="#6b4fd3", fg="white", height=2
        ).pack(side="left", expand=True, fill="x", padx=4)

        tk.Button(
            btn_row, text="Save Import", command=save_import,
            font=("Arial", 12, "bold"), bg="#2d6cdf", fg="white", height=2
        ).pack(side="left", expand=True, fill="x", padx=4)

    def export_backup(self):
        if not self.is_unlocked:
            return

        try:
            export_path = filedialog.asksaveasfilename(
                title="Export Encrypted Backup",
                defaultextension=".dat",
                initialfile="rwb_2fa_backup.dat",
                filetypes=[("Encrypted vault", "*.dat"), ("All files", "*.*")]
            )
            if not export_path:
                return

            confirm = messagebox.askyesno("Export", "Export encrypted backup now?")
            if not confirm:
                return

            self.save_accounts()
            with open(VAULT_FILE, "rb") as src:
                data = src.read()
            with open(export_path, "wb") as dst:
                dst.write(data)

            self.status_label.config(text=f"Exported backup: {os.path.basename(export_path)}")
            self.mark_activity()
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def import_backup(self):
        if not self.is_unlocked:
            return

        try:
            import_path = filedialog.askopenfilename(
                title="Import Encrypted Backup",
                filetypes=[("Encrypted vault", "*.dat"), ("All files", "*.*")]
            )
            if not import_path:
                return

            with open(import_path, "rb") as f:
                encrypted = f.read()

            try:
                decrypted = decrypt_data(encrypted, self.master_password)
                imported_accounts = self.normalize_accounts(json.loads(decrypted.decode("utf-8")))
            except Exception:
                messagebox.showerror("Import Error", "Could not decrypt backup with current vault password.")
                return

            if not imported_accounts:
                messagebox.showwarning("Import", "Backup contains no valid accounts.")
                return

            mode = messagebox.askyesnocancel(
                "Import Backup",
                "Yes = merge accounts\nNo = replace all accounts\nCancel = abort"
            )

            if mode is None:
                return

            if mode is False:
                self.accounts = imported_accounts
                self.save_accounts()
                self.update_listbox()
                self.status_label.config(text=f"Imported backup (replaced all, {len(imported_accounts)} accounts)")
                self.mark_activity()
                return

            # Merge mode
            added = 0
            skipped = 0
            for acc in imported_accounts:
                if self.account_exists(acc["name"], acc["secret"]):
                    skipped += 1
                else:
                    self.accounts.append(acc)
                    added += 1

            self.save_accounts()
            self.update_listbox()
            self.status_label.config(text=f"Import merged: +{added}, skipped {skipped}")
            self.mark_activity()

        except Exception as e:
            messagebox.showerror("Import Error", str(e))

    # --------------------------------------------------------
    # ACTIONS
    # ------------------------------------------------------------
    def on_select(self, event=None):
        selection = self.listbox.curselection()
        if selection:
            visible_idx = selection[0]
            if 0 <= visible_idx < len(self.filtered_indices):
                self.selected_index = self.filtered_indices[visible_idx]
            else:
                self.selected_index = None
        else:
            self.selected_index = None

    def delete_selected(self):
        if not self.is_unlocked:
            return
        if self.selected_index is None:
            messagebox.showwarning("Warning", "Select an account first")
            return

        name = self.accounts[self.selected_index]["name"]
        ok = messagebox.askyesno("Delete", f"Delete account '{name}'?")
        if not ok:
            return

        del self.accounts[self.selected_index]
        self.selected_index = None
        self.save_accounts()
        self.update_listbox()
        self.status_label.config(text=f"Deleted account: {name}")
        self.mark_activity()

    def copy_selected_code(self):
        if not self.is_unlocked:
            return
        if self.selected_index is None:
            messagebox.showwarning("Warning", "Select an account first")
            return

        try:
            acc = self.accounts[self.selected_index]
            secret = clean_secret_text(acc["secret"])
            code = generate_totp(secret)

            self.root.clipboard_clear()
            self.root.clipboard_append(code)
            self.root.update()

            self.status_label.config(text=f"Copied code: {code} | {acc['name']}")
            self.mark_activity()
        except Exception as e:
            messagebox.showerror("Error", f"Could not generate/copy code:\n{e}")

    def show_selected_secret(self):
        if not self.is_unlocked:
            return
        if self.selected_index is None:
            messagebox.showwarning("Warning", "Select an account first")
            return

        acc = self.accounts[self.selected_index]
        content = (
            f"Name: {acc['name']}\n\n"
            f"Secret:\n{acc['secret']}\n\n"
            f"Length: {len(clean_secret_text(acc['secret']))}"
        )
        self.show_large_message("Secret Viewer", content)
        self.mark_activity()

    def debug_selected_account(self):
        if not self.is_unlocked:
            return
        if self.selected_index is None:
            messagebox.showwarning("Warning", "Select an account first")
            return

        try:
            acc = self.accounts[self.selected_index]
            raw_secret = acc["secret"]
            clean_secret = clean_secret_text(raw_secret)
            code = generate_totp(clean_secret)
            remain = seconds_remaining()

            msg = (
                f"Name: {acc['name']}\n\n"
                f"Raw secret:\n{raw_secret}\n\n"
                f"Clean secret:\n{clean_secret}\n\n"
                f"Length: {len(clean_secret)}\n"
                f"Code now: {code}\n"
                f"Refresh in: {remain}s\n"
                f"Auto-lock: {AUTO_LOCK_SECONDS}s\n"
                f"Sort mode: {self.sort_mode}\n"
                f"Search: {self.search_var.get().strip()}"
            )
            self.show_large_message("Debug Account", msg)
            self.mark_activity()
        except Exception as e:
            messagebox.showerror("Debug Error", str(e))

    # --------------------------------------------------------
    # LIST / REFRESH
    # ------------------------------------------------------------
    def update_listbox(self):
        self.listbox.delete(0, tk.END)
        self.filtered_indices = self.get_filtered_sorted_indices()

        if not self.filtered_indices:
            self.listbox.insert(tk.END, "No matching accounts" if self.accounts else "No accounts added")
        else:
            for display_pos, real_idx in enumerate(self.filtered_indices, start=1):
                acc = self.accounts[real_idx]
                try:
                    secret = clean_secret_text(acc["secret"])
                    code = generate_totp(secret)
                except Exception:
                    code = "ERROR"

                line = f"{display_pos:02d}. {acc['name'][:14]:14} {code}"
                self.listbox.insert(tk.END, line)

        self.count_label.config(text=f"Accounts: {len(self.filtered_indices)} / {len(self.accounts)}")

    def refresh_codes(self):
        if not self.is_unlocked:
            return

        remain = seconds_remaining()
        idle_left = max(0, int(AUTO_LOCK_SECONDS - (time.time() - self.last_activity)))
        self.timer_label.config(text=f"Refresh in: {remain} | Lock in: {idle_left}s")

        current_selection = self.listbox.curselection()
        self.update_listbox()

        if current_selection and len(self.filtered_indices) > current_selection[0]:
            self.listbox.selection_set(current_selection[0])
            self.listbox.activate(current_selection[0])
            self.selected_index = self.filtered_indices[current_selection[0]]

        self.root.after(1000, self.refresh_codes)


# --------------------------------------------------------
# MAIN
# --------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = RWB2FAMobileUI(root)
    root.mainloop()
