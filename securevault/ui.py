"""Tkinter interface for SecureVault."""

from __future__ import annotations

import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from pydantic import ValidationError

from .database import VaultDatabase
from .models import Credential, CredentialInput
from .security import assess_password, generate_passphrase, generate_password
from .vault import (
    LoginLockedOutError,
    RecoveryLockedOutError,
    VaultLockedError,
    VaultService,
)

APP_BG = "#07110c"
SIDEBAR = "#091a11"
CARD = "#10231a"
CARD_LIGHT = "#173126"
GREEN = "#35e07b"
GREEN_HOVER = "#68f39a"
TEXT = "#f1fff6"
MUTED = "#9bb9a5"
BORDER = "#25513a"
DANGER = "#ff6577"
WARNING = "#f6c85f"

CATEGORIES = ["Social media", "School", "Work", "Banking", "Entertainment", "Other"]


class SecureVaultApp(tk.Tk):
    def __init__(self, db_path: Path | None = None):
        super().__init__()
        self.title("SecureVault — Smart Password Manager")
        self.geometry("1180x760")
        self.minsize(980, 650)
        self.configure(bg=APP_BG)
        self.db_path = db_path or Path(__file__).resolve().parent.parent / "data" / "vault.db"
        self.database = VaultDatabase(self.db_path)
        self.vault = VaultService(self.database)
        self.last_activity = time.monotonic()
        self.clipboard_value: str | None = None
        self.current_page = ""
        self._configure_styles()
        self.bind_all("<KeyPress>", self._record_activity, add="+")
        self.bind_all("<Button>", self._record_activity, add="+")
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(1000, self._check_inactivity)
        self.show_start()

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=APP_BG, foreground=TEXT, font=("Helvetica", 11))
        style.configure("TFrame", background=APP_BG)
        style.configure("Card.TFrame", background=CARD, relief="flat")
        style.configure("Sidebar.TFrame", background=SIDEBAR)
        style.configure("TLabel", background=APP_BG, foreground=TEXT)
        style.configure("Muted.TLabel", foreground=MUTED)
        style.configure("Card.TLabel", background=CARD, foreground=TEXT)
        style.configure("CardMuted.TLabel", background=CARD, foreground=MUTED)
        style.configure("Title.TLabel", font=("Helvetica", 28, "bold"), foreground=TEXT)
        style.configure("Brand.TLabel", font=("Helvetica", 21, "bold"), foreground=GREEN, background=SIDEBAR)
        style.configure("Heading.TLabel", font=("Helvetica", 18, "bold"))
        style.configure("CardTitle.TLabel", font=("Helvetica", 12, "bold"), background=CARD)
        style.configure("Metric.TLabel", font=("Helvetica", 28, "bold"), background=CARD, foreground=GREEN)
        style.configure(
            "TButton", background=CARD_LIGHT, foreground=TEXT, borderwidth=0,
            padding=(14, 9), font=("Helvetica", 10, "bold")
        )
        style.map("TButton", background=[("active", BORDER), ("pressed", GREEN)], foreground=[("pressed", APP_BG)])
        style.configure("Accent.TButton", background=GREEN, foreground="#03130a")
        style.map("Accent.TButton", background=[("active", GREEN_HOVER), ("pressed", GREEN_HOVER)])
        style.configure("Danger.TButton", background="#4a1f28", foreground="#ffacb5")
        style.map("Danger.TButton", background=[("active", "#632934")])
        style.configure("Nav.TButton", background=SIDEBAR, foreground=MUTED, anchor="w", padding=(18, 12))
        style.map("Nav.TButton", background=[("active", CARD)], foreground=[("active", GREEN)])
        style.configure("TEntry", fieldbackground="#0b1b12", foreground=TEXT, insertcolor=GREEN, bordercolor=BORDER, padding=9)
        style.map("TEntry", bordercolor=[("focus", GREEN)])
        style.configure("TCombobox", fieldbackground="#0b1b12", background=CARD_LIGHT, foreground=TEXT, arrowcolor=GREEN, padding=8)
        style.map("TCombobox", fieldbackground=[("readonly", "#0b1b12")], foreground=[("readonly", TEXT)])
        style.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT, rowheight=40, borderwidth=0)
        style.configure("Treeview.Heading", background=CARD_LIGHT, foreground=MUTED, relief="flat", font=("Helvetica", 9, "bold"))
        style.map("Treeview", background=[("selected", "#1b5735")], foreground=[("selected", TEXT)])
        style.configure("TCheckbutton", background=APP_BG, foreground=TEXT)
        style.configure("Card.TCheckbutton", background=CARD, foreground=TEXT)
        style.map("TCheckbutton", indicatorcolor=[("selected", GREEN)], background=[("active", APP_BG)])
        style.configure("Horizontal.TProgressbar", troughcolor=CARD_LIGHT, background=GREEN, borderwidth=0)
        self.option_add("*TCombobox*Listbox.background", CARD)
        self.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.option_add("*TCombobox*Listbox.selectBackground", GREEN)

    def clear(self) -> None:
        self.unbind("<Return>")
        for child in self.winfo_children():
            child.destroy()

    def _record_activity(self, _event=None) -> None:
        self.last_activity = time.monotonic()

    def _check_inactivity(self) -> None:
        if self.vault.unlocked:
            minutes = int(self.database.get_meta("inactivity_minutes") or "5")
            if minutes > 0 and time.monotonic() - self.last_activity >= minutes * 60:
                self.lock_vault("Vault locked after inactivity.")
        self.after(1000, self._check_inactivity)

    def _on_close(self) -> None:
        self.vault.lock()
        self.database.close()
        self.destroy()

    def show_start(self, notice: str = "") -> None:
        self.clear()
        if self.database.is_initialized():
            self._show_unlock(notice)
        else:
            self._show_setup()

    def _auth_shell(self, eyebrow: str, title: str, subtitle: str) -> ttk.Frame:
        shell = ttk.Frame(self)
        shell.pack(fill="both", expand=True)
        left = tk.Frame(shell, bg=SIDEBAR, width=430)
        left.pack(side="left", fill="both")
        left.pack_propagate(False)
        tk.Label(left, text="SECUREVAULT", bg=SIDEBAR, fg=GREEN, font=("Helvetica", 13, "bold")).pack(anchor="w", padx=55, pady=(70, 8))
        tk.Label(left, text="Your passwords.\nYour privacy.\nYour vault.", justify="left", bg=SIDEBAR, fg=TEXT, font=("Helvetica", 31, "bold")).pack(anchor="w", padx=55, pady=(30, 20))
        tk.Label(left, text="Local-first encryption • No cloud account\nNo recovery backdoor • Automatic locking", justify="left", bg=SIDEBAR, fg=MUTED, font=("Helvetica", 11), pady=4).pack(anchor="w", padx=55)
        badge = tk.Frame(left, bg="#123c25")
        badge.pack(anchor="w", padx=55, pady=45)
        tk.Label(badge, text="  AES-256-GCM  +  Argon2id  ", bg="#123c25", fg=GREEN, font=("Helvetica", 10, "bold"), pady=8).pack()

        content = ttk.Frame(shell)
        content.pack(side="left", fill="both", expand=True, padx=90, pady=80)
        ttk.Label(content, text=eyebrow.upper(), foreground=GREEN, font=("Helvetica", 10, "bold")).pack(anchor="w")
        ttk.Label(content, text=title, style="Title.TLabel").pack(anchor="w", pady=(8, 8))
        ttk.Label(content, text=subtitle, style="Muted.TLabel", wraplength=520, justify="left").pack(anchor="w", pady=(0, 30))
        return content

    def _show_setup(self) -> None:
        content = self._auth_shell(
            "New private vault",
            "Create your master password",
            "This password protects every credential. It is never stored and cannot be recovered by SecureVault.",
        )
        pw = tk.StringVar()
        confirm = tk.StringVar()
        show = tk.BooleanVar()
        strength = tk.StringVar(value="Start with 12+ characters")

        ttk.Label(content, text="Master password").pack(anchor="w")
        pw_entry = ttk.Entry(content, textvariable=pw, show="•", width=46)
        pw_entry.pack(fill="x", pady=(7, 16))
        ttk.Label(content, text="Confirm master password").pack(anchor="w")
        confirm_entry = ttk.Entry(content, textvariable=confirm, show="•", width=46)
        confirm_entry.pack(fill="x", pady=(7, 12))
        ttk.Checkbutton(
            content, text="Show passwords", variable=show,
            command=lambda: [
                pw_entry.configure(show="" if show.get() else "•"),
                confirm_entry.configure(show="" if show.get() else "•"),
            ],
        ).pack(anchor="w")
        meter = ttk.Progressbar(content, maximum=100)
        meter.pack(fill="x", pady=(20, 7))
        ttk.Label(content, textvariable=strength, style="Muted.TLabel").pack(anchor="w")

        def update_strength(*_args) -> None:
            result = assess_password(pw.get())
            meter["value"] = result.score
            strength.set(f"{result.label} · " + (" ".join(result.suggestions) or "Ready to protect your vault."))

        pw.trace_add("write", update_strength)

        def create() -> None:
            if pw.get() != confirm.get():
                messagebox.showerror("Passwords do not match", "Enter the same master password twice.", parent=self)
                return
            try:
                recovery = self.vault.setup(pw.get())
            except ValueError as exc:
                messagebox.showerror("Choose a stronger password", str(exc), parent=self)
                return
            self._show_recovery_key(recovery)
            self.show_main()

        ttk.Button(content, text="Create secure vault", style="Accent.TButton", command=create).pack(fill="x", pady=(28, 12))
        ttk.Label(content, text="Important: losing both your master password and recovery key means permanent loss of access.", foreground=WARNING, wraplength=520).pack(anchor="w", pady=8)
        pw_entry.focus_set()
        self.bind("<Return>", lambda _e: create(), add="+")

    def _show_recovery_key(self, recovery: str) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Save your recovery key")
        dialog.geometry("620x390")
        dialog.configure(bg=APP_BG)
        dialog.transient(self)
        dialog.grab_set()
        dialog.protocol("WM_DELETE_WINDOW", lambda: None)
        frame = ttk.Frame(dialog, padding=35)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Save your recovery key", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            frame,
            text="This is shown only once. Store it offline in a safe place. Anyone with this key can unlock your vault.",
            style="Muted.TLabel", wraplength=530, justify="left",
        ).pack(anchor="w", pady=(10, 25))
        key_box = tk.Text(frame, height=3, bg=CARD, fg=GREEN, insertbackground=GREEN, relief="flat", font=("Courier", 15, "bold"), padx=15, pady=15)
        key_box.insert("1.0", recovery)
        key_box.configure(state="disabled")
        key_box.pack(fill="x")
        confirmed = tk.BooleanVar()
        ttk.Checkbutton(frame, text="I saved this recovery key safely", variable=confirmed).pack(anchor="w", pady=20)

        def finish() -> None:
            if not confirmed.get():
                messagebox.showwarning("Save the key first", "Confirm that you stored the recovery key safely.", parent=dialog)
                return
            dialog.destroy()

        ttk.Button(frame, text="Continue to my vault", style="Accent.TButton", command=finish).pack(fill="x")
        self.wait_window(dialog)

    def _show_unlock(self, notice: str = "") -> None:
        content = self._auth_shell(
            "Welcome back", "Unlock SecureVault",
            "Enter your master password. Your vault always starts locked.",
        )
        password = tk.StringVar()
        show = tk.BooleanVar()
        if notice:
            ttk.Label(content, text=notice, foreground=GREEN).pack(anchor="w", pady=(0, 16))
        ttk.Label(content, text="Master password").pack(anchor="w")
        entry = ttk.Entry(content, textvariable=password, show="•", width=46)
        entry.pack(fill="x", pady=(7, 10))
        ttk.Checkbutton(
            content, text="Show password", variable=show,
            command=lambda: entry.configure(show="" if show.get() else "•"),
        ).pack(anchor="w")
        status = tk.StringVar()
        ttk.Label(content, textvariable=status, foreground=DANGER).pack(anchor="w", pady=(15, 0))

        def unlock() -> None:
            status.set("")
            try:
                self.vault.unlock(password.get())
            except (VaultLockedError, LoginLockedOutError, ValueError) as exc:
                status.set(str(exc))
                password.set("")
                entry.focus_set()
                return
            self.last_activity = time.monotonic()
            self.show_main()

        ttk.Button(content, text="Unlock vault", style="Accent.TButton", command=unlock).pack(fill="x", pady=(22, 12))
        ttk.Button(
            content,
            text="Forgot master password?",
            command=self._recover_master_password_dialog,
        ).pack(fill="x")
        ttk.Label(
            content,
            text="Resetting requires the recovery key shown during setup. "
            "There is no recovery backdoor.",
            style="Muted.TLabel",
            wraplength=520,
        ).pack(anchor="w", pady=18)
        entry.focus_set()
        self.bind("<Return>", lambda _e: unlock(), add="+")

    def _recover_master_password_dialog(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Recover master password")
        dialog.geometry("600x570")
        dialog.minsize(560, 540)
        dialog.configure(bg=APP_BG)
        dialog.transient(self)
        dialog.grab_set()
        frame = ttk.Frame(dialog, padding=30)
        frame.pack(fill="both", expand=True)
        ttk.Label(
            frame, text="Recover your vault", style="Heading.TLabel"
        ).pack(anchor="w")
        ttk.Label(
            frame,
            text="Enter the recovery key you saved during setup, then choose "
            "a new master password. You have five recovery-key attempts.",
            style="Muted.TLabel",
            wraplength=520,
            justify="left",
        ).pack(anchor="w", pady=(7, 20))

        recovery_key = tk.StringVar()
        new_password = tk.StringVar()
        confirmation = tk.StringVar()
        show_values = tk.BooleanVar()
        strength = tk.StringVar(value="Use at least 12 characters")

        ttk.Label(frame, text="Recovery key").pack(anchor="w")
        recovery_entry = ttk.Entry(
            frame, textvariable=recovery_key, show="•"
        )
        recovery_entry.pack(fill="x", pady=(5, 14))
        ttk.Label(frame, text="New master password").pack(anchor="w")
        password_entry = ttk.Entry(
            frame, textvariable=new_password, show="•"
        )
        password_entry.pack(fill="x", pady=(5, 14))
        ttk.Label(frame, text="Confirm new master password").pack(anchor="w")
        confirmation_entry = ttk.Entry(
            frame, textvariable=confirmation, show="•"
        )
        confirmation_entry.pack(fill="x", pady=(5, 10))

        def toggle_visibility() -> None:
            hidden = "" if show_values.get() else "•"
            recovery_entry.configure(show=hidden)
            password_entry.configure(show=hidden)
            confirmation_entry.configure(show=hidden)

        ttk.Checkbutton(
            frame,
            text="Show recovery key and passwords",
            variable=show_values,
            command=toggle_visibility,
        ).pack(anchor="w")
        ttk.Label(
            frame, textvariable=strength, style="Muted.TLabel"
        ).pack(anchor="w", pady=(12, 0))

        def update_strength(*_args) -> None:
            result = assess_password(new_password.get())
            strength.set(
                f"Strength: {result.label} · "
                + (" ".join(result.suggestions) or "Ready to use.")
            )

        new_password.trace_add("write", update_strength)

        def recover() -> None:
            if new_password.get() != confirmation.get():
                messagebox.showerror(
                    "Passwords do not match",
                    "Enter the same new master password twice.",
                    parent=dialog,
                )
                return
            try:
                self.vault.recover_master_password(
                    recovery_key.get(), new_password.get()
                )
            except (
                RecoveryLockedOutError,
                VaultLockedError,
                ValueError,
            ) as exc:
                messagebox.showerror(
                    "Recovery failed", str(exc), parent=dialog
                )
                return
            dialog.destroy()
            self.last_activity = time.monotonic()
            self.show_main()
            messagebox.showinfo(
                "Master password reset",
                "Your vault is unlocked. Use the new master password the "
                "next time you sign in.",
                parent=self,
            )

        ttk.Button(
            frame,
            text="Reset password and unlock vault",
            style="Accent.TButton",
            command=recover,
        ).pack(fill="x", pady=(22, 12))
        ttk.Label(
            frame,
            text="No recovery key? SecureVault cannot decrypt or reset this "
            "vault. This protects it from unauthorized password resets.",
            foreground=WARNING,
            wraplength=520,
            justify="left",
        ).pack(anchor="w")
        recovery_entry.focus_set()
        dialog.bind("<Return>", lambda _event: recover())

    def show_main(self, page: str = "vault") -> None:
        self.clear()
        self.current_page = page
        shell = ttk.Frame(self)
        shell.pack(fill="both", expand=True)
        sidebar = ttk.Frame(shell, style="Sidebar.TFrame", width=220)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        ttk.Label(sidebar, text="⬡  SECUREVAULT", style="Brand.TLabel").pack(anchor="w", padx=20, pady=(28, 35))
        for text, target in (
            ("▦   My vault", "vault"),
            ("✦   Generator", "generator"),
            ("♥   Vault health", "health"),
            ("⚙   Settings", "settings"),
        ):
            ttk.Button(sidebar, text=text, style="Nav.TButton", command=lambda p=target: self.show_main(p)).pack(fill="x", padx=8, pady=2)
        ttk.Frame(sidebar, style="Sidebar.TFrame").pack(fill="both", expand=True)
        ttk.Button(sidebar, text="⌾   Lock vault", style="Nav.TButton", command=self.lock_vault).pack(fill="x", padx=8, pady=18)
        ttk.Label(sidebar, text="Encrypted locally", background=SIDEBAR, foreground=MUTED, font=("Helvetica", 9)).pack(pady=(0, 25))
        content = ttk.Frame(shell, padding=(32, 28))
        content.pack(side="left", fill="both", expand=True)
        {
            "vault": self._build_vault_page,
            "generator": self._build_generator_page,
            "health": self._build_health_page,
            "settings": self._build_settings_page,
        }[page](content)

    def lock_vault(self, notice: str = "Vault locked.") -> None:
        self.vault.lock()
        self._clear_clipboard_now()
        self.show_start(notice)

    def _page_header(self, parent: ttk.Frame, title: str, subtitle: str) -> ttk.Frame:
        top = ttk.Frame(parent)
        top.pack(fill="x", pady=(0, 24))
        left = ttk.Frame(top)
        left.pack(side="left")
        ttk.Label(left, text=title, style="Title.TLabel").pack(anchor="w")
        ttk.Label(left, text=subtitle, style="Muted.TLabel").pack(anchor="w", pady=(4, 0))
        return top

    def _build_vault_page(self, parent: ttk.Frame) -> None:
        top = self._page_header(parent, "My vault", "Search and manage your saved accounts")
        ttk.Button(top, text="+  Add account", style="Accent.TButton", command=lambda: self._credential_dialog()).pack(side="right")
        filters = ttk.Frame(parent)
        filters.pack(fill="x", pady=(0, 18))
        search = tk.StringVar()
        category = tk.StringVar(value="All")
        favorites = tk.BooleanVar()
        search_entry = ttk.Entry(filters, textvariable=search)
        search_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        search_entry.insert(0, "")
        category_box = ttk.Combobox(filters, textvariable=category, state="readonly", width=18, values=["All", *self.vault.categories()])
        category_box.pack(side="left", padx=(0, 12))
        ttk.Checkbutton(filters, text="Favorites only", variable=favorites).pack(side="left")

        columns = ("favorite", "account", "username", "category", "updated")
        tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")
        tree.heading("favorite", text="")
        tree.heading("account", text="ACCOUNT")
        tree.heading("username", text="USERNAME / EMAIL")
        tree.heading("category", text="CATEGORY")
        tree.heading("updated", text="LAST UPDATED")
        tree.column("favorite", width=45, anchor="center", stretch=False)
        tree.column("account", width=230)
        tree.column("username", width=260)
        tree.column("category", width=150)
        tree.column("updated", width=140)
        tree.pack(fill="both", expand=True)
        empty = ttk.Label(parent, text="", style="Muted.TLabel")
        empty.pack(pady=8)

        def refresh(*_args) -> None:
            tree.delete(*tree.get_children())
            try:
                items = self.vault.list_credentials(search.get(), category.get(), favorites.get())
            except VaultLockedError:
                return
            for item in items:
                updated = item.updated_at[:10]
                tree.insert("", "end", iid=str(item.id), values=("★" if item.favorite else "", item.account_name, item.username, item.category, updated))
            empty.configure(text="No matching accounts yet." if not items else f"{len(items)} account{'s' if len(items) != 1 else ''} securely stored")

        search.trace_add("write", refresh)
        category.trace_add("write", refresh)
        favorites.trace_add("write", refresh)
        refresh()

        actions = ttk.Frame(parent)
        actions.pack(fill="x", pady=(14, 0))

        def selected_id() -> int | None:
            selection = tree.selection()
            return int(selection[0]) if selection else None

        def open_selected() -> None:
            item_id = selected_id()
            if item_id is not None:
                self._view_credential_dialog(item_id, refresh)

        ttk.Button(actions, text="View details", command=open_selected).pack(side="left")
        ttk.Button(actions, text="Edit", command=lambda: self._edit_selected(selected_id(), refresh)).pack(side="left", padx=8)
        ttk.Button(actions, text="Delete", style="Danger.TButton", command=lambda: self._delete_selected(selected_id(), refresh)).pack(side="right")
        tree.bind("<Double-1>", lambda _e: open_selected())

    def _edit_selected(self, item_id: int | None, refresh) -> None:
        if item_id is not None:
            self._credential_dialog(self.vault.get_credential(item_id), refresh)

    def _delete_selected(self, item_id: int | None, refresh) -> None:
        if item_id is None:
            return
        item = self.vault.get_credential(item_id)
        if messagebox.askyesno("Delete account?", f"Permanently delete “{item.account_name}” from this vault?", parent=self):
            self.vault.delete_credential(item_id)
            refresh()

    def _credential_dialog(self, item: Credential | None = None, on_saved=None) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Edit account" if item else "Add account")
        dialog.geometry("690x710")
        dialog.minsize(620, 650)
        dialog.configure(bg=APP_BG)
        dialog.transient(self)
        dialog.grab_set()
        canvas = tk.Canvas(dialog, bg=APP_BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(dialog, orient="vertical", command=canvas.yview)
        form = ttk.Frame(canvas, padding=30)
        form_id = canvas.create_window((0, 0), window=form, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        form.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(form_id, width=e.width))

        ttk.Label(form, text="Edit account" if item else "Add account", style="Title.TLabel").pack(anchor="w")
        ttk.Label(form, text="Sensitive fields are encrypted before they reach SQLite.", style="Muted.TLabel").pack(anchor="w", pady=(5, 22))

        values = {
            "account_name": tk.StringVar(value=item.account_name if item else ""),
            "website": tk.StringVar(value=item.website if item else ""),
            "username": tk.StringVar(value=item.username if item else ""),
            "password": tk.StringVar(value=item.password if item else ""),
            "category": tk.StringVar(value=item.category if item else "Other"),
            "tags": tk.StringVar(value=item.tags if item else ""),
            "favorite": tk.BooleanVar(value=item.favorite if item else False),
        }

        def field(label: str, name: str, show: str = "") -> ttk.Entry:
            ttk.Label(form, text=label).pack(anchor="w", pady=(9, 5))
            entry = ttk.Entry(form, textvariable=values[name], show=show)
            entry.pack(fill="x")
            return entry

        field("Account name *", "account_name")
        field("Website URL", "website")
        field("Username or email", "username")
        ttk.Label(form, text="Password *").pack(anchor="w", pady=(9, 5))
        password_row = ttk.Frame(form)
        password_row.pack(fill="x")
        password_entry = ttk.Entry(password_row, textvariable=values["password"], show="•")
        password_entry.pack(side="left", fill="x", expand=True)
        show_password = tk.BooleanVar()
        ttk.Checkbutton(password_row, text="Show", variable=show_password, command=lambda: password_entry.configure(show="" if show_password.get() else "•")).pack(side="left", padx=8)
        ttk.Button(password_row, text="Generate", command=lambda: values["password"].set(generate_password())).pack(side="left")
        strength = tk.StringVar()
        ttk.Label(form, textvariable=strength, style="Muted.TLabel").pack(anchor="w", pady=(5, 0))
        values["password"].trace_add("write", lambda *_: strength.set(f"Strength: {assess_password(values['password'].get()).label}"))
        strength.set(f"Strength: {assess_password(values['password'].get()).label}")

        ttk.Label(form, text="Category").pack(anchor="w", pady=(9, 5))
        ttk.Combobox(form, textvariable=values["category"], values=CATEGORIES).pack(fill="x")
        field("Tags (comma separated)", "tags")
        ttk.Label(form, text="Notes or recovery information").pack(anchor="w", pady=(9, 5))
        notes = tk.Text(form, height=5, bg="#0b1b12", fg=TEXT, insertbackground=GREEN, relief="flat", padx=10, pady=10, wrap="word")
        notes.insert("1.0", item.notes if item else "")
        notes.pack(fill="x")
        ttk.Checkbutton(form, text="Mark as favorite", variable=values["favorite"]).pack(anchor="w", pady=14)

        def save() -> None:
            try:
                data = CredentialInput(
                    account_name=values["account_name"].get(),
                    website=values["website"].get(),
                    username=values["username"].get(),
                    password=values["password"].get(),
                    category=values["category"].get(),
                    tags=values["tags"].get(),
                    notes=notes.get("1.0", "end-1c"),
                    favorite=values["favorite"].get(),
                )
                self.vault.save_credential(data, item.id if item else None)
            except (ValidationError, ValueError) as exc:
                messagebox.showerror("Check the account", str(exc), parent=dialog)
                return
            dialog.destroy()
            if on_saved:
                on_saved()
            elif self.current_page == "vault":
                self.show_main("vault")

        ttk.Button(form, text="Save encrypted account", style="Accent.TButton", command=save).pack(fill="x", pady=(8, 25))

    def _view_credential_dialog(self, item_id: int, on_changed=None) -> None:
        item = self.vault.get_credential(item_id)
        dialog = tk.Toplevel(self)
        dialog.title(item.account_name)
        dialog.geometry("650x590")
        dialog.configure(bg=APP_BG)
        dialog.transient(self)
        dialog.grab_set()
        frame = ttk.Frame(dialog, padding=32)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text=("★  " if item.favorite else "") + item.account_name, style="Title.TLabel").pack(anchor="w")
        ttk.Label(frame, text=f"{item.category}  •  Updated {item.updated_at[:10]}", style="Muted.TLabel").pack(anchor="w", pady=(5, 22))

        def value_row(label: str, value: str, secret: bool = False) -> None:
            ttk.Label(frame, text=label.upper(), foreground=MUTED, font=("Helvetica", 9, "bold")).pack(anchor="w", pady=(9, 4))
            row = ttk.Frame(frame, style="Card.TFrame", padding=10)
            row.pack(fill="x")
            shown = tk.StringVar(value="•" * 14 if secret else (value or "—"))
            ttk.Label(row, textvariable=shown, style="Card.TLabel", font=("Courier", 11) if secret else ("Helvetica", 11)).pack(side="left", fill="x", expand=True)
            if secret:
                visible = tk.BooleanVar()
                ttk.Button(row, text="Reveal", command=lambda: [visible.set(not visible.get()), shown.set(value if visible.get() else "•" * 14)]).pack(side="right", padx=5)
            if value:
                ttk.Button(row, text="Copy", command=lambda: self.copy_sensitive(value, label)).pack(side="right")

        value_row("Website", item.website)
        value_row("Username", item.username)
        value_row("Password", item.password, True)
        ttk.Label(frame, text="NOTES", foreground=MUTED, font=("Helvetica", 9, "bold")).pack(anchor="w", pady=(15, 4))
        ttk.Label(frame, text=item.notes or "No notes added.", wraplength=560, justify="left").pack(anchor="w")
        if item.tags:
            ttk.Label(frame, text=f"Tags: {item.tags}", style="Muted.TLabel").pack(anchor="w", pady=12)
        bottom = ttk.Frame(frame)
        bottom.pack(fill="x", side="bottom")

        def edit() -> None:
            dialog.destroy()
            self._credential_dialog(item, on_changed)

        ttk.Button(bottom, text="Edit account", style="Accent.TButton", command=edit).pack(side="left")
        ttk.Button(bottom, text="Close", command=dialog.destroy).pack(side="right")

    def copy_sensitive(self, value: str, label: str = "Value") -> None:
        self.clipboard_clear()
        self.clipboard_append(value)
        self.update()
        self.clipboard_value = value
        seconds = int(self.database.get_meta("clipboard_seconds") or "20")
        self.after(seconds * 1000, lambda expected=value: self._clear_clipboard_if_matches(expected))
        messagebox.showinfo("Copied", f"{label} copied. Clipboard will clear in {seconds} seconds.", parent=self)

    def _clear_clipboard_if_matches(self, expected: str) -> None:
        if self.clipboard_value != expected:
            return
        try:
            if self.clipboard_get() == expected:
                self.clipboard_clear()
        except tk.TclError:
            pass
        self.clipboard_value = None

    def _clear_clipboard_now(self) -> None:
        if self.clipboard_value is not None:
            self._clear_clipboard_if_matches(self.clipboard_value)

    def _build_generator_page(self, parent: ttk.Frame) -> None:
        self._page_header(parent, "Password generator", "Create strong passwords with cryptographically secure randomness")
        card = ttk.Frame(parent, style="Card.TFrame", padding=28)
        card.pack(fill="x")
        output = tk.StringVar()
        mode = tk.StringVar(value="password")
        mode_row = ttk.Frame(card, style="Card.TFrame")
        mode_row.pack(fill="x")
        ttk.Radiobutton(mode_row, text="Random password", variable=mode, value="password").pack(side="left")
        ttk.Radiobutton(mode_row, text="Memorable passphrase", variable=mode, value="passphrase").pack(side="left", padx=18)
        output_entry = ttk.Entry(card, textvariable=output, font=("Courier", 15))
        output_entry.pack(fill="x", pady=22)
        meter = ttk.Progressbar(card, maximum=100)
        meter.pack(fill="x")
        strength = tk.StringVar()
        ttk.Label(card, textvariable=strength, style="CardMuted.TLabel").pack(anchor="w", pady=(7, 18))
        options = ttk.Frame(card, style="Card.TFrame")
        options.pack(fill="x")
        length = tk.IntVar(value=20)
        ttk.Label(options, text="Length / words", style="Card.TLabel").grid(row=0, column=0, sticky="w", pady=8)
        ttk.Spinbox(options, from_=3, to=128, textvariable=length, width=8).grid(row=0, column=1, sticky="w", padx=12)
        upper = tk.BooleanVar(value=True)
        lower = tk.BooleanVar(value=True)
        numbers = tk.BooleanVar(value=True)
        symbols = tk.BooleanVar(value=True)
        confusing = tk.BooleanVar(value=True)
        for index, (label, variable) in enumerate((
            ("Uppercase letters", upper), ("Lowercase letters", lower),
            ("Numbers", numbers), ("Symbols", symbols),
            ("Exclude O, 0, l, 1", confusing),
        )):
            ttk.Checkbutton(options, text=label, variable=variable, style="Card.TCheckbutton").grid(row=1 + index // 2, column=index % 2, sticky="w", pady=7, padx=(0, 25))

        def make() -> None:
            try:
                if mode.get() == "passphrase":
                    result = generate_passphrase(length.get())
                else:
                    result = generate_password(length.get(), uppercase=upper.get(), lowercase=lower.get(), numbers=numbers.get(), symbols=symbols.get(), exclude_confusing=confusing.get())
            except ValueError as exc:
                messagebox.showerror("Generator options", str(exc), parent=self)
                return
            output.set(result)

        def update_meter(*_args) -> None:
            result = assess_password(output.get())
            meter["value"] = result.score
            strength.set(f"{result.label} · Estimated strength score {result.score}/100")

        output.trace_add("write", update_meter)
        button_row = ttk.Frame(card, style="Card.TFrame")
        button_row.pack(fill="x", pady=(24, 0))
        ttk.Button(button_row, text="Generate new", style="Accent.TButton", command=make).pack(side="left")
        ttk.Button(button_row, text="Copy securely", command=lambda: self.copy_sensitive(output.get(), "Password") if output.get() else None).pack(side="left", padx=10)
        make()

    def _build_health_page(self, parent: ttk.Frame) -> None:
        self._page_header(parent, "Vault health", "Find passwords that deserve your attention")
        report = self.vault.health()
        hero = ttk.Frame(parent, style="Card.TFrame", padding=28)
        hero.pack(fill="x", pady=(0, 18))
        left = ttk.Frame(hero, style="Card.TFrame")
        left.pack(side="left")
        ttk.Label(left, text=str(report.score), style="Metric.TLabel", font=("Helvetica", 48, "bold")).pack(anchor="w")
        ttk.Label(left, text="OVERALL HEALTH SCORE", style="CardMuted.TLabel").pack(anchor="w")
        ttk.Progressbar(hero, maximum=100, value=report.score, length=460).pack(side="right", padx=20)
        metrics = ttk.Frame(parent)
        metrics.pack(fill="both", expand=True)
        data = (
            ("Total accounts", report.total, "All credentials in this vault", GREEN),
            ("Weak passwords", report.weak, "Below Good strength", DANGER if report.weak else GREEN),
            ("Reused passwords", report.reused, "Accounts sharing a password", DANGER if report.reused else GREEN),
            ("Old passwords", report.old, f"Not updated in {self.database.get_meta('old_password_days') or '180'} days", WARNING if report.old else GREEN),
            ("Missing notes", report.incomplete, "No recovery information", WARNING if report.incomplete else GREEN),
        )
        for index, (label, value, detail, color) in enumerate(data):
            card = ttk.Frame(metrics, style="Card.TFrame", padding=22)
            card.grid(row=index // 3, column=index % 3, sticky="nsew", padx=(0 if index % 3 == 0 else 9, 0), pady=(0, 10))
            tk.Label(card, text=str(value), bg=CARD, fg=color, font=("Helvetica", 27, "bold")).pack(anchor="w")
            ttk.Label(card, text=label, style="CardTitle.TLabel").pack(anchor="w", pady=(5, 3))
            ttk.Label(card, text=detail, style="CardMuted.TLabel", wraplength=220).pack(anchor="w")
        for column in range(3):
            metrics.columnconfigure(column, weight=1)
        ttk.Label(parent, text="Passwords are assessed locally and never leave this device.", style="Muted.TLabel").pack(anchor="w", pady=8)

    def _build_settings_page(self, parent: ttk.Frame) -> None:
        self._page_header(parent, "Settings & recovery", "Control security, backups, and automatic privacy features")
        card = ttk.Frame(parent, style="Card.TFrame", padding=26)
        card.pack(fill="x", pady=(0, 15))
        ttk.Label(card, text="Automatic security", style="CardTitle.TLabel").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 15))
        inactivity = tk.IntVar(value=int(self.database.get_meta("inactivity_minutes") or "5"))
        clipboard = tk.IntVar(value=int(self.database.get_meta("clipboard_seconds") or "20"))
        old_days = tk.IntVar(value=int(self.database.get_meta("old_password_days") or "180"))
        for row, (label, variable, values, suffix) in enumerate((
            ("Lock vault after inactivity", inactivity, (1, 2, 5, 10, 15, 30), "minutes"),
            ("Clear copied secrets after", clipboard, (10, 15, 20, 30, 60), "seconds"),
            ("Flag passwords older than", old_days, (30, 60, 90, 180, 365), "days"),
        ), start=1):
            ttk.Label(card, text=label, style="Card.TLabel").grid(row=row, column=0, sticky="w", pady=9)
            row_frame = ttk.Frame(card, style="Card.TFrame")
            row_frame.grid(row=row, column=1, sticky="e", pady=6)
            ttk.Combobox(row_frame, textvariable=variable, values=values, state="readonly", width=7).pack(side="left")
            ttk.Label(row_frame, text=suffix, style="CardMuted.TLabel").pack(side="left", padx=8)
        card.columnconfigure(0, weight=1)

        def save_settings() -> None:
            self.database.set_meta_many({
                "inactivity_minutes": str(inactivity.get()),
                "clipboard_seconds": str(clipboard.get()),
                "old_password_days": str(old_days.get()),
            })
            self.last_activity = time.monotonic()
            messagebox.showinfo("Settings saved", "Your security preferences were updated.", parent=self)

        ttk.Button(card, text="Save preferences", style="Accent.TButton", command=save_settings).grid(row=4, column=0, columnspan=2, sticky="ew", pady=(18, 0))

        security = ttk.Frame(parent, style="Card.TFrame", padding=26)
        security.pack(fill="x", pady=(0, 15))
        ttk.Label(security, text="Master password", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(security, text="Changing it re-wraps your vault key without exposing any saved password.", style="CardMuted.TLabel").pack(anchor="w", pady=(5, 12))
        ttk.Button(security, text="Change master password", command=self._change_master_dialog).pack(anchor="w")

        backup = ttk.Frame(parent, style="Card.TFrame", padding=26)
        backup.pack(fill="x")
        ttk.Label(backup, text="Encrypted backup", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(backup, text="Backups remain encrypted and can only be restored into this vault.", style="CardMuted.TLabel").pack(anchor="w", pady=(5, 12))
        ttk.Button(backup, text="Create backup", command=self._create_backup).pack(side="left")
        ttk.Button(backup, text="Restore backup", command=self._restore_backup).pack(side="left", padx=10)

    def _change_master_dialog(self, required: bool = False) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Set a new master password")
        dialog.geometry("570x410")
        dialog.configure(bg=APP_BG)
        dialog.transient(self)
        dialog.grab_set()
        if required:
            dialog.protocol("WM_DELETE_WINDOW", lambda: None)
        frame = ttk.Frame(dialog, padding=30)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Set a new master password", style="Heading.TLabel").pack(anchor="w")
        ttk.Label(frame, text="Use at least 12 characters with Good or Strong strength.", style="Muted.TLabel").pack(anchor="w", pady=(6, 18))
        first = tk.StringVar()
        second = tk.StringVar()
        ttk.Label(frame, text="New master password").pack(anchor="w")
        ttk.Entry(frame, textvariable=first, show="•").pack(fill="x", pady=(5, 13))
        ttk.Label(frame, text="Confirm new password").pack(anchor="w")
        ttk.Entry(frame, textvariable=second, show="•").pack(fill="x", pady=(5, 12))
        status = tk.StringVar()
        ttk.Label(frame, textvariable=status, style="Muted.TLabel").pack(anchor="w")
        first.trace_add("write", lambda *_: status.set(f"Strength: {assess_password(first.get()).label}"))

        def change() -> None:
            if first.get() != second.get():
                messagebox.showerror("Passwords do not match", "Enter the same password twice.", parent=dialog)
                return
            try:
                self.vault.change_master_password(first.get())
            except ValueError as exc:
                messagebox.showerror("Choose a stronger password", str(exc), parent=dialog)
                return
            dialog.destroy()
            messagebox.showinfo("Master password changed", "Your vault is now protected by the new password.", parent=self)

        ttk.Button(frame, text="Update master password", style="Accent.TButton", command=change).pack(fill="x", pady=20)

    def _create_backup(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self, title="Save encrypted backup",
            defaultextension=".svbackup",
            filetypes=[("SecureVault backup", "*.svbackup")],
            initialfile="securevault-backup.svbackup",
        )
        if not path:
            return
        Path(path).write_bytes(self.vault.backup())
        messagebox.showinfo("Backup created", "The encrypted backup was saved successfully.", parent=self)

    def _restore_backup(self) -> None:
        path = filedialog.askopenfilename(
            parent=self, title="Restore encrypted backup",
            filetypes=[("SecureVault backup", "*.svbackup"), ("All files", "*")],
        )
        if not path:
            return
        if not messagebox.askyesno("Replace current accounts?", "Restoring replaces all accounts currently in this vault.", parent=self):
            return
        try:
            count = self.vault.restore(Path(path).read_bytes())
        except Exception as exc:
            messagebox.showerror("Restore failed", str(exc), parent=self)
            return
        messagebox.showinfo("Restore complete", f"Restored {count} encrypted accounts.", parent=self)


def run() -> None:
    SecureVaultApp().mainloop()
