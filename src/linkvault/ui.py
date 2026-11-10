"""Tkinter desktop GUI for LinkVault."""

from __future__ import annotations

import contextlib
import hmac
import logging
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any

from linkvault.config import (
    APP_NAME,
    APP_VERSION,
    AUTO_LOCK_SECONDS,
    CLIPBOARD_CLEAR_MS,
    IDLE_CHECK_INTERVAL_MS,
    KDF_ITERATIONS,
    MIN_PASSWORD_LEN,
    default_links_copy,
)
from linkvault.crypto import VaultError, WrongPassword, active_cipher_label
from linkvault.logging_setup import log_unhandled_exception
from linkvault.storage import VaultStorage, export_links, import_links
from linkvault.validation import find_duplicate_link, normalize_url, validate_new_password

logger = logging.getLogger("linkvault")


class LinkVaultApp(tk.Tk):
    """Main Tkinter window managing authentication, vault table, and link actions."""

    COLUMNS: tuple[tuple[str, str, int], ...] = (
        ("title", "Title", 220),
        ("category", "Category", 140),
        ("url", "URL / Link", 280),
        ("notes", "Notes", 160),
    )

    def __init__(self, storage: VaultStorage) -> None:
        super().__init__()
        self.storage = storage

        self.title(f"{APP_NAME} - Safe Link Locker")
        self.geometry("920x620")
        self.minsize(760, 500)

        self.bg_color = "#121826"
        self.card_bg = "#1f293d"
        self.accent_color = "#3b82f6"
        self.accent_hover = "#2563eb"
        self.danger_color = "#ef4444"
        self.muted_color = "#9ca3af"
        self.configure(bg=self.bg_color)

        self.current_password: str | None = None
        self.links: list[dict[str, Any]] = []
        self.sort_col: str | None = None
        self.sort_reverse = False
        self.failed_attempts = 0
        self.locked_until = 0.0
        self.last_activity = time.time()
        self.status_job: str | None = None
        self._idle_job: str | None = None

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        for seq in ("<Key>", "<Button>", "<Motion>"):
            self.bind_all(seq, self._touch, add="+")
        self._schedule_idle_check()

        self._setup_styles()
        self.show_auth_screen()

    # ---- infrastructure ---------------------------------------------------
    def report_callback_exception(self, exc_type: Any, exc: Any, tb: Any) -> None:
        log_unhandled_exception(exc_type, exc, tb, logger=logger)
        messagebox.showerror(
            "Unexpected Error",
            f"{exc}\n\nDetails logged to:\n{self.storage.paths.log_file}",
        )

    def _on_close(self) -> None:
        self.current_password = None
        self.links = []
        if self._idle_job is not None:
            with contextlib.suppress(tk.TclError):
                self.after_cancel(self._idle_job)
            self._idle_job = None
        self.destroy()

    def _touch(self, _event: Any = None) -> None:
        self.last_activity = time.time()

    def _schedule_idle_check(self) -> None:
        self._idle_job = self.after(IDLE_CHECK_INTERVAL_MS, self._idle_check)

    def _idle_check(self) -> None:
        if (
            self.current_password is not None
            and (time.time() - self.last_activity) > AUTO_LOCK_SECONDS
        ):
            logger.info("Auto-locking vault after inactivity timeout.")
            self.lock_vault()
        self._schedule_idle_check()

    def _setup_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background="#1e293b",
            foreground="#f8fafc",
            rowheight=32,
            fieldbackground="#1e293b",
            bordercolor="#334155",
            borderwidth=0,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Treeview.Heading",
            background="#0f172a",
            foreground="#cbd5e1",
            relief="flat",
            font=("Segoe UI", 10, "bold"),
        )
        style.map("Treeview.Heading", background=[("active", "#1e293b")])
        style.map(
            "Treeview",
            background=[("selected", "#3b82f6")],
            foreground=[("selected", "#ffffff")],
        )

    def _clear_root(self) -> None:
        for widget in self.winfo_children():
            widget.destroy()

    def _unbind_vault_shortcuts(self) -> None:
        for seq in ("<Return>", "<Control-n>", "<Control-l>", "<Control-f>"):
            self.unbind(seq)

    def make_button(
        self,
        parent: tk.Misc,
        text: str,
        command: Any,
        bg: str | None = None,
        bold: bool = False,
        **kw: Any,
    ) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg or self.accent_color,
            fg="#ffffff",
            activebackground=self.accent_hover,
            activeforeground="#ffffff",
            font=("Segoe UI", 10, "bold" if bold else "normal"),
            relief="flat",
            cursor="hand2",
            padx=kw.pop("padx", 12),
            pady=kw.pop("pady", 4),
            **kw,
        )

    def make_entry(self, parent: tk.Misc, **kw: Any) -> tk.Entry:
        return tk.Entry(
            parent,
            bg="#111827",
            fg="#ffffff",
            insertbackground="#ffffff",
            relief="flat",
            highlightbackground="#4b5563",
            highlightthickness=1,
            **kw,
        )

    def set_status(self, message: str, ms: int = 4000) -> None:
        if hasattr(self, "status_lbl") and self.status_lbl.winfo_exists():
            self.status_lbl.config(text=message)
            if self.status_job:
                self.after_cancel(self.status_job)
            self.status_job = self.after(
                ms,
                lambda: self.status_lbl.winfo_exists() and self.status_lbl.config(text=""),
            )

    # ---- auth screen ------------------------------------------------------
    def show_auth_screen(self) -> None:
        self._unbind_vault_shortcuts()
        self.config(menu="")
        self._clear_root()
        is_first_run = not self.storage.vault_exists()

        box = tk.Frame(self, bg=self.bg_color)
        box.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        tk.Label(box, text="🛡️", font=("Segoe UI Emoji", 48), bg=self.bg_color).pack(pady=(0, 10))
        tk.Label(
            box,
            text=f"Safe {APP_NAME}",
            font=("Segoe UI", 22, "bold"),
            fg="#ffffff",
            bg=self.bg_color,
        ).pack()

        subtitle = (
            f"Create a master password (min {MIN_PASSWORD_LEN} characters)"
            if is_first_run
            else "Enter your master password to unlock"
        )
        tk.Label(
            box,
            text=subtitle,
            font=("Segoe UI", 11),
            fg=self.muted_color,
            bg=self.bg_color,
        ).pack(pady=(4, 25))

        card = tk.Frame(
            box,
            bg=self.card_bg,
            padx=30,
            pady=25,
            highlightbackground="#374151",
            highlightthickness=1,
        )
        card.pack(fill=tk.BOTH)

        def labeled_entry(text: str) -> tk.Entry:
            tk.Label(
                card,
                text=text,
                font=("Segoe UI", 10, "bold"),
                fg="#e5e7eb",
                bg=self.card_bg,
                anchor="w",
            ).pack(fill=tk.X, pady=(0, 6))
            entry = self.make_entry(card, show="●", font=("Segoe UI", 13), width=28)
            entry.pack(pady=(0, 12), ipady=5)
            return entry

        pwd_entry = labeled_entry("Master Password:")
        pwd_entry.focus()
        confirm_entry = labeled_entry("Confirm Password:") if is_first_run else None

        show_var = tk.BooleanVar(value=False)

        def toggle_show() -> None:
            mark = "" if show_var.get() else "●"
            pwd_entry.config(show=mark)
            if confirm_entry:
                confirm_entry.config(show=mark)

        tk.Checkbutton(
            card,
            text="Show password",
            variable=show_var,
            command=toggle_show,
            bg=self.card_bg,
            fg="#cbd5e1",
            selectcolor="#111827",
            activebackground=self.card_bg,
            activeforeground="#ffffff",
            font=("Segoe UI", 9),
        ).pack(anchor="w")

        error_lbl = tk.Label(
            card,
            text="",
            font=("Segoe UI", 9),
            fg="#f87171",
            bg=self.card_bg,
            wraplength=320,
            justify="left",
        )
        error_lbl.pack(pady=(6, 8))

        def handle_auth(_event: Any = None) -> None:
            # Preserve leading/trailing spaces because spaces can be part of a passphrase.
            pwd = pwd_entry.get()
            wait = self.locked_until - time.time()
            if wait > 0:
                error_lbl.config(
                    text=f"Too many failed attempts. Wait {int(wait) + 1}s.",
                    fg="#f87171",
                )
                return

            if is_first_run:
                confirm_val = confirm_entry.get() if confirm_entry else None
                err = validate_new_password(pwd, confirm_val)
                if err:
                    error_lbl.config(text=err, fg="#f87171")
                    return
                self.current_password = pwd
                self.links = default_links_copy()
                self.storage.save(self.links, pwd)
                logger.info("Initialized new encrypted vault.")
                self.show_main_vault()
                return

            if not pwd:
                error_lbl.config(text="Password cannot be empty.", fg="#f87171")
                return

            error_lbl.config(text="Unlocking...", fg="#9ca3af")
            self.update_idletasks()
            try:
                items, needs_upgrade = self.storage.load(pwd)
            except WrongPassword:
                self.failed_attempts += 1
                if self.failed_attempts >= 3:
                    self.locked_until = time.time() + min(2 ** (self.failed_attempts - 3), 30)
                error_lbl.config(text="Incorrect password. Please try again.", fg="#f87171")
                pwd_entry.delete(0, tk.END)
                return
            except VaultError as exc:
                if self.storage.backup_exists() and messagebox.askyesno(
                    "Vault Recovery",
                    f"Primary vault could not be unlocked:\n{exc}\n\n"
                    f"Try unlocking the automatic backup ({self.storage.paths.backup_file.name})?",
                ):
                    try:
                        items, _ = self.storage.load(pwd, from_backup=True)
                        self.storage.save(items, pwd)
                        needs_upgrade = False
                        logger.warning("Restored primary vault from backup.")
                    except VaultError as bak_exc:
                        error_lbl.config(
                            text=f"Backup recovery failed: {bak_exc}",
                            fg="#f87171",
                        )
                        return
                else:
                    error_lbl.config(text=f"Vault file error: {exc}", fg="#f87171")
                    return

            self.failed_attempts = 0
            self.current_password = pwd
            self.links = items
            upgraded = False
            if needs_upgrade:
                self.storage.save(self.links, pwd)
                upgraded = True
                logger.info("Upgraded vault encryption format to latest v2 defaults.")
            self.show_main_vault()
            if upgraded:
                self.set_status("Vault upgraded to latest encryption format.", ms=6000)

        self.bind("<Return>", handle_auth)
        self.make_button(
            card,
            "Set Password & Unlock Safe" if is_first_run else "Unlock Vault",
            handle_auth,
            bold=True,
            pady=6,
        ).pack(fill=tk.X, ipady=2)

    # ---- main screen ------------------------------------------------------
    def build_menu(self) -> None:
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Add new link\tCtrl+N", command=self.popup_add_edit)
        file_menu.add_separator()
        file_menu.add_command(label="Import (JSON / CSV)...", command=self.import_links_dialog)
        file_menu.add_command(
            label="Export as JSON...",
            command=lambda: self.export_links_dialog("json"),
        )
        file_menu.add_command(
            label="Export as CSV...",
            command=lambda: self.export_links_dialog("csv"),
        )
        file_menu.add_separator()
        file_menu.add_command(label="Change master password...", command=self.change_password)
        file_menu.add_command(label="Lock vault\tCtrl+L", command=self.lock_vault)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label=f"About {APP_NAME}", command=self.show_about_dialog)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def show_main_vault(self) -> None:
        self.unbind("<Return>")
        self._clear_root()
        self.build_menu()
        self._touch()

        header = tk.Frame(self, bg="#0f172a", padx=20, pady=10)
        header.pack(fill=tk.X)
        tk.Label(
            header,
            text=f"🛡️ {APP_NAME}",
            font=("Segoe UI", 14, "bold"),
            fg="#38bdf8",
            bg="#0f172a",
        ).pack(side=tk.LEFT)
        tk.Label(
            header,
            text=f"  Encrypted: {active_cipher_label()}",
            font=("Segoe UI", 9),
            fg=self.muted_color,
            bg="#0f172a",
        ).pack(side=tk.LEFT, padx=6)
        self.make_button(header, "🔒 Lock", self.lock_vault, bg="#334155", bold=True).pack(
            side=tk.RIGHT
        )

        bar = tk.Frame(self, bg=self.bg_color, padx=20, pady=12)
        bar.pack(fill=tk.X)
        tk.Label(
            bar,
            text="Search:",
            font=("Segoe UI", 10, "bold"),
            fg="#e2e8f0",
            bg=self.bg_color,
        ).pack(side=tk.LEFT, padx=(0, 8))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.refresh_table())
        self.search_entry = tk.Entry(
            bar,
            textvariable=self.search_var,
            font=("Segoe UI", 11),
            bg="#1e293b",
            fg="#ffffff",
            insertbackground="#ffffff",
            relief="flat",
            highlightbackground="#475569",
            highlightthickness=1,
            width=26,
        )
        self.search_entry.pack(side=tk.LEFT, ipady=3)

        tk.Label(
            bar,
            text="Category:",
            font=("Segoe UI", 10, "bold"),
            fg="#e2e8f0",
            bg=self.bg_color,
        ).pack(side=tk.LEFT, padx=(16, 8))
        self.category_var = tk.StringVar(value="All")
        self.category_box = ttk.Combobox(
            bar,
            textvariable=self.category_var,
            state="readonly",
            width=24,
            values=["All"],
        )
        self.category_box.pack(side=tk.LEFT)
        self.category_box.bind("<<ComboboxSelected>>", lambda _e: self.refresh_table())

        self.make_button(
            bar,
            "+ Add New Link",
            self.popup_add_edit,
            bold=True,
            padx=14,
        ).pack(side=tk.RIGHT)

        frame = tk.Frame(self, bg=self.bg_color, padx=20)
        frame.pack(fill=tk.BOTH, expand=True)
        self.tree = ttk.Treeview(
            frame,
            columns=[col[0] for col in self.COLUMNS],
            show="headings",
            selectmode="browse",
        )
        for key, label, width in self.COLUMNS:
            self.tree.heading(key, text=label, command=lambda k=key: self.sort_by(k))
            self.tree.column(key, width=width, minwidth=100)
        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.ctx = tk.Menu(self, tearoff=0)
        self.ctx.add_command(label="Open", command=self.open_selected_url)
        self.ctx.add_command(label="Copy URL", command=self.copy_selected_url)
        self.ctx.add_command(label="Edit", command=self.edit_selected)
        self.ctx.add_separator()
        self.ctx.add_command(label="Delete", command=self.delete_selected)

        self.tree.bind("<Button-3>", self._show_context_menu)
        self.tree.bind("<Double-1>", lambda _e: self.open_selected_url())
        self.tree.bind("<Return>", lambda _e: self.open_selected_url())
        self.tree.bind("<Delete>", lambda _e: self.delete_selected())

        self.bind("<Control-n>", lambda _e: self.popup_add_edit())
        self.bind("<Control-l>", lambda _e: self.lock_vault())
        self.bind("<Control-f>", lambda _e: self.search_entry.focus_set())

        footer = tk.Frame(self, bg=self.card_bg, padx=20, pady=12)
        footer.pack(fill=tk.X, side=tk.BOTTOM)
        self.make_button(
            footer,
            "🌐 Open",
            self.open_selected_url,
            bg="#10b981",
            bold=True,
            padx=14,
        ).pack(side=tk.LEFT, padx=(0, 10))
        self.make_button(footer, "📋 Copy URL", self.copy_selected_url).pack(
            side=tk.LEFT, padx=(0, 10)
        )
        self.make_button(footer, "✏️ Edit", self.edit_selected, bg="#64748b").pack(
            side=tk.LEFT, padx=(0, 10)
        )
        self.make_button(footer, "🗑️ Delete", self.delete_selected, bg=self.danger_color).pack(
            side=tk.LEFT
        )
        self.count_lbl = tk.Label(
            footer,
            font=("Segoe UI", 10),
            fg=self.muted_color,
            bg=self.card_bg,
        )
        self.count_lbl.pack(side=tk.RIGHT)
        self.status_lbl = tk.Label(
            footer,
            font=("Segoe UI", 10),
            fg="#34d399",
            bg=self.card_bg,
        )
        self.status_lbl.pack(side=tk.RIGHT, padx=20)

        self.refresh_table()

    def _show_context_menu(self, event: Any) -> None:
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self.ctx.tk_popup(event.x_root, event.y_root)

    # ---- table ------------------------------------------------------------
    def sort_by(self, column: str) -> None:
        self.sort_reverse = (not self.sort_reverse) if self.sort_col == column else False
        self.sort_col = column
        self.refresh_table()

    def _existing_categories(self) -> list[str]:
        return sorted(
            {str(x.get("category", "")) for x in self.links if x.get("category")},
            key=str.lower,
        )

    def refresh_table(self) -> None:
        query = self.search_var.get().lower().strip()
        categories = self._existing_categories()
        self.category_box["values"] = ["All"] + categories
        if self.category_var.get() not in self.category_box["values"]:
            self.category_var.set("All")
        chosen = self.category_var.get()

        rows: list[tuple[Any, dict[str, str]]] = []
        for item in self.links:
            values = {k: str(item.get(k, "")) for k, _l, _w in self.COLUMNS}
            if chosen != "All" and values["category"] != chosen:
                continue
            if query and not any(query in v.lower() for v in values.values()):
                continue
            rows.append((item.get("id"), values))

        if self.sort_col:
            sort_key = self.sort_col
            rows.sort(key=lambda r: r[1][sort_key].lower(), reverse=self.sort_reverse)

        self.tree.delete(*self.tree.get_children())
        for item_id, values in rows:
            self.tree.insert(
                "",
                tk.END,
                iid=str(item_id),
                values=tuple(values[k] for k, _l, _w in self.COLUMNS),
            )

        for key, label, _w in self.COLUMNS:
            arrow = (" ▼" if self.sort_reverse else " ▲") if key == self.sort_col else ""
            self.tree.heading(key, text=label + arrow)
        self.count_lbl.config(text=f"Showing {len(rows)} of {len(self.links)} links")

    def get_selected_item(self) -> dict[str, Any] | None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a link row first.")
            return None
        target_id = str(selected[0])
        return next((x for x in self.links if str(x.get("id")) == target_id), None)

    # ---- actions ----------------------------------------------------------
    def open_selected_url(self) -> None:
        if self.current_password is None:
            return
        item = self.get_selected_item()
        if not item:
            return
        url = normalize_url(str(item.get("url", "")))
        if url:
            webbrowser.open(url)
        else:
            messagebox.showerror("Invalid URL", "Only valid http/https links can be opened.")

    def copy_selected_url(self) -> None:
        if self.current_password is None:
            return
        item = self.get_selected_item()
        if not item:
            return
        text = str(item.get("url", ""))
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        secs = CLIPBOARD_CLEAR_MS // 1000
        self.set_status(f"Copied! Clipboard will auto-clear in {secs}s.")
        self.after(CLIPBOARD_CLEAR_MS, lambda: self._clear_clipboard_if(text))

    def _clear_clipboard_if(self, text: str) -> None:
        with contextlib.suppress(tk.TclError):
            if self.clipboard_get() == text:
                self.clipboard_clear()
                self.clipboard_append("")

    def delete_selected(self) -> None:
        if self.current_password is None:
            return
        item = self.get_selected_item()
        if item and messagebox.askyesno("Confirm Delete", f"Delete '{item.get('title')}'?"):
            target_id = item.get("id")
            self.links = [x for x in self.links if x.get("id") != target_id]
            self.storage.save(self.links, self.current_password)
            self.refresh_table()
            self.set_status("Deleted.")

    def edit_selected(self) -> None:
        if self.current_password is None:
            return
        item = self.get_selected_item()
        if item:
            self.popup_add_edit(item)

    def popup_add_edit(self, edit_item: dict[str, Any] | None = None) -> None:
        if self.current_password is None:
            return

        win = tk.Toplevel(self)
        win.title("Edit Link" if edit_item else "Add Safe Link")
        win.geometry("500x400")
        win.configure(bg=self.bg_color)
        win.transient(self)
        win.grab_set()

        frm = tk.Frame(win, bg=self.bg_color, padx=25, pady=20)
        frm.pack(fill=tk.BOTH, expand=True)
        frm.columnconfigure(0, weight=1)

        def make_field(label: str, row: int) -> tk.Entry:
            tk.Label(
                frm,
                text=label,
                font=("Segoe UI", 9, "bold"),
                fg="#e2e8f0",
                bg=self.bg_color,
                anchor="w",
            ).grid(row=row, column=0, sticky="w", pady=(6, 2))
            entry = tk.Entry(
                frm,
                font=("Segoe UI", 10),
                bg="#1e293b",
                fg="#ffffff",
                insertbackground="#ffffff",
                relief="flat",
                highlightbackground="#475569",
                highlightthickness=1,
            )
            entry.grid(row=row + 1, column=0, sticky="ew", ipady=3)
            return entry

        title_e = make_field("Title / Name:", 0)
        url_e = make_field("URL / Web Link:", 2)

        tk.Label(
            frm,
            text="Category (e.g., Coding, Career, Tech):",
            font=("Segoe UI", 9, "bold"),
            fg="#e2e8f0",
            bg=self.bg_color,
            anchor="w",
        ).grid(row=4, column=0, sticky="w", pady=(6, 2))
        cat_e = ttk.Combobox(
            frm,
            values=self._existing_categories(),
            font=("Segoe UI", 10),
        )
        cat_e.grid(row=5, column=0, sticky="ew", ipady=2)

        notes_e = make_field("Notes / Tags (Optional):", 6)
        title_e.focus()

        if edit_item:
            title_e.insert(0, str(edit_item.get("title", "")))
            url_e.insert(0, str(edit_item.get("url", "")))
            cat_e.set(str(edit_item.get("category", "")))
            notes_e.insert(0, str(edit_item.get("notes", "")))

        def save_action(_event: Any = None) -> None:
            if self.current_password is None:
                win.destroy()
                return

            title = title_e.get().strip()
            url = normalize_url(url_e.get())
            category = cat_e.get().strip() or "General"
            notes = notes_e.get().strip()

            if not title:
                messagebox.showerror("Validation Error", "Title is required.", parent=win)
                return
            if not url:
                messagebox.showerror(
                    "Validation Error",
                    "Please enter a valid http/https URL.",
                    parent=win,
                )
                return

            duplicate = find_duplicate_link(self.links, url, exclude_item=edit_item)
            if duplicate and not messagebox.askyesno(
                "Duplicate URL",
                f"This URL is already saved as '{duplicate.get('title')}'.\nSave anyway?",
                parent=win,
            ):
                return

            if edit_item is not None:
                edit_item.update(title=title, url=url, category=category, notes=notes)
            else:
                max_id = max(
                    (int(x.get("id", 0)) for x in self.links if str(x.get("id", "")).isdigit()),
                    default=0,
                )
                self.links.append(
                    {
                        "id": max_id + 1,
                        "title": title,
                        "url": url,
                        "category": category,
                        "notes": notes,
                    }
                )

            self.storage.save(self.links, self.current_password)
            self.refresh_table()
            self.set_status("Saved.")
            win.destroy()

        win.bind("<Return>", save_action)
        win.bind("<Escape>", lambda _e: win.destroy())

        btns = tk.Frame(frm, bg=self.bg_color)
        btns.grid(row=8, column=0, sticky="ew", pady=(20, 0))
        self.make_button(btns, "Save Link", save_action, bold=True, padx=16).pack(side=tk.RIGHT)
        self.make_button(btns, "Cancel", win.destroy, bg="#475569").pack(side=tk.RIGHT, padx=10)

    # ---- import / export / password / about -------------------------------
    def export_links_dialog(self, fmt: str) -> None:
        if self.current_password is None:
            return
        if not messagebox.askyesno(
            "Plain-Text Export Warning",
            "The exported file will NOT be encrypted—all saved links will be readable.\n\nContinue?",
        ):
            return
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            initialfile=f"linkvault_export.{fmt}",
            filetypes=[(fmt.upper(), f"*.{fmt}")],
        )
        if not path:
            return
        count = export_links(self.links, path, fmt)
        self.set_status(f"Exported {count} links.")

    def import_links_dialog(self) -> None:
        if self.current_password is None:
            return
        path = filedialog.askopenfilename(filetypes=[("JSON / CSV", "*.json *.csv")])
        if not path:
            return
        try:
            merged, added, skipped = import_links(path, self.links)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Import Failed", str(exc))
            return

        if added:
            self.links = merged
            self.storage.save(self.links, self.current_password)
            self.refresh_table()
        messagebox.showinfo(
            "Import Complete",
            f"Added: {added}\nSkipped (duplicate or invalid): {skipped}",
        )

    def change_password(self) -> None:
        if self.current_password is None:
            return
        old = simpledialog.askstring(
            "Change Password",
            "Current master password:",
            show="●",
            parent=self,
        )
        if old is None:
            return
        if not hmac.compare_digest(old.encode("utf-8"), self.current_password.encode("utf-8")):
            messagebox.showerror("Error", "Current password is incorrect.")
            return

        new = simpledialog.askstring(
            "Change Password",
            f"New password (min {MIN_PASSWORD_LEN} characters):",
            show="●",
            parent=self,
        )
        if new is None:
            return
        confirm = simpledialog.askstring(
            "Change Password",
            "Confirm new password:",
            show="●",
            parent=self,
        )
        if confirm is None:
            return
        err = validate_new_password(new, confirm)
        if err:
            messagebox.showerror("Error", err)
            return

        self.storage.save(self.links, new)
        self.current_password = new
        logger.info("Master password changed.")
        self.set_status("Master password changed.")

    def show_about_dialog(self) -> None:
        messagebox.showinfo(
            f"About {APP_NAME}",
            f"{APP_NAME} v{APP_VERSION}\n\n"
            f"Cipher: {active_cipher_label()}\n"
            f"KDF: PBKDF2-HMAC-SHA256 ({KDF_ITERATIONS:,} iterations)\n"
            f"Vault location:\n{self.storage.paths.data_file}",
            parent=self,
        )

    def lock_vault(self) -> None:
        self.current_password = None
        self.links = []
        self.show_auth_screen()
