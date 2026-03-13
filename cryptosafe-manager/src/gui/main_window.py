from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.core.audit import AuditLogger
from src.core.config import ConfigManager
from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import Argon2Config, KeyManager, PBKDF2Config, PasswordPolicy
from src.core.crypto.key_storage import CachePolicy, SecureKeyCache
from src.core.crypto.placeholder import AES256Placeholder
from src.core.events import EntryAdded, EventBus
from src.core.state_manager import StateManager
from src.core.utils import validate_safe_text
from src.database.db import Database
from src.gui.widgets import PasswordEntry, SecureTable, SettingsDialog


class SetupWizard(tk.Toplevel):
    def __init__(self, master, cfg_mgr: ConfigManager):
        super().__init__(master)
        self.title("Первоначальная настройка")
        self.geometry("560x420")
        self.transient(master)
        self.grab_set()

        self.cfg_mgr = cfg_mgr
        self.result = None
        self._build()

    def _build(self) -> None:
        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True, padx=14, pady=14)

        ttk.Label(frm, text="Создайте мастер-пароль", font=("TkDefaultFont", 10, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(frm, text="Пароль:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.pw1 = PasswordEntry(frm)
        self.pw1.grid(row=2, column=0, sticky="ew")

        ttk.Label(frm, text="Повтор:").grid(row=3, column=0, sticky="w", pady=(8, 0))
        self.pw2 = PasswordEntry(frm)
        self.pw2.grid(row=4, column=0, sticky="ew")

        ttk.Separator(frm).grid(row=5, column=0, sticky="ew", pady=14)

        ttk.Label(frm, text="Файл БД", font=("TkDefaultFont", 10, "bold")).grid(row=6, column=0, sticky="w")
        self.db_path_var = tk.StringVar(value=self.cfg_mgr.load().db_path)
        row_db = ttk.Frame(frm)
        row_db.grid(row=7, column=0, sticky="ew", pady=(8, 0))
        ttk.Entry(row_db, textvariable=self.db_path_var).pack(side="left", fill="x", expand=True)
        ttk.Button(row_db, text="Выбрать...", command=self._choose_db).pack(side="left", padx=(8, 0))

        btns = ttk.Frame(frm)
        btns.grid(row=11, column=0, sticky="e", pady=(18, 0))
        ttk.Button(btns, text="Отмена", command=self._cancel).pack(side="right")
        ttk.Button(btns, text="Создать", command=self._finish).pack(side="right", padx=(0, 8))

        frm.columnconfigure(0, weight=1)
        self.pw1.focus()

    def _choose_db(self) -> None:
        p = filedialog.asksaveasfilename(
            title="Выберите файл базы данных",
            defaultextension=".sqlite3",
            filetypes=[("SQLite DB", "*.sqlite3"), ("All files", "*.*")],
        )
        if p:
            self.db_path_var.set(p)

    def _cancel(self) -> None:
        self.result = None
        self.destroy()

    def _finish(self) -> None:
        pw1 = self.pw1.get()
        pw2 = self.pw2.get()
        if pw1 != pw2:
            messagebox.showerror("Ошибка", "Пароли не совпадают")
            return
        db_path = self.db_path_var.get().strip()
        if not db_path:
            messagebox.showerror("Ошибка", "Укажите путь к БД")
            return
        self.result = (db_path, pw1)
        self.destroy()


class LoginDialog(tk.Toplevel):
    def __init__(self, master, auth: AuthenticationManager):
        super().__init__(master)
        self.title("Вход")
        self.geometry("420x180")
        self.transient(master)
        self.grab_set()
        self.auth = auth
        self.success = False

        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True, padx=14, pady=14)

        ttk.Label(frm, text="Введите мастер-пароль").pack(anchor="w")
        self.password = PasswordEntry(frm)
        self.password.pack(fill="x", pady=(8, 0))
        self.message_var = tk.StringVar(value="")
        ttk.Label(frm, textvariable=self.message_var).pack(anchor="w", pady=(8, 0))

        btns = ttk.Frame(frm)
        btns.pack(anchor="e", pady=(12, 0))
        ttk.Button(btns, text="Войти", command=self._login).pack(side="right")
        ttk.Button(btns, text="Отмена", command=self._cancel).pack(side="right", padx=(0, 8))
        self.password.focus()

    def _login(self) -> None:
        ok, msg = self.auth.authenticate(self.password.get())
        if ok:
            self.success = True
            self.destroy()
            return
        self.message_var.set(msg or "Ошибка входа")

    def _cancel(self) -> None:
        self.success = False
        self.destroy()


class ChangePasswordDialog(tk.Toplevel):
    def __init__(self, master, auth: AuthenticationManager):
        super().__init__(master)
        self.title("Смена пароля")
        self.geometry("480x300")
        self.transient(master)
        self.grab_set()
        self.auth = auth

        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True, padx=14, pady=14)

        ttk.Label(frm, text="Текущий пароль").grid(row=0, column=0, sticky="w")
        self.cur = PasswordEntry(frm)
        self.cur.grid(row=1, column=0, sticky="ew")

        ttk.Label(frm, text="Новый пароль").grid(row=2, column=0, sticky="w", pady=(10, 0))
        self.new1 = PasswordEntry(frm)
        self.new1.grid(row=3, column=0, sticky="ew")

        ttk.Label(frm, text="Подтверждение нового пароля").grid(row=4, column=0, sticky="w", pady=(10, 0))
        self.new2 = PasswordEntry(frm)
        self.new2.grid(row=5, column=0, sticky="ew")

        self.progress = ttk.Progressbar(frm, mode="determinate")
        self.progress.grid(row=6, column=0, sticky="ew", pady=(14, 0))

        self.msg_var = tk.StringVar(value="")
        ttk.Label(frm, textvariable=self.msg_var).grid(row=7, column=0, sticky="w", pady=(8, 0))

        btns = ttk.Frame(frm)
        btns.grid(row=8, column=0, sticky="e", pady=(12, 0))
        ttk.Button(btns, text="Сменить", command=self._submit).pack(side="right")
        ttk.Button(btns, text="Закрыть", command=self.destroy).pack(side="right", padx=(0, 8))
        frm.columnconfigure(0, weight=1)

    def _submit(self) -> None:
        current = self.cur.get()
        new1 = self.new1.get()
        new2 = self.new2.get()
        if new1 != new2:
            self.msg_var.set("Новые пароли не совпадают")
            return

        def progress(done, total):
            self.progress["maximum"] = max(1, total)
            self.progress["value"] = done
            self.update_idletasks()

        ok, msg = self.auth.rotate_password(current, new1, progress_callback=progress)
        if ok:
            self.msg_var.set("Пароль успешно изменён")
        else:
            self.msg_var.set(msg or "Ошибка смены пароля")


class MainWindow(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("CryptoSafe Manager (Sprint 2)")
        self.geometry("980x560")

        self.bus = EventBus()
        self.state = StateManager()
        self.cfg_mgr = ConfigManager(env=os.getenv("CRYPTOSAFE_ENV", "development"))
        self.cfg = self.cfg_mgr.load()

        self.db = Database(self.cfg.db_path, pool_size=4)
        self.db.initialize()

        self.key_manager = KeyManager(
            argon2_config=Argon2Config(
                time_cost=self.cfg.crypto.argon2_time,
                memory_cost=self.cfg.crypto.argon2_memory,
                parallelism=self.cfg.crypto.argon2_parallelism,
                hash_len=self.cfg.crypto.argon2_hash_len,
                salt_len=self.cfg.crypto.argon2_salt_len,
            ),
            pbkdf2_config=PBKDF2Config(
                iterations=self.cfg.crypto.pbkdf2_iterations,
                salt_len=self.cfg.crypto.pbkdf2_salt_len,
                dklen=self.cfg.crypto.pbkdf2_dklen,
            ),
            policy=PasswordPolicy(min_length=12),
        )
        self.key_cache = SecureKeyCache(CachePolicy(idle_timeout_seconds=self.cfg.auto_lock_seconds))
        self.auth = AuthenticationManager(self.db, self.key_manager, self.key_cache, self.bus)
        self.crypto = AES256Placeholder()

        self.audit = AuditLogger(self.bus, self.db)
        self.audit.start()

        self._build_menu()
        self._build_main()
        self._build_statusbar()

        self.bind_all("<Any-KeyPress>", lambda _e: self._touch_activity())
        self.bind_all("<Any-Button>", lambda _e: self._touch_activity())
        self.bind("<Unmap>", self._on_unmap)
        self.protocol("WM_DELETE_WINDOW", self.on_exit)

        self._bootstrap_auth_flow()
        self.refresh_table()

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Создать", command=self.on_new)
        file_menu.add_command(label="Открыть", command=self.on_open)
        file_menu.add_separator()
        file_menu.add_command(label="Сменить пароль", command=self.on_change_password)
        file_menu.add_command(label="Выход", command=self.on_exit)

        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Добавить", command=self.on_add_entry)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Настройки", command=self.on_settings)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="О программе", command=self.on_about)

        menubar.add_cascade(label="Файл", menu=file_menu)
        menubar.add_cascade(label="Правка", menu=edit_menu)
        menubar.add_cascade(label="Вид", menu=view_menu)
        menubar.add_cascade(label="Справка", menu=help_menu)
        self.config(menu=menubar)

    def _build_main(self) -> None:
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=10, pady=10)
        self.table = SecureTable(container)
        self.table.pack(fill="both", expand=True)

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Статус: locked")
        self.session_var = tk.StringVar(value="Сессия: -")
        ttk.Label(bar, textvariable=self.status_var).pack(side="left", padx=10, pady=6)
        ttk.Label(bar, textvariable=self.session_var).pack(side="right", padx=10, pady=6)

    def _set_status(self, msg: str) -> None:
        self.status_var.set(f"Статус: {msg}")

    def _bootstrap_auth_flow(self) -> None:
        if not self.auth.is_initialized():
            wizard = SetupWizard(self, self.cfg_mgr)
            self.wait_window(wizard)
            if wizard.result is None:
                self.destroy()
                return
            db_path, password = wizard.result
            if db_path != self.cfg.db_path:
                self.cfg.db_path = db_path
                self.cfg_mgr.save(self.cfg)
                self.db = Database(self.cfg.db_path, pool_size=4)
                self.db.initialize()
                self.audit = AuditLogger(self.bus, self.db)
                self.audit.start()
                self.auth = AuthenticationManager(self.db, self.key_manager, self.key_cache, self.bus)
            self.auth.initialize_master_password(password)
            ok, msg = self.auth.authenticate(password)
            if not ok:
                messagebox.showerror("Ошибка", msg or "Не удалось открыть хранилище")
                self.destroy()
                return
            self._load_test_data_if_empty()
            self.state.mark_login()
            self._set_status("unlocked")
            return

        login = LoginDialog(self, self.auth)
        self.wait_window(login)
        if not login.success:
            self.destroy()
            return
        self.state.mark_login()
        self._set_status("unlocked")

    def _load_test_data_if_empty(self) -> None:
        if self.db.list_vault_entries():
            return
        sample = [
            ("GitHub", "alice", "p@ssw0rd", "https://github.com", "note", "dev,work"),
            ("Email", "alice@example.com", "secret123!!AA", "https://mail.example.com", "", "personal"),
            ("Server", "root", "toor!!AA1122", "ssh://10.0.0.1", "rotate keys", "infra"),
        ]
        for title, user, pw, url, notes, tags in sample:
            ct = self.crypto.encrypt(pw.encode("utf-8"), self.auth)
            self.db.insert_vault_entry(title=title, username=user, encrypted_password=ct, url=url, notes=notes, tags=tags)

    def _touch_activity(self) -> None:
        self.state.touch_activity()
        self.auth.touch_activity()
        self.session_var.set("Сессия: active")

    def _on_unmap(self, _event) -> None:
        if self.key_cache.policy.clear_on_minimize:
            self.auth.logout()
            self.state.mark_logout()
            self._set_status("locked")
            messagebox.showinfo("Безопасность", "Хранилище заблокировано после сворачивания окна.")
            self.destroy()

    def refresh_table(self) -> None:
        rows = self.db.list_vault_entries()
        self.table.set_rows(rows)

    def on_new(self) -> None:
        messagebox.showinfo("Создать", "Хранилище уже создано. Используйте отдельную БД для нового сейфа.")

    def on_open(self) -> None:
        messagebox.showinfo("Открыть", "Для Sprint 2 открытие выполняется при запуске приложения.")

    def on_change_password(self) -> None:
        ChangePasswordDialog(self, self.auth)

    def on_add_entry(self) -> None:
        if not self.auth.get_encryption_key():
            messagebox.showerror("Ошибка", "Хранилище заблокировано")
            return

        win = tk.Toplevel(self)
        win.title("Добавить запись")
        win.geometry("520x360")
        win.transient(self)
        win.grab_set()

        frm = ttk.Frame(win)
        frm.pack(fill="both", expand=True, padx=12, pady=12)

        title_var = tk.StringVar()
        user_var = tk.StringVar()
        url_var = tk.StringVar()
        tags_var = tk.StringVar()
        notes_var = tk.StringVar()

        ttk.Label(frm, text="Title:").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm, textvariable=title_var).grid(row=0, column=1, sticky="ew")

        ttk.Label(frm, text="Username:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frm, textvariable=user_var).grid(row=1, column=1, sticky="ew", pady=(8, 0))

        ttk.Label(frm, text="Password:").grid(row=2, column=0, sticky="w", pady=(8, 0))
        pw = PasswordEntry(frm)
        pw.grid(row=2, column=1, sticky="ew", pady=(8, 0))

        ttk.Label(frm, text="URL:").grid(row=3, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frm, textvariable=url_var).grid(row=3, column=1, sticky="ew", pady=(8, 0))

        ttk.Label(frm, text="Tags:").grid(row=4, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frm, textvariable=tags_var).grid(row=4, column=1, sticky="ew", pady=(8, 0))

        ttk.Label(frm, text="Notes:").grid(row=5, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frm, textvariable=notes_var).grid(row=5, column=1, sticky="ew", pady=(8, 0))

        frm.columnconfigure(1, weight=1)

        def submit():
            for field, var, allow_empty, max_len in [
                ("Title", title_var.get(), False, 120),
                ("Username", user_var.get(), False, 120),
                ("URL", url_var.get(), True, 300),
                ("Tags", tags_var.get(), True, 200),
                ("Notes", notes_var.get(), True, 500),
            ]:
                res = validate_safe_text(var, field, max_len=max_len, allow_empty=allow_empty)
                if not res.ok:
                    messagebox.showerror("Ошибка", res.message)
                    return
            password = pw.get()
            if not password:
                messagebox.showerror("Ошибка", "Password: required")
                return

            ct = self.crypto.encrypt(password.encode("utf-8"), self.auth)
            entry_id = self.db.insert_vault_entry(
                title=title_var.get().strip(),
                username=user_var.get().strip(),
                encrypted_password=ct,
                url=url_var.get().strip(),
                notes=notes_var.get().strip(),
                tags=tags_var.get().strip(),
            )
            self.bus.publish(EntryAdded(entry_id=entry_id))
            self.refresh_table()
            win.destroy()

        btns = ttk.Frame(frm)
        btns.grid(row=6, column=0, columnspan=2, sticky="e", pady=(16, 0))
        ttk.Button(btns, text="Отмена", command=win.destroy).pack(side="right")
        ttk.Button(btns, text="Сохранить", command=submit).pack(side="right", padx=(0, 8))

    def on_settings(self) -> None:
        SettingsDialog(self)

    def on_about(self) -> None:
        messagebox.showinfo("О программе", "CryptoSafe Manager — Sprint 2\nArgon2id + PBKDF2 + login + password rotation.")

    def on_exit(self) -> None:
        self.auth.logout()
        self.state.mark_logout()
        self.destroy()


def main() -> None:
    app = MainWindow()
    app.mainloop()

if __name__ == "__main__":
    main()