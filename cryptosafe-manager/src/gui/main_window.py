from __future__ import annotations

import os
import secrets
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from ..core.audit import AuditLogger
from ..core.config import ConfigManager
from ..core.crypto.placeholder import AES256Placeholder
from ..core.events import EntryAdded, EventBus, UserLoggedIn, UserLoggedOut
from ..core.key_manager import KeyManager, KdfParams
from ..core.state_manager import StateManager
from ..core.utils import validate_safe_text
from ..database.db import Database
from .widgets import PasswordEntry, SecureTable, SettingsDialog

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

        ttk.Label(frm, text="Мастер-пароль", font=("TkDefaultFont", 10, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(frm, text="Пароль:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.pw1 = PasswordEntry(frm)
        self.pw1.grid(row=2, column=0, sticky="ew")

        ttk.Label(frm, text="Повтор:").grid(row=3, column=0, sticky="w", pady=(8, 0))
        self.pw2 = PasswordEntry(frm)
        self.pw2.grid(row=4, column=0, sticky="ew")

        ttk.Separator(frm).grid(row=5, column=0, sticky="ew", pady=14)

        ttk.Label(frm, text="Расположение базы данных", font=("TkDefaultFont", 10, "bold")).grid(row=6, column=0, sticky="w")
        self.db_path_var = tk.StringVar(value=self.cfg_mgr.load().db_path)
        row_db = ttk.Frame(frm)
        row_db.grid(row=7, column=0, sticky="ew", pady=(8, 0))
        ttk.Entry(row_db, textvariable=self.db_path_var).pack(side="left", fill="x", expand=True)
        ttk.Button(row_db, text="Выбрать...", command=self._choose_db).pack(side="left", padx=(8, 0))

        ttk.Separator(frm).grid(row=8, column=0, sticky="ew", pady=14)

        ttk.Label(frm, text="Параметры KDF (заглушка)", font=("TkDefaultFont", 10, "bold")).grid(row=9, column=0, sticky="w")
        grid = ttk.Frame(frm)
        grid.grid(row=10, column=0, sticky="ew", pady=(8, 0))
        ttk.Label(grid, text="Iterations:").grid(row=0, column=0, sticky="w")
        self.iters_var = tk.StringVar(value="120000")
        ttk.Entry(grid, textvariable=self.iters_var, width=12).grid(row=0, column=1, sticky="w", padx=(8, 0))

        ttk.Label(grid, text="Hash:").grid(row=0, column=2, sticky="w", padx=(18, 0))
        self.hash_var = tk.StringVar(value="sha256")
        ttk.Entry(grid, textvariable=self.hash_var, width=10).grid(row=0, column=3, sticky="w", padx=(8, 0))

        ttk.Label(grid, text="DKLen:").grid(row=0, column=4, sticky="w", padx=(18, 0))
        self.dklen_var = tk.StringVar(value="32")
        ttk.Entry(grid, textvariable=self.dklen_var, width=6).grid(row=0, column=5, sticky="w", padx=(8, 0))

        btns = ttk.Frame(frm)
        btns.grid(row=11, column=0, sticky="e", pady=(18, 0))
        ttk.Button(btns, text="Отмена", command=self._cancel).pack(side="right")
        ttk.Button(btns, text="Готово", command=self._finish).pack(side="right", padx=(0, 8))

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
        if not pw1 or len(pw1) < 8:
            messagebox.showerror("Ошибка", "Пароль должен быть не короче 8 символов.")
            return
        if pw1 != pw2:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            return

        db_path = self.db_path_var.get().strip()
        if not db_path:
            messagebox.showerror("Ошибка", "Укажите путь к базе данных.")
            return

        try:
            os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        except Exception:
            messagebox.showerror("Ошибка", "Невозможно создать каталог для базы данных.")
            return

        try:
            iters = int(self.iters_var.get().strip())
            dklen = int(self.dklen_var.get().strip())
            hname = self.hash_var.get().strip()
            if iters < 10_000 or iters > 5_000_000:
                raise ValueError
            if dklen not in (16, 24, 32, 48, 64):
                raise ValueError
            if hname not in ("sha256", "sha512"):
                raise ValueError
        except Exception:
            messagebox.showerror("Ошибка", "Некорректные параметры KDF.")
            return

        self.result = (db_path, pw1, KdfParams(iterations=iters, dklen=dklen, hash_name=hname))
        self.destroy()


class MainWindow(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("CryptoSafe Manager (Sprint 1)")
        self.geometry("980x560")

        # Core
        self.bus = EventBus()
        self.state = StateManager()
        self.cfg_mgr = ConfigManager(env=os.getenv("CRYPTOSAFE_ENV", "development"))
        self.cfg = self.cfg_mgr.load()

        self.crypto = AES256Placeholder()
        self.km = KeyManager()
        self.master_key: bytes | None = None
        self.salt: bytes | None = None

        self.db = Database(self.cfg.db_path, pool_size=4)
        self.db.initialize()

        self.audit = AuditLogger(self.bus, self.db)
        self.audit.start()

        # GUI
        self._build_menu()
        self._build_main()
        self._build_statusbar()

        self._first_run_if_needed()
        self._load_test_data_if_empty()
        self.refresh_table()

        # Mark as logged-in for Sprint 1
        self.state.set_locked(False)
        self.bus.publish(UserLoggedIn(username="local"))
        self._set_status("Готово. (Спринт 1)")

        self.protocol("WM_DELETE_WINDOW", self.on_exit)


    def _build_menu(self) -> None:
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Создать", command=self.on_new)
        file_menu.add_command(label="Открыть", command=self.on_open)
        file_menu.add_separator()
        file_menu.add_command(label="Резервная копия", command=self.on_backup_stub)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.on_exit)

        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Добавить", command=self.on_add_entry)
        edit_menu.add_command(label="Изменить", command=self.on_edit_entry_stub)
        edit_menu.add_command(label="Удалить", command=self.on_delete_entry_stub)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Логи", command=self.on_logs_stub)
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
        self.status_var = tk.StringVar(value="Статус: (не вошли)")
        self.clipboard_var = tk.StringVar(value="Буфер: таймер (заглушка)")
        bar = ttk.Frame(self)
        bar.pack(fill="x", side="bottom")

        ttk.Label(bar, textvariable=self.status_var).pack(side="left", padx=10, pady=6)
        ttk.Label(bar, textvariable=self.clipboard_var).pack(side="right", padx=10, pady=6)

    def _set_status(self, text: str) -> None:
        # Do not include secrets.
        self.status_var.set(f"Статус: {text}")


    def _first_run_if_needed(self) -> None:
        has = self.db.get_setting("master_salt")
        if has is not None:
            self.salt = has[0]
            self.master_key = AES256Placeholder.random_key(32)
            return

        wizard = SetupWizard(self, self.cfg_mgr)
        self.wait_window(wizard)
        if wizard.result is None:
            self.destroy()
            return

        db_path, master_password, kdf_params = wizard.result

        if db_path != self.cfg.db_path:
            self.cfg.db_path = db_path
            self.cfg_mgr.save(self.cfg)
            self.db = Database(self.cfg.db_path, pool_size=4)
            self.db.initialize()
            self.audit = AuditLogger(self.bus, self.db)
            self.audit.start()

        self.cfg.crypto.kdf_iterations = kdf_params.iterations
        self.cfg.crypto.kdf_hash = kdf_params.hash_name
        self.cfg.crypto.kdf_dklen = kdf_params.dklen
        self.cfg_mgr.save(self.cfg)

        self.km = KeyManager(params=kdf_params)
        self.salt = secrets.token_bytes(16)
        self.master_key = self.km.derive_key(master_password, self.salt)

        self.db.upsert_setting("master_salt", self.salt, encrypted=False)
        self._set_status("Первоначальная настройка завершена")

    def _load_test_data_if_empty(self) -> None:
        rows = self.db.list_vault_entries()
        if rows:
            return

        if self.master_key is None:
            self.master_key = AES256Placeholder.random_key(32)
        sample = [
            ("GitHub", "alice", "p@ssw0rd", "https://github.com", "note", "dev,work"),
            ("Email", "alice@example.com", "secret123", "https://mail.example.com", "", "personal"),
            ("Server", "root", "toor", "ssh://10.0.0.1", "rotate keys", "infra"),
        ]
        for title, user, pw, url, notes, tags in sample:
            ct = self.crypto.encrypt(pw.encode("utf-8"), self.master_key)
            self.db.insert_vault_entry(title=title, username=user, encrypted_password=ct, url=url, notes=notes, tags=tags)

    def refresh_table(self) -> None:
        rows = self.db.list_vault_entries()
        self.table.set_rows(rows)


    def on_new(self) -> None:
        messagebox.showinfo("Создать", "Заглушка: создание нового хранилища будет расширено в следующих спринтах.")

    def on_open(self) -> None:
        messagebox.showinfo("Открыть", "Заглушка: открытие/разблокировка хранилища будет расширено в следующих спринтах.")

    def on_backup_stub(self) -> None:
        messagebox.showinfo("Резервная копия", "Заглушка: backup/restore будут в Спринте 8.")

    def on_exit(self) -> None:
        try:
            self.bus.publish(UserLoggedOut(username="local"))
        except Exception:
            pass
        self.destroy()

    def on_add_entry(self) -> None:
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

            if self.master_key is None:
                self.master_key = AES256Placeholder.random_key(32)

            ct = self.crypto.encrypt(password.encode("utf-8"), self.master_key)
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

    def on_edit_entry_stub(self) -> None:
        messagebox.showinfo("Изменить", "Заглушка: редактирование будет расширено в следующих спринтах.")

    def on_delete_entry_stub(self) -> None:
        messagebox.showinfo("Удалить", "Заглушка: удаление будет расширено в следующих спринтах.")

    def on_logs_stub(self) -> None:
        messagebox.showinfo("Логи", "Заглушка: просмотр аудита будет в Спринте 5.")

    def on_settings(self) -> None:
        SettingsDialog(self)

    def on_about(self) -> None:
        messagebox.showinfo(
            "О программе",
            "CryptoSafe Manager — Sprint 1\n"
            "Фундамент: модульная архитектура, DB schema, crypto placeholders, EventBus, базовый GUI.",
        )


def main() -> None:
    app = MainWindow()
    app.mainloop()


if __name__ == "__main__":
    main()
