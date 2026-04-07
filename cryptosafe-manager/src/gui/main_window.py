from __future__ import annotations

import os
import re
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from urllib.parse import urlparse

from src.core.audit import AuditLogger
from src.core.config import ConfigManager
from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import Argon2Config, KeyManager, PBKDF2Config, PasswordPolicy
from src.core.crypto.key_storage import CachePolicy, SecureKeyCache
from src.core.events import EventBus
from src.core.state_manager import StateManager
from src.core.vault import AESGCMEntryEncryptionService, EntryManager, PasswordGenerator, PasswordGeneratorOptions
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
        ttk.Label(frm, text="Минимум 12 символов, нужны заглавные, строчные, цифры и спецсимволы.").grid(
            row=1, column=0, sticky="w", pady=(4, 8)
        )

        ttk.Label(frm, text="Пароль:").grid(row=2, column=0, sticky="w")
        self.pw1 = PasswordEntry(frm)
        self.pw1.grid(row=3, column=0, sticky="ew")

        ttk.Label(frm, text="Повтор:").grid(row=4, column=0, sticky="w", pady=(8, 0))
        self.pw2 = PasswordEntry(frm)
        self.pw2.grid(row=5, column=0, sticky="ew")

        ttk.Separator(frm).grid(row=6, column=0, sticky="ew", pady=14)

        ttk.Label(frm, text="Файл БД", font=("TkDefaultFont", 10, "bold")).grid(row=7, column=0, sticky="w")
        self.db_path_var = tk.StringVar(value=self.cfg_mgr.load().db_path)
        row_db = ttk.Frame(frm)
        row_db.grid(row=8, column=0, sticky="ew", pady=(8, 0))
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


class EntryDialog(tk.Toplevel):
    def __init__(self, master, title: str, initial: dict | None = None, generator: PasswordGenerator | None = None):
        super().__init__(master)
        self.title(title)
        self.geometry("620x420")
        self.transient(master)
        self.grab_set()

        self.generator = generator or PasswordGenerator()
        self.result = None
        initial = initial or {}

        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True, padx=12, pady=12)

        self.title_var = tk.StringVar(value=initial.get("title", ""))
        self.user_var = tk.StringVar(value=initial.get("username", ""))
        self.url_var = tk.StringVar(value=initial.get("url", ""))
        self.tags_var = tk.StringVar(value=initial.get("tags", ""))
        self.category_var = tk.StringVar(value=initial.get("category", ""))
        self.notes_var = tk.StringVar(value=initial.get("notes", ""))

        ttk.Label(frm, text="Заголовок *").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.title_var).grid(row=0, column=1, sticky="ew")

        ttk.Label(frm, text="Имя пользователя").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frm, textvariable=self.user_var).grid(row=1, column=1, sticky="ew", pady=(8, 0))

        ttk.Label(frm, text="Пароль *").grid(row=2, column=0, sticky="w", pady=(8, 0))
        pw_row = ttk.Frame(frm)
        pw_row.grid(row=2, column=1, sticky="ew", pady=(8, 0))
        self.password = PasswordEntry(pw_row)
        self.password.pack(side="left", fill="x", expand=True)
        self.password.set(initial.get("password", ""))
        ttk.Button(pw_row, text="Сгенерировать", command=self._generate_password).pack(side="left", padx=(8, 0))

        self.strength_var = tk.StringVar(value="Надёжность: -")
        ttk.Label(frm, textvariable=self.strength_var).grid(row=3, column=1, sticky="w")
        self.password.entry.bind("<KeyRelease>", lambda _e: self._update_strength())

        ttk.Label(frm, text="URL").grid(row=4, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frm, textvariable=self.url_var).grid(row=4, column=1, sticky="ew", pady=(8, 0))

        ttk.Label(frm, text="Категория").grid(row=5, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frm, textvariable=self.category_var).grid(row=5, column=1, sticky="ew", pady=(8, 0))

        ttk.Label(frm, text="Теги").grid(row=6, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frm, textvariable=self.tags_var).grid(row=6, column=1, sticky="ew", pady=(8, 0))

        ttk.Label(frm, text="Заметки").grid(row=7, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frm, textvariable=self.notes_var).grid(row=7, column=1, sticky="ew", pady=(8, 0))

        frm.columnconfigure(1, weight=1)

        btns = ttk.Frame(frm)
        btns.grid(row=8, column=0, columnspan=2, sticky="e", pady=(16, 0))
        ttk.Button(btns, text="Отмена", command=self.destroy).pack(side="right")
        ttk.Button(btns, text="Сохранить", command=self._submit).pack(side="right", padx=(0, 8))

        self._update_strength()

    def _generate_password(self) -> None:
        length = simpledialog.askinteger("Генератор паролей", "Длина пароля (8-64):", minvalue=8, maxvalue=64, initialvalue=16, parent=self)
        if not length:
            return
        password = self.generator.generate(PasswordGeneratorOptions(length=length))
        self.password.set(password)
        self._update_strength()

    def _update_strength(self) -> None:
        score = self.generator.score(self.password.get())
        labels = {0: "Очень слабый", 1: "Слабый", 2: "Ниже среднего", 3: "Хороший", 4: "Сильный"}
        self.strength_var.set(f"Надёжность: {labels.get(score, '-')}")

    @staticmethod
    def _is_valid_url(url: str) -> bool:
        if not url:
            return True
        try:
            p = urlparse(url)
            return p.scheme in ("http", "https", "ssh", "ftp") and bool(p.netloc or p.path)
        except Exception:
            return False

    def _submit(self) -> None:
        data = {
            "title": self.title_var.get().strip(),
            "username": self.user_var.get().strip(),
            "password": self.password.get(),
            "url": self.url_var.get().strip(),
            "category": self.category_var.get().strip(),
            "tags": self.tags_var.get().strip(),
            "notes": self.notes_var.get().strip(),
        }

        if not data["title"]:
            messagebox.showerror("Ошибка", "Поле 'Заголовок' обязательно")
            return
        if not data["password"]:
            messagebox.showerror("Ошибка", "Поле 'Пароль' обязательно")
            return
        if not self._is_valid_url(data["url"]):
            messagebox.showerror("Ошибка", "Некорректный URL")
            return

        self.result = data
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
        self.msg_var.set("Пароль успешно изменён" if ok else (msg or "Ошибка смены пароля"))


class MainWindow(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("CryptoSafe Manager (Sprint 3)")
        self.geometry("1100x650")

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
        idle_timeout = self.cfg.auto_lock_seconds if self.cfg.auto_lock_seconds and self.cfg.auto_lock_seconds > 0 else 3600
        self.key_cache = SecureKeyCache(CachePolicy(idle_timeout_seconds=idle_timeout))
        self.auth = AuthenticationManager(self.db, self.key_manager, self.key_cache, self.bus)

        self.entry_encryption = AESGCMEntryEncryptionService(self.auth)
        self.entry_manager = EntryManager(self.db, self.entry_encryption, self.bus)
        self.password_generator = PasswordGenerator()

        self.audit = AuditLogger(self.bus, self.db)
        self.audit.start()

        self._current_rows: list[dict] = []
        self._show_passwords = False

        self._build_menu()
        self._build_toolbar()
        self._build_main()
        self._build_statusbar()

        self.bind_all("<Any-KeyPress>", lambda _e: self._touch_activity())
        self.bind_all("<Any-Button>", lambda _e: self._touch_activity())
        self.bind("<Control-Shift-P>", lambda _e: self.toggle_passwords())
        self.protocol("WM_DELETE_WINDOW", self.on_exit)

        self._bootstrap_auth_flow()
        self.refresh_table()

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Создать запись", command=self.on_add_entry)
        file_menu.add_command(label="Сменить пароль", command=self.on_change_password)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.on_exit)

        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Добавить", command=self.on_add_entry)
        edit_menu.add_command(label="Изменить", command=self.on_edit_entry)
        edit_menu.add_command(label="Удалить", command=self.on_delete_entry)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Показать/скрыть пароли", command=self.toggle_passwords)
        view_menu.add_command(label="Настройки", command=self.on_settings)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="О программе", command=self.on_about)

        menubar.add_cascade(label="Файл", menu=file_menu)
        menubar.add_cascade(label="Правка", menu=edit_menu)
        menubar.add_cascade(label="Вид", menu=view_menu)
        menubar.add_cascade(label="Справка", menu=help_menu)
        self.config(menu=menubar)

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=10, pady=(10, 0))

        ttk.Button(bar, text="Добавить", command=self.on_add_entry).pack(side="left")
        ttk.Button(bar, text="Изменить", command=self.on_edit_entry).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="Удалить", command=self.on_delete_entry).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="Показать/скрыть пароли (Ctrl+Shift+P)", command=self.toggle_passwords).pack(side="left", padx=(12, 0))

        ttk.Label(bar, text="Поиск:").pack(side="left", padx=(20, 6))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(bar, textvariable=self.search_var)
        search_entry.pack(side="left", fill="x", expand=True)
        search_entry.bind("<KeyRelease>", lambda _e: self.refresh_table())

    def _build_main(self) -> None:
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=10, pady=10)

        self.table = SecureTable(container)
        self.table.pack(fill="both", expand=True)
        self.table.bind_context_menu(self._show_context_menu)
        self.table.bind_double_click(lambda _e: self.on_edit_entry())

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
                self.entry_encryption = AESGCMEntryEncryptionService(self.auth)
                self.entry_manager = EntryManager(self.db, self.entry_encryption, self.bus)

            try:
                self.auth.initialize_master_password(password)
            except ValueError as e:
                messagebox.showerror("Ошибка", str(e))
                self.destroy()
                return
            except Exception:
                messagebox.showerror("Ошибка", "Не удалось инициализировать хранилище.")
                self.destroy()
                return

            ok, msg = self.auth.authenticate(password)
            if not ok:
                messagebox.showerror("Ошибка", msg or "Не удалось открыть хранилище")
                self.destroy()
                return

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

    def _touch_activity(self) -> None:
        self.state.touch_activity()
        self.auth.touch_activity()
        self.session_var.set("Сессия: active")

    def refresh_table(self) -> None:
        query = self.search_var.get().strip() if hasattr(self, "search_var") else ""
        rows = self.entry_manager.search_entries(query) if query else self.entry_manager.get_all_entries()
        self._current_rows = rows
        self.table.set_rows(rows)
        self.table.set_show_passwords(self._show_passwords)

    def toggle_passwords(self) -> None:
        self._show_passwords = not self._show_passwords
        self.table.set_show_passwords(self._show_passwords)

    def _selected_single_id(self) -> int | None:
        ids = self.table.selected_ids()
        if not ids:
            messagebox.showwarning("Внимание", "Выберите запись")
            return None
        if len(ids) > 1:
            messagebox.showwarning("Внимание", "Выберите одну запись")
            return None
        return ids[0]

    def _show_context_menu(self, event) -> None:
        item = self.table.tree.identify_row(event.y)
        if item:
            self.table.tree.selection_set(item)

        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Изменить", command=self.on_edit_entry)
        menu.add_command(label="Удалить", command=self.on_delete_entry)
        menu.add_separator()
        menu.add_command(label="Показать/скрыть пароли", command=self.toggle_passwords)
        menu.tk_popup(event.x_root, event.y_root)

    def on_add_entry(self) -> None:
        if not self.auth.get_encryption_key():
            messagebox.showerror("Ошибка", "Хранилище заблокировано")
            return

        dialog = EntryDialog(self, "Новая запись", generator=self.password_generator)
        self.wait_window(dialog)
        if dialog.result is None:
            return

        try:
            self.entry_manager.create_entry(dialog.result)
            self.refresh_table()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def on_edit_entry(self) -> None:
        entry_id = self._selected_single_id()
        if entry_id is None:
            return

        try:
            current = self.entry_manager.get_entry(entry_id)
        except Exception:
            messagebox.showerror("Ошибка", "Не удалось открыть запись")
            return

        dialog = EntryDialog(self, "Редактировать запись", initial=current, generator=self.password_generator)
        self.wait_window(dialog)
        if dialog.result is None:
            return

        try:
            self.entry_manager.update_entry(entry_id, dialog.result)
            self.refresh_table()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def on_delete_entry(self) -> None:
        ids = self.table.selected_ids()
        if not ids:
            messagebox.showwarning("Внимание", "Выберите запись")
            return
        if not messagebox.askyesno("Подтверждение", f"Удалить выбранные записи: {len(ids)}?"):
            return

        for entry_id in ids:
            try:
                self.entry_manager.delete_entry(entry_id, soft_delete=True)
            except Exception:
                messagebox.showerror("Ошибка", "Не удалось удалить запись")
                return
        self.refresh_table()

    def on_change_password(self) -> None:
        ChangePasswordDialog(self, self.auth)

    def on_settings(self) -> None:
        SettingsDialog(self)

    def on_about(self) -> None:
        messagebox.showinfo(
            "О программе",
            "CryptoSafe Manager — Sprint 3\nAES-256-GCM per entry, CRUD, поиск и генератор паролей.",
        )

    def on_exit(self) -> None:
        self.auth.logout()
        self.state.mark_logout()
        self.destroy()


def main() -> None:
    app = MainWindow()
    app.mainloop()


if __name__ == "__main__":
    main()