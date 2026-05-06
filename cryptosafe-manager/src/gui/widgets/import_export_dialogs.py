from __future__ import annotations

import hashlib
import json
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any

import qrcode

from src.core.import_export.exporter import ExportOptions
from src.core.import_export.importer import ImportOptions
from src.core.import_export.sharing_service import ShareOptions


EXPORT_FORMAT_HELP = {
    "encrypted_json": (
        "Encrypted JSON — основной безопасный формат CryptoSafe Manager.\n"
        "Подходит для резервных копий и переноса между экземплярами приложения.\n"
        "Сохраняет структуру записей и шифруется при экспорте."
    ),
    "csv": (
        "CSV — простой табличный формат.\n"
        "Подходит для миграции в другие менеджеры паролей и просмотра в таблицах.\n"
        "Менее безопасен, если экспортируется без дополнительной защиты."
    ),
    "bitwarden_json": (
        "Bitwarden JSON — формат совместимости с Bitwarden.\n"
        "Позволяет переносить записи в Bitwarden через его импорт JSON."
    ),
    "lastpass_csv": (
        "LastPass CSV — формат совместимости с LastPass.\n"
        "Используйте его, если хотите импортировать записи в LastPass.\n"
        "LastPass обычно ожидает CSV-файл со стандартными колонками."
    ),
}

IMPORT_FORMAT_HELP = {
    "": (
        "Автоопределение — приложение само попробует определить формат файла.\n"
        "Подходит в большинстве случаев."
    ),
    "encrypted_json": (
        "Encrypted JSON — нативный экспорт CryptoSafe Manager.\n"
        "Если файл был защищён паролем, укажите пароль импорта."
    ),
    "csv": (
        "CSV — обычный табличный формат.\n"
        "Подходит для простых файлов с колонками title, username, password, url и notes."
    ),
    "bitwarden_json": (
        "Bitwarden JSON — импорт из экспорта Bitwarden."
    ),
    "lastpass_csv": (
        "LastPass CSV — импорт из CSV-экспорта LastPass."
    ),
}

EXPORT_METHOD_HELP = {
    "password": (
        "Password — файл будет защищён отдельным паролем экспорта.\n"
        "Это удобно для резервных копий и переноса вручную."
    ),
    "public_key": (
        "Public key — файл будет зашифрован на публичный ключ получателя.\n"
        "Такой экспорт сможет открыть только владелец соответствующего приватного ключа."
    ),
}

IMPORT_MODE_HELP = {
    "merge": (
        "Merge — добавить новые записи в текущее хранилище.\n"
        "Существующие записи не удаляются."
    ),
    "replace": (
        "Replace — очистить текущее хранилище и загрузить импорт заново.\n"
        "Используйте осторожно."
    ),
}


class QRViewerDialog(tk.Toplevel):
    def __init__(self, master, payload_text: str, title: str = "QR Viewer"):
        super().__init__(master)
        self.title(title)
        self.geometry("720x760")
        self.payload_text = payload_text
        self._build()

    def _build(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Label(top, text="QR payload preview", font=("TkDefaultFont", 10, "bold")).pack(anchor="w")
        preview = tk.Text(top, height=6, wrap="word")
        preview.pack(fill="x", expand=False, pady=(8, 0))
        preview.insert("1.0", self.payload_text[:2000])
        preview.configure(state="disabled")

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=10, pady=10)

        canvas = tk.Canvas(body, bg="white")
        canvas.pack(fill="both", expand=True)

        self.update_idletasks()
        self._draw_qr(canvas, self.payload_text)

    @staticmethod
    def _draw_qr(canvas: tk.Canvas, text: str) -> None:
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(text)
        qr.make(fit=True)
        matrix = qr.get_matrix()

        canvas_width = max(600, canvas.winfo_width())
        canvas_height = max(600, canvas.winfo_height())

        rows = len(matrix)
        cols = len(matrix[0]) if rows else 0
        if not rows or not cols:
            return

        cell = min((canvas_width - 40) // cols, (canvas_height - 40) // rows)
        cell = max(4, cell)
        offset_x = 20
        offset_y = 20

        canvas.delete("all")
        canvas.create_rectangle(0, 0, canvas_width, canvas_height, fill="white", outline="white")

        for y, row in enumerate(matrix):
            for x, bit in enumerate(row):
                if bit:
                    x1 = offset_x + x * cell
                    y1 = offset_y + y * cell
                    x2 = x1 + cell
                    y2 = y1 + cell
                    canvas.create_rectangle(x1, y1, x2, y2, fill="black", outline="black")


class ExportDialog(tk.Toplevel):
    def __init__(self, master, db, auth, entry_manager, exporter):
        super().__init__(master)
        self.title("Vault Export")
        self.geometry("1060x760")
        self.minsize(980, 700)
        self.db = db
        self.auth = auth
        self.entry_manager = entry_manager
        self.exporter = exporter
        self.entries = self.entry_manager.get_all_entries()
        self._build()
        self._update_help()

    def _build(self) -> None:
        root = ttk.Frame(self)
        root.pack(fill="both", expand=True, padx=12, pady=12)

        top_info = ttk.LabelFrame(root, text="Что делает экспорт")
        top_info.pack(fill="x", pady=(0, 10))
        ttk.Label(
            top_info,
            text=(
                "Экспорт создаёт отдельный файл с выбранными записями.\n"
                "Для безопасного резервного копирования используйте encrypted_json.\n"
                "Для переноса в другие менеджеры паролей используйте CSV, Bitwarden JSON или LastPass CSV."
            ),
            justify="left",
        ).pack(anchor="w", padx=10, pady=8)

        content = ttk.Frame(root)
        content.pack(fill="both", expand=True)

        left = ttk.Frame(content)
        left.pack(side="left", fill="both", expand=True)

        right = ttk.Frame(content)
        right.pack(side="left", fill="both", expand=True, padx=(12, 0))

        ttk.Label(left, text="Настройки экспорта", font=("TkDefaultFont", 10, "bold")).pack(anchor="w")

        self.format_var = tk.StringVar(value="encrypted_json")
        self.compress_var = tk.BooleanVar(value=False)
        self.include_notes_var = tk.BooleanVar(value=True)
        self.include_tags_var = tk.BooleanVar(value=True)
        self.key_bits_var = tk.StringVar(value="256")
        self.method_var = tk.StringVar(value="password")

        ttk.Label(left, text="Формат").pack(anchor="w", pady=(8, 0))
        format_box = ttk.Combobox(
            left,
            textvariable=self.format_var,
            values=["encrypted_json", "csv", "bitwarden_json", "lastpass_csv"],
            state="readonly",
        )
        format_box.pack(fill="x")
        format_box.bind("<<ComboboxSelected>>", lambda _e: self._update_help())

        ttk.Checkbutton(left, text="Включать заметки", variable=self.include_notes_var).pack(anchor="w", pady=(8, 0))
        ttk.Checkbutton(left, text="Включать теги", variable=self.include_tags_var).pack(anchor="w")
        ttk.Checkbutton(left, text="Сжимать через GZIP", variable=self.compress_var).pack(anchor="w")

        ttk.Label(left, text="Способ защиты файла").pack(anchor="w", pady=(10, 0))
        method_box = ttk.Combobox(
            left,
            textvariable=self.method_var,
            values=["password", "public_key"],
            state="readonly",
        )
        method_box.pack(fill="x")
        method_box.bind("<<ComboboxSelected>>", lambda _e: self._update_help())

        ttk.Label(left, text="Размер AES-ключа").pack(anchor="w", pady=(8, 0))
        ttk.Combobox(
            left,
            textvariable=self.key_bits_var,
            values=["128", "256"],
            state="readonly",
        ).pack(fill="x")

        ttk.Label(left, text="Публичный ключ получателя (PEM), если выбран public_key").pack(anchor="w", pady=(10, 0))
        self.public_key_text = tk.Text(left, height=7, wrap="word")
        self.public_key_text.pack(fill="x")

        ttk.Label(left, text="Выберите записи для экспорта").pack(anchor="w", pady=(10, 0))
        self.entries_list = tk.Listbox(left, selectmode="extended", height=14)
        self.entries_list.pack(fill="both", expand=True)
        for row in self.entries:
            self.entries_list.insert("end", f'#{row["id"]} | {row.get("title", "")} | {row.get("username", "")}')

        ttk.Label(right, text="Подсказка", font=("TkDefaultFont", 10, "bold")).pack(anchor="w")
        self.help_text = tk.Text(right, height=16, wrap="word")
        self.help_text.pack(fill="x", expand=False)

        ttk.Label(right, text="Предпросмотр", font=("TkDefaultFont", 10, "bold")).pack(anchor="w", pady=(10, 0))
        self.preview = tk.Text(right, wrap="word")
        self.preview.pack(fill="both", expand=True)

        bottom = ttk.Frame(root)
        bottom.pack(fill="x", pady=(12, 0))

        ttk.Button(bottom, text="Выбрать все", command=self._select_all).pack(side="left")
        ttk.Button(bottom, text="Предпросмотр", command=self._preview).pack(side="left", padx=(8, 0))
        ttk.Button(bottom, text="Экспортировать", command=self._export).pack(side="right")
        ttk.Button(bottom, text="Закрыть", command=self.destroy).pack(side="right", padx=(0, 8))

    def _update_help(self) -> None:
        fmt = self.format_var.get()
        method = self.method_var.get()

        notes = [
            "Формат:",
            EXPORT_FORMAT_HELP.get(fmt, ""),
            "",
            "Способ защиты:",
            EXPORT_METHOD_HELP.get(method, ""),
            "",
            "Рекомендации:",
        ]

        if fmt == "encrypted_json":
            notes.append("- Лучший вариант для резервной копии CryptoSafe Manager.")
        if fmt == "csv":
            notes.append("- Используйте только если нужен универсальный табличный формат.")
        if fmt == "bitwarden_json":
            notes.append("- Выберите этот формат, если хотите перенести записи в Bitwarden.")
        if fmt == "lastpass_csv":
            notes.append("- Выберите этот формат, если хотите импортировать файл в LastPass.")
            notes.append("- Для совместимости с LastPass обычно нужен CSV-файл.")
        if method == "password":
            notes.append("- Получателю нужно знать пароль экспорта.")
        if method == "public_key":
            notes.append("- Получатель должен иметь соответствующий приватный ключ.")

        self.help_text.delete("1.0", "end")
        self.help_text.insert("1.0", "\n".join(notes))

    def _select_all(self) -> None:
        self.entries_list.selection_set(0, "end")

    def _selected_entry_ids(self) -> list[int]:
        indices = list(self.entries_list.curselection())
        if not indices:
            return [int(e["id"]) for e in self.entries]
        return [int(self.entries[i]["id"]) for i in indices]

    def _build_options(self) -> ExportOptions:
        return ExportOptions(
            export_format=self.format_var.get(),
            include_notes=self.include_notes_var.get(),
            include_tags=self.include_tags_var.get(),
            compress=self.compress_var.get(),
            key_bits=int(self.key_bits_var.get()),
            selected_entry_ids=self._selected_entry_ids(),
        )

    def _preview(self) -> None:
        options = self._build_options()
        selected = self._selected_entry_ids()
        self.preview.delete("1.0", "end")
        self.preview.insert(
            "1.0",
            json.dumps(
                {
                    "what_happens": "A new export file will be created from selected vault entries.",
                    "format": options.export_format,
                    "entry_count": len(selected),
                    "include_notes": options.include_notes,
                    "include_tags": options.include_tags,
                    "compress": options.compress,
                    "key_bits": options.key_bits,
                    "method": self.method_var.get(),
                    "selected_ids": selected,
                },
                ensure_ascii=False,
                indent=2,
            ),
        )

    def _export(self) -> None:
        confirm = simpledialog.askstring("Подтверждение", "Введите мастер-пароль для подтверждения экспорта:", show="*", parent=self)
        if not confirm:
            return

        ok, msg = self.auth.authenticate(confirm)
        if not ok:
            messagebox.showerror("Ошибка", msg or "Проверка мастер-пароля не пройдена")
            return

        options = self._build_options()
        method = self.method_var.get()

        password = None
        public_key_pem = None

        if method == "password":
            password = simpledialog.askstring("Пароль экспорта", "Задайте пароль для файла экспорта:", show="*", parent=self)
            if not password:
                messagebox.showerror("Ошибка", "Нужен пароль экспорта")
                return
        else:
            public_key_raw = self.public_key_text.get("1.0", "end").strip()
            if not public_key_raw:
                messagebox.showerror("Ошибка", "Нужен публичный ключ получателя")
                return
            public_key_pem = public_key_raw.encode("utf-8")

        package = self.exporter.export_vault(password=password, public_key_pem=public_key_pem, options=options)

        default_ext = ".json"
        filetypes = [("JSON", "*.json"), ("All files", "*.*")]
        if options.export_format in {"csv", "lastpass_csv"}:
            default_ext = ".csv"
            filetypes = [("CSV", "*.csv"), ("All files", "*.*")]

        path = filedialog.asksaveasfilename(
            title="Сохранить экспорт",
            defaultextension=default_ext,
            filetypes=filetypes,
        )
        if not path:
            return

        raw = json.dumps(package, ensure_ascii=False, indent=2).encode("utf-8")
        with open(path, "wb") as f:
            f.write(raw)

        checksum = hashlib.sha256(raw).hexdigest()
        self.db.insert_import_export_history(
            operation_type="export",
            data_format=options.export_format,
            encryption_used=method,
            entry_count=package.get("entry_count", 0),
            file_size=len(raw),
            checksum=checksum,
            verification_status="ok",
            created_at=package.get("timestamp", ""),
        )

        messagebox.showinfo("Экспорт", f"Файл успешно сохранён:\n{path}")


class ImportDialog(tk.Toplevel):
    def __init__(self, master, db, auth, importer):
        super().__init__(master)
        self.title("Vault Import")
        self.geometry("1020x760")
        self.minsize(940, 700)
        self.db = db
        self.auth = auth
        self.importer = importer
        self.raw: bytes | None = None
        self._build()
        self._update_help()

    def _build(self) -> None:
        root = ttk.Frame(self)
        root.pack(fill="both", expand=True, padx=12, pady=12)

        top_info = ttk.LabelFrame(root, text="Что делает импорт")
        top_info.pack(fill="x", pady=(0, 10))
        ttk.Label(
            top_info,
            text=(
                "Импорт загружает записи из внешнего файла в текущее хранилище.\n"
                "Сначала используйте Dry run, чтобы посмотреть результат без изменения данных.\n"
                "Режим Replace удаляет текущие записи и загружает новые."
            ),
            justify="left",
        ).pack(anchor="w", padx=10, pady=8)

        content = ttk.Frame(root)
        content.pack(fill="both", expand=True)

        left = ttk.Frame(content)
        left.pack(side="left", fill="both", expand=True)

        right = ttk.Frame(content)
        right.pack(side="left", fill="both", expand=True, padx=(12, 0))

        top = ttk.Frame(left)
        top.pack(fill="x")

        self.format_var = tk.StringVar(value="")
        self.mode_var = tk.StringVar(value="merge")
        self.dup_var = tk.StringVar(value="skip")

        ttk.Button(top, text="Выбрать файл", command=self._choose_file).pack(side="left")
        ttk.Label(top, text="Формат").pack(side="left", padx=(12, 4))
        format_box = ttk.Combobox(
            top,
            textvariable=self.format_var,
            values=["", "encrypted_json", "csv", "bitwarden_json", "lastpass_csv"],
            width=18,
        )
        format_box.pack(side="left")
        format_box.bind("<<ComboboxSelected>>", lambda _e: self._update_help())

        ttk.Label(top, text="Режим").pack(side="left", padx=(12, 4))
        mode_box = ttk.Combobox(top, textvariable=self.mode_var, values=["merge", "replace"], width=12, state="readonly")
        mode_box.pack(side="left")
        mode_box.bind("<<ComboboxSelected>>", lambda _e: self._update_help())

        ttk.Label(top, text="Дубликаты").pack(side="left", padx=(12, 4))
        ttk.Combobox(top, textvariable=self.dup_var, values=["skip"], width=12, state="readonly").pack(side="left")

        pw_frame = ttk.Frame(left)
        pw_frame.pack(fill="x", pady=(10, 0))
        ttk.Label(pw_frame, text="Пароль импорта (нужен для encrypted_json, если файл защищён паролем)").pack(anchor="w")
        self.password_entry = ttk.Entry(pw_frame, show="*")
        self.password_entry.pack(fill="x")

        ttk.Label(left, text="Предпросмотр / summary", font=("TkDefaultFont", 10, "bold")).pack(anchor="w", pady=(10, 0))
        self.preview = tk.Text(left, wrap="word")
        self.preview.pack(fill="both", expand=True)

        ttk.Label(right, text="Подсказка", font=("TkDefaultFont", 10, "bold")).pack(anchor="w")
        self.help_text = tk.Text(right, wrap="word", height=18)
        self.help_text.pack(fill="x", expand=False)

        tips = ttk.LabelFrame(right, text="Что выбрать")
        tips.pack(fill="x", pady=(10, 0))
        ttk.Label(
            tips,
            text=(
                "• encrypted_json — если файл был экспортирован из CryptoSafe Manager\n"
                "• csv — если у вас простой табличный файл\n"
                "• bitwarden_json — если файл экспортирован из Bitwarden\n"
                "• lastpass_csv — если файл экспортирован из LastPass\n"
                "• merge — безопаснее для обычного импорта\n"
                "• replace — только если хотите полностью заменить vault"
            ),
            justify="left",
        ).pack(anchor="w", padx=10, pady=8)

        bottom = ttk.Frame(root)
        bottom.pack(fill="x", pady=(12, 0))
        ttk.Button(bottom, text="Dry run", command=self._dry_run).pack(side="left")
        ttk.Button(bottom, text="Импортировать", command=self._import).pack(side="right")
        ttk.Button(bottom, text="Закрыть", command=self.destroy).pack(side="right", padx=(0, 8))

    def _update_help(self) -> None:
        fmt = self.format_var.get()
        mode = self.mode_var.get()

        notes = [
            "Формат:",
            IMPORT_FORMAT_HELP.get(fmt, ""),
            "",
            "Режим:",
            IMPORT_MODE_HELP.get(mode, ""),
            "",
            "Пояснения:",
        ]

        if fmt == "encrypted_json":
            notes.append("- Если файл был зашифрован паролем, введите его в поле пароля импорта.")
        if fmt == "csv":
            notes.append("- CSV подходит для простого миграционного импорта.")
        if fmt == "bitwarden_json":
            notes.append("- Используйте для файлов, экспортированных из Bitwarden.")
        if fmt == "lastpass_csv":
            notes.append("- Используйте для CSV, экспортированных из LastPass.")
        if mode == "merge":
            notes.append("- Текущие записи останутся в vault.")
        if mode == "replace":
            notes.append("- Все текущие записи будут удалены перед импортом.")

        self.help_text.delete("1.0", "end")
        self.help_text.insert("1.0", "\n".join(notes))

    def _choose_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Выберите файл импорта",
            filetypes=[("All supported", "*.json *.csv"), ("JSON", "*.json"), ("CSV", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        with open(path, "rb") as f:
            self.raw = f.read()
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", f"Loaded file: {path}\nSize: {len(self.raw)} bytes\n")

    def _build_options(self, dry_run: bool) -> ImportOptions:
        return ImportOptions(
            mode=self.mode_var.get(),
            dry_run=dry_run,
            duplicate_strategy=self.dup_var.get(),
        )

    def _dry_run(self) -> None:
        if not self.raw:
            messagebox.showerror("Ошибка", "Сначала выберите файл")
            return

        result = self.importer.import_data(
            self.raw,
            import_format=self.format_var.get() or None,
            password=self.password_entry.get().strip() or None,
            options=self._build_options(dry_run=True),
        )
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2))

    def _import(self) -> None:
        if not self.raw:
            messagebox.showerror("Ошибка", "Сначала выберите файл")
            return

        confirm = simpledialog.askstring("Подтверждение", "Введите мастер-пароль для подтверждения импорта:", show="*", parent=self)
        if not confirm:
            return

        ok, msg = self.auth.authenticate(confirm)
        if not ok:
            messagebox.showerror("Ошибка", msg or "Проверка мастер-пароля не пройдена")
            return

        result = self.importer.import_data(
            self.raw,
            import_format=self.format_var.get() or None,
            password=self.password_entry.get().strip() or None,
            options=self._build_options(dry_run=False),
        )
        checksum = hashlib.sha256(self.raw).hexdigest()
        summary = result.get("summary", {})

        self.db.insert_import_export_history(
            operation_type="import",
            data_format=summary.get("format", self.format_var.get() or "auto"),
            encryption_used="password" if self.password_entry.get().strip() else "none",
            entry_count=len(result.get("created_ids", [])),
            file_size=len(self.raw),
            checksum=checksum,
            verification_status="ok",
            created_at="imported",
        )

        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2))
        messagebox.showinfo("Импорт", f'Импортировано записей: {len(result.get("created_ids", []))}')


class ContactsDialog(tk.Toplevel):
    def __init__(self, master, db, key_exchange_service):
        super().__init__(master)
        self.title("Contacts")
        self.geometry("950x520")
        self.db = db
        self.key_exchange_service = key_exchange_service
        self._build()
        self.refresh()

    def _build(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Button(top, text="Add contact", command=self._add_contact).pack(side="left")
        ttk.Button(top, text="Generate RSA keypair", command=lambda: self._generate_keypair("rsa")).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="Generate EC keypair", command=lambda: self._generate_keypair("ec")).pack(side="left", padx=(8, 0))

        self.tree = ttk.Treeview(self, columns=("name", "identifier", "fingerprint", "last_used"), show="headings")
        for col, title, width in [
            ("name", "Name", 180),
            ("identifier", "Identifier", 220),
            ("fingerprint", "Fingerprint", 360),
            ("last_used", "Last used", 140),
        ]:
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def refresh(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for row in self.db.list_contacts():
            self.tree.insert(
                "",
                "end",
                values=(
                    row.get("contact_name", ""),
                    row.get("contact_identifier", ""),
                    row.get("fingerprint", ""),
                    row.get("last_used_at", "") or "",
                ),
            )

    def _add_contact(self) -> None:
        name = simpledialog.askstring("Contact", "Contact name:", parent=self)
        if not name:
            return
        identifier = simpledialog.askstring("Contact", "Identifier / email:", parent=self)
        if not identifier:
            return

        editor = tk.Toplevel(self)
        editor.title("Paste public key")
        editor.geometry("700x400")

        txt = tk.Text(editor, wrap="word")
        txt.pack(fill="both", expand=True, padx=10, pady=10)

        def save():
            public_key = txt.get("1.0", "end").strip()
            if not public_key:
                messagebox.showerror("Error", "Public key is required")
                return
            try:
                fingerprint = self.key_exchange_service.validate_public_key(public_key.encode("utf-8"))
            except Exception as e:
                messagebox.showerror("Error", f"Invalid public key:\n{e}")
                return
            self.db.add_contact(name, identifier, public_key, fingerprint)
            editor.destroy()
            self.refresh()

        ttk.Button(editor, text="Save", command=save).pack(pady=(0, 10))

    def _generate_keypair(self, mode: str) -> None:
        pair = self.key_exchange_service.generate_rsa_keypair() if mode == "rsa" else self.key_exchange_service.generate_ec_keypair()

        win = tk.Toplevel(self)
        win.title("Generated keypair")
        win.geometry("900x620")

        ttk.Label(win, text=f"Algorithm: {pair.algorithm}").pack(anchor="w", padx=10, pady=(10, 0))
        ttk.Label(win, text=f"Fingerprint: {pair.fingerprint}").pack(anchor="w", padx=10, pady=(4, 10))

        txt = tk.Text(win, wrap="word")
        txt.pack(fill="both", expand=True, padx=10, pady=10)
        txt.insert(
            "1.0",
            "PRIVATE KEY:\n\n"
            + pair.private_pem.decode("utf-8")
            + "\nPUBLIC KEY:\n\n"
            + pair.public_pem.decode("utf-8"),
        )


class ShareDialog(tk.Toplevel):
    def __init__(self, master, db, entry_manager, sharing_service, key_exchange_service, qr_service, entry_id: int):
        super().__init__(master)
        self.title("Share Entry")
        self.geometry("980x720")
        self.db = db
        self.entry_manager = entry_manager
        self.sharing_service = sharing_service
        self.key_exchange_service = key_exchange_service
        self.qr_service = qr_service
        self.entry_id = entry_id
        self._last_share_package: dict[str, Any] | None = None
        self._build()

    def _build(self) -> None:
        root = ttk.Frame(self)
        root.pack(fill="both", expand=True, padx=12, pady=12)

        left = ttk.Frame(root)
        left.pack(side="left", fill="both", expand=True)

        right = ttk.Frame(root)
        right.pack(side="left", fill="both", expand=True, padx=(12, 0))

        self.recipient_var = tk.StringVar()
        self.method_var = tk.StringVar(value="password")
        self.days_var = tk.StringVar(value="7")
        self.read_only_var = tk.BooleanVar(value=True)
        self.include_notes_var = tk.BooleanVar(value=True)

        ttk.Label(left, text="Recipient").pack(anchor="w")
        ttk.Entry(left, textvariable=self.recipient_var).pack(fill="x")

        ttk.Label(left, text="Method").pack(anchor="w", pady=(8, 0))
        ttk.Combobox(left, textvariable=self.method_var, values=["password", "public_key"], state="readonly").pack(fill="x")

        ttk.Label(left, text="Share password").pack(anchor="w", pady=(8, 0))
        self.password_entry = ttk.Entry(left, show="*")
        self.password_entry.pack(fill="x")

        ttk.Label(left, text="Recipient public key (PEM)").pack(anchor="w", pady=(8, 0))
        self.public_key_text = tk.Text(left, height=10, wrap="word")
        self.public_key_text.pack(fill="x")

        ttk.Label(left, text="Expiration (days)").pack(anchor="w", pady=(8, 0))
        ttk.Combobox(left, textvariable=self.days_var, values=[str(i) for i in range(1, 31)], state="readonly").pack(fill="x")

        ttk.Checkbutton(left, text="Read only", variable=self.read_only_var).pack(anchor="w", pady=(8, 0))
        ttk.Checkbutton(left, text="Include notes", variable=self.include_notes_var).pack(anchor="w")

        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="Create share", command=self._share).pack(side="left")
        ttk.Button(btns, text="Show QR", command=self._show_qr).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Close", command=self.destroy).pack(side="right")

        ttk.Label(right, text="Generated package", font=("TkDefaultFont", 10, "bold")).pack(anchor="w")
        self.preview = tk.Text(right, wrap="word")
        self.preview.pack(fill="both", expand=True)

    def _share(self) -> None:
        recipient = self.recipient_var.get().strip()
        if not recipient:
            messagebox.showerror("Error", "Recipient is required")
            return

        method = self.method_var.get()
        password = self.password_entry.get().strip() or None
        public_key_raw = self.public_key_text.get("1.0", "end").strip()

        options = ShareOptions(
            recipient=recipient,
            permissions={
                "read_only": self.read_only_var.get(),
                "include_notes": self.include_notes_var.get(),
            },
            expires_in_days=int(self.days_var.get()),
            method=method,
            password=password,
            public_key_pem=public_key_raw.encode("utf-8") if public_key_raw else None,
        )

        result = self.sharing_service.share_entry(self.entry_id, options)
        self._last_share_package = result["package"]
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2))

    def _show_qr(self) -> None:
        if not self._last_share_package:
            messagebox.showerror("Error", "Create share package first")
            return

        payload = json.dumps(self._last_share_package, ensure_ascii=False)
        QRViewerDialog(self, payload, title="Share Package QR")


__all__ = [
    "ExportDialog",
    "ImportDialog",
    "ShareDialog",
    "QRViewerDialog",
    "ContactsDialog",
]