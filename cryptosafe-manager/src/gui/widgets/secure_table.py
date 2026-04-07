from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Iterable, Mapping


def mask_username(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "•" * len(value)
    return value[:4] + "•" * max(1, len(value) - 4)


class SecureTable(ttk.Frame):
    columns = ("id", "title", "username", "domain", "password", "updated_at")

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self._show_passwords = False
        self._rows_by_id: dict[int, dict] = {}

        self.tree = ttk.Treeview(self, columns=self.columns, show="headings", height=16, selectmode="extended")
        self.scroll_y = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scroll_y.set)

        headings = {
            "id": "ID",
            "title": "Заголовок",
            "username": "Имя пользователя",
            "domain": "Домен",
            "password": "Пароль",
            "updated_at": "Изменён",
        }
        widths = {"id": 60, "title": 240, "username": 180, "domain": 180, "password": 160, "updated_at": 140}

        for col in self.columns:
            self.tree.heading(col, text=headings.get(col, col), command=lambda c=col: self._sort_by(c, False))
            self.tree.column(col, width=widths.get(col, 120), anchor="w", stretch=True)

        self.tree.grid(row=0, column=0, sticky="nsew")
        self.scroll_y.grid(row=0, column=1, sticky="ns")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

    def set_rows(self, rows: Iterable[Mapping]) -> None:
        self._rows_by_id = {}
        for item in self.tree.get_children():
            self.tree.delete(item)

        for r in rows:
            rid = int(r.get("id"))
            self._rows_by_id[rid] = dict(r)
            self.tree.insert("", "end", iid=str(rid), values=self._display_values(r))

    def _display_values(self, r: Mapping) -> tuple:
        username = str(r.get("username", "") or "")
        password = str(r.get("password", "") or "")
        return (
            r.get("id"),
            r.get("title", ""),
            username if self._show_passwords else mask_username(username),
            r.get("domain", ""),
            password if self._show_passwords else "••••••••",
            r.get("updated_at", ""),
        )

    def set_show_passwords(self, show: bool) -> None:
        self._show_passwords = bool(show)
        for rid, r in self._rows_by_id.items():
            if self.tree.exists(str(rid)):
                self.tree.item(str(rid), values=self._display_values(r))

    def selected_ids(self) -> list[int]:
        return [int(i) for i in self.tree.selection()]

    def bind_context_menu(self, callback) -> None:
        self.tree.bind("<Button-3>", callback)

    def bind_double_click(self, callback) -> None:
        self.tree.bind("<Double-1>", callback)

    def _sort_by(self, col: str, descending: bool) -> None:
        data = [(self.tree.set(child, col), child) for child in self.tree.get_children("")]
        data.sort(reverse=descending)
        for index, (_, child) in enumerate(data):
            self.tree.move(child, "", index)
        self.tree.heading(col, command=lambda: self._sort_by(col, not descending))