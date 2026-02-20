from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Iterable, Mapping


class SecureTable(ttk.Frame):

    columns = ("id", "title", "username", "url", "tags", "updated_at")

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.tree = ttk.Treeview(self, columns=self.columns, show="headings", height=14)
        self.scroll_y = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scroll_y.set)

        headings = {
            "id": "ID",
            "title": "Title",
            "username": "Username",
            "url": "URL",
            "tags": "Tags",
            "updated_at": "Updated",
        }
        widths = {"id": 60, "title": 220, "username": 160, "url": 220, "tags": 160, "updated_at": 120}

        for col in self.columns:
            self.tree.heading(col, text=headings.get(col, col))
            self.tree.column(col, width=widths.get(col, 120), anchor="w")

        self.tree.grid(row=0, column=0, sticky="nsew")
        self.scroll_y.grid(row=0, column=1, sticky="ns")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

    def set_rows(self, rows: Iterable[Mapping]) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for r in rows:
            values = (
                r.get("id"),
                r.get("title", ""),
                r.get("username", ""),
                r.get("url", ""),
                r.get("tags", ""),
                r.get("updated_at", ""),
            )
            self.tree.insert("", "end", values=values)
