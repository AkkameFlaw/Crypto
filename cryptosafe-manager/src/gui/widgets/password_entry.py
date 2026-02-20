from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class PasswordEntry(ttk.Frame):

    def __init__(self, master, *, width: int = 28, **kwargs):
        super().__init__(master, **kwargs)
        self._var = tk.StringVar()
        self._shown = False

        self.entry = ttk.Entry(self, textvariable=self._var, show="*", width=width)
        self.entry.grid(row=0, column=0, sticky="ew")

        self.btn = ttk.Button(self, text="Показать", command=self._toggle, width=10)
        self.btn.grid(row=0, column=1, padx=(6, 0))

        self.columnconfigure(0, weight=1)

    def _toggle(self) -> None:
        self._shown = not self._shown
        self.entry.configure(show="" if self._shown else "*")
        self.btn.configure(text="Скрыть" if self._shown else "Показать")

    def get(self) -> str:
        return self._var.get()

    def set(self, value: str) -> None:
        self._var.set(value)

    def focus(self) -> None:
        self.entry.focus_set()
