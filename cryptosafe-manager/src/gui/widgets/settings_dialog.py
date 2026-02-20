from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class SettingsDialog(tk.Toplevel):

    def __init__(self, master):
        super().__init__(master)
        self.title("Настройки (заглушка)")
        self.geometry("520x360")
        self.transient(master)
        self.grab_set()

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        tab_security = ttk.Frame(nb)
        tab_ui = ttk.Frame(nb)
        tab_adv = ttk.Frame(nb)

        nb.add(tab_security, text="Безопасность")
        nb.add(tab_ui, text="Внешний вид")
        nb.add(tab_adv, text="Дополнительно")

        ttk.Label(tab_security, text="Таймаут буфера / авто-блокировка (Спринт 4/7)").pack(anchor="w", padx=12, pady=12)
        ttk.Label(tab_ui, text="Тема / язык (заглушка)").pack(anchor="w", padx=12, pady=12)
        ttk.Label(tab_adv, text="Резервное копирование / экспорт (Спринт 8)").pack(anchor="w", padx=12, pady=12)

        btn = ttk.Button(self, text="Закрыть", command=self.destroy)
        btn.pack(pady=(0, 12))
