from __future__ import annotations

from tkinter import ttk


class AuditLogViewer(ttk.Frame):

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        lbl = ttk.Label(self, text="Audit Log Viewer (заглушка, Спринт 5)")
        lbl.pack(padx=12, pady=12)
