from __future__ import annotations

import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.core.audit import AuditExportFormatter, LogVerifier


class AuditLogViewer(tk.Toplevel):
    def __init__(self, master, db, audit_logger):
        super().__init__(master)
        self.title("Audit Log Viewer")
        self.geometry("1100x650")
        self.db = db
        self.audit_logger = audit_logger
        self.verifier = LogVerifier(audit_logger)

        self.limit = 50
        self.offset = 0

        self._build()
        self.refresh_rows()

    def _build(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)

        self.search_var = tk.StringVar()
        self.event_var = tk.StringVar()
        self.severity_var = tk.StringVar()

        ttk.Label(top, text="Search").pack(side="left")
        ttk.Entry(top, textvariable=self.search_var, width=30).pack(side="left", padx=(6, 10))

        ttk.Label(top, text="Event").pack(side="left")
        ttk.Entry(top, textvariable=self.event_var, width=18).pack(side="left", padx=(6, 10))

        ttk.Label(top, text="Severity").pack(side="left")
        ttk.Combobox(top, textvariable=self.severity_var, values=["", "INFO", "WARN", "ERROR", "CRITICAL"], width=12).pack(side="left", padx=(6, 10))

        ttk.Button(top, text="Apply", command=self._reset_and_refresh).pack(side="left")
        ttk.Button(top, text="Verify", command=self.verify_full).pack(side="left", padx=(10, 0))
        ttk.Button(top, text="Export JSON", command=self.export_json).pack(side="left", padx=(10, 0))
        ttk.Button(top, text="Export CSV", command=self.export_csv).pack(side="left", padx=(6, 0))
        ttk.Button(top, text="Export PDF", command=self.export_pdf).pack(side="left", padx=(6, 0))

        middle = ttk.Frame(self)
        middle.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        columns = ("seq", "timestamp", "severity", "event", "source", "entry_id")
        self.tree = ttk.Treeview(middle, columns=columns, show="headings", height=18)
        for c, title, w in [
            ("seq", "Seq", 70),
            ("timestamp", "Timestamp", 220),
            ("severity", "Severity", 90),
            ("event", "Event", 180),
            ("source", "Source", 120),
            ("entry_id", "Entry ID", 90),
        ]:
            self.tree.heading(c, text=title)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.show_details)

        scroll = ttk.Scrollbar(middle, orient="vertical", command=self.tree.yview)
        scroll.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scroll.set)

        bottom = ttk.Frame(self)
        bottom.pack(fill="both", expand=False, padx=10, pady=(0, 10))

        self.details = tk.Text(bottom, height=12, wrap="word")
        self.details.pack(fill="both", expand=True)

        nav = ttk.Frame(self)
        nav.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(nav, text="Prev", command=self.prev_page).pack(side="left")
        ttk.Button(nav, text="Next", command=self.next_page).pack(side="left", padx=(6, 0))

    def _reset_and_refresh(self) -> None:
        self.offset = 0
        self.refresh_rows()

    def refresh_rows(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

        rows = self.db.fetch_audit_entries(
            limit=self.limit,
            offset=self.offset,
            event_type=self.event_var.get().strip() or None,
            severity=self.severity_var.get().strip() or None,
            search=self.search_var.get().strip() or None,
        )

        self._current_rows = rows
        for row in rows:
            self.tree.insert(
                "",
                "end",
                iid=str(row["sequence_number"]),
                values=(
                    row["sequence_number"],
                    row.get("timestamp_utc", ""),
                    row.get("severity", ""),
                    row.get("event_type", ""),
                    row.get("source", ""),
                    row.get("entry_id", ""),
                ),
            )

    def show_details(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return

        seq = int(sel[0])
        row = next((r for r in self._current_rows if int(r["sequence_number"]) == seq), None)
        if not row:
            return

        self.details.delete("1.0", "end")
        pretty = {
            "sequence_number": row.get("sequence_number"),
            "timestamp_utc": row.get("timestamp_utc"),
            "severity": row.get("severity"),
            "event_type": row.get("event_type"),
            "source": row.get("source"),
            "entry_id": row.get("entry_id"),
            "previous_hash": row.get("previous_hash"),
            "entry_hash": row.get("entry_hash"),
            "signature": row.get("signature"),
            "public_key": row.get("public_key"),
            "signing_mode": row.get("signing_mode"),
            "entry_data": bytes(row["entry_data"]).decode("utf-8", errors="ignore") if row.get("entry_data") else "",
        }
        self.details.insert("1.0", json.dumps(pretty, ensure_ascii=False, indent=2))

    def verify_full(self) -> None:
        report = self.verifier.verify_full()
        messagebox.showinfo("Verification", self.verifier.to_pretty_text(report))

    def export_json(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return
        rows = self.db.fetch_audit_entries(limit=100000)
        AuditExportFormatter.export_signed_json(rows, path)
        messagebox.showinfo("Export", f"Saved: {path}")

    def export_csv(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        rows = self.db.fetch_audit_entries(limit=100000)
        AuditExportFormatter.export_csv(rows, path)
        messagebox.showinfo("Export", f"Saved: {path}")

    def export_pdf(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
        if not path:
            return
        rows = self.db.fetch_audit_entries(limit=100000)
        AuditExportFormatter.export_pdf(rows, path)
        messagebox.showinfo("Export", f"Saved: {path}")

    def next_page(self) -> None:
        self.offset += self.limit
        self.refresh_rows()

    def prev_page(self) -> None:
        self.offset = max(0, self.offset - self.limit)
        self.refresh_rows()