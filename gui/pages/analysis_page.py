"""Analysis page: file pickers (PCAP, PE/ELF, CSV/JSON) and a scrollable result area."""
import customtkinter as ctk
from tkinter import filedialog

from gui import ACCENT, MUTED, Page, button, card, entry, label, output_box, set_text
from modules import analysis, common

KINDS = [("pcap", "PCAP file", [("Packet captures", "*.pcap *.pcapng *.cap"), ("All files", "*")]),
         ("binary", "PE / ELF binary", [("All files", "*")]),
         ("data", "CSV / JSON file", [("Data files", "*.csv *.json"), ("All files", "*")])]


class AnalysisPage(Page):
    title = "File & Traffic Analysis"

    def __init__(self, master, app):
        super().__init__(master, app)
        box = card(self)
        box.pack(fill="x", padx=24, pady=(0, 10))
        box.grid_columnconfigure(1, weight=1)
        self.paths, self.btns = {}, []
        for i, (kind, text, types) in enumerate(KINDS):
            label(box, text, 12, MUTED).grid(row=i, column=0, sticky="w", padx=16, pady=8)
            e = entry(box, "No file selected", 500)
            e.grid(row=i, column=1, sticky="ew", padx=8)
            self.paths[kind] = e
            button(box, "Browse", lambda e=e, t=types: self._browse(e, t), 90, True).grid(row=i, column=2, padx=4)
            b = button(box, "Analyze", lambda k=kind: self._run(k), 100)
            b.grid(row=i, column=3, padx=(4, 16))
            self.btns.append(b)
        label(box, "Samples are parsed as bytes only - never executed.", 11, MUTED).grid(
            row=3, column=0, columnspan=4, sticky="w", padx=16, pady=(0, 10))
        self.bar = ctk.CTkProgressBar(self, mode="indeterminate", progress_color=ACCENT, fg_color="#263340")
        self.bar.pack(fill="x", padx=24, pady=(0, 8))
        self.bar.set(0)
        self.out = output_box(self)
        self.out.pack(fill="both", expand=True, padx=24, pady=(0, 24))

    def _browse(self, e, types):
        p = filedialog.askopenfilename(filetypes=types)
        if p:
            e.delete(0, "end")
            e.insert(0, p)

    def _run(self, kind):
        path = self.paths[kind].get().strip()
        if not path:
            set_text(self.out, "Select a file first.")
            return
        set_text(self.out, "Analyzing...")
        for b in self.btns:
            b.configure(state="disabled")
        self.bar.start()
        common.run_async(self, lambda emit: analysis.analyze(kind, path, emit),
                         lambda k, v: set_text(self.out, f"Analyzing... {v}") if k == "status" else None,
                         self._done)

    def _done(self, res, err):
        self.bar.stop()
        self.bar.set(0)
        for b in self.btns:
            b.configure(state="normal")
        set_text(self.out, res if not err else f"[ERROR] {type(err).__name__}: {err}")
