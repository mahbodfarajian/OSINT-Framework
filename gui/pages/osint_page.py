"""OSINT page: pick a target type first, then only the relevant fields are shown."""
import customtkinter as ctk
from tkinter import filedialog, messagebox

from gui import ACCENT, ACCENT_HOVER, CARD, MUTED, TEXT, Page, append_text, button, card, entry, label, output_box, set_text
from modules import common, osint

# target type -> [(field key, label, placeholder)] ; the first field is required
TYPES = {
    "Website": [("domain", "Domain", "example.com"), ("ip", "Related IP (optional)", "203.0.113.10")],
    "Server / IP": [("ip", "IP address", "203.0.113.10"), ("domain", "Related domain (optional)", "example.com")],
    "Email": [("email", "Email address", "user@example.com"), ("username", "Username (optional)", "handle")],
    "Network": [("network", "CIDR range or ASN", "203.0.113.0/24   or   AS13335")],
    "Username": [("username", "Username", "handle"), ("email", "Email (optional)", "user@example.com")],
    "Phone": [("phone", "Phone number", "+4915112345678"), ("region", "Default region (optional)", "DE")],
    "File Metadata": [("file", "File path", "")],
}


class OsintPage(Page):
    title = "OSINT Investigation"

    def __init__(self, master, app):
        super().__init__(master, app)
        box = card(self)
        box.pack(fill="x", padx=24, pady=(0, 10))
        label(box, "1. Target type", 12, MUTED).pack(anchor="w", padx=16, pady=(12, 4))
        self.seg = ctk.CTkSegmentedButton(box, values=list(TYPES), command=self._build, selected_color=ACCENT,
                                          unselected_color=CARD, fg_color=CARD, text_color=TEXT)
        self.seg.pack(anchor="w", padx=16)
        label(box, "2. Details", 12, MUTED).pack(anchor="w", padx=16, pady=(12, 0))
        self.body = ctk.CTkFrame(box, fg_color="transparent")
        self.body.pack(fill="x", padx=12, pady=4)
        bar = ctk.CTkFrame(box, fg_color="transparent")
        bar.pack(fill="x", padx=12, pady=(4, 12))
        self.active_var = ctk.BooleanVar(value=False)
        self.active_chk = ctk.CTkCheckBox(bar, text="Allow active checks (needs Safe Mode OFF)", variable=self.active_var,
                                          fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=TEXT)
        self.run_btn = button(bar, "Run", self._run, 110)
        self.run_btn.pack(side="right", padx=4)
        self.active_chk.pack(side="left", padx=4)
        self.progress = ctk.CTkProgressBar(self, progress_color=ACCENT, fg_color="#263340")
        self.progress.set(0)
        self.progress.pack(fill="x", padx=24, pady=(0, 8))
        self.out = output_box(self)
        self.out.pack(fill="both", expand=True, padx=24, pady=(0, 24))
        self.fields, self.kind = {}, "Website"
        self.seg.set("Website")
        self._build("Website")
        common.add_safe_listener(self._on_safe)
        self._on_safe(common.is_safe_mode())

    def _build(self, kind):
        self.kind = kind
        for w in self.body.winfo_children():
            w.destroy()
        self.fields = {}
        for key, text, ph in TYPES[kind]:
            row = ctk.CTkFrame(self.body, fg_color="transparent")
            row.pack(fill="x", pady=3)
            label(row, text, 12, TEXT).pack(side="left", padx=(4, 12))
            e = entry(row, ph, 420)
            e.pack(side="left")
            if key == "file":
                button(row, "Browse", lambda e=e: self._pick(e), 90, True).pack(side="left", padx=8)
            self.fields[key] = e
        if kind == "Website":
            self.active_chk.pack(side="left", padx=4)
        else:
            self.active_chk.pack_forget()

    def _on_safe(self, enabled):
        if enabled:
            self.active_var.set(False)
        self.active_chk.configure(state="disabled" if enabled else "normal")

    def _pick(self, e):
        p = filedialog.askopenfilename(title="File for metadata extraction")
        if p:
            e.delete(0, "end")
            e.insert(0, p)

    def _run(self):
        t = {k: e.get().strip() for k, e in self.fields.items()}
        if not t[TYPES[self.kind][0][0]]:
            messagebox.showwarning("OSINT", f"Enter the {TYPES[self.kind][0][1].lower()}.")
            return
        t["active"] = self.kind == "Website" and self.active_var.get() and not common.is_safe_mode()
        common.log.info("OSINT run: type=%s fields=%s", self.kind, [k for k, v in t.items() if v])
        set_text(self.out, f"Target type: {self.kind}   |   Safe mode: {'ON (passive only)' if common.is_safe_mode() else 'OFF'}\n")
        self.progress.set(0)
        self.run_btn.configure(state="disabled")
        common.run_async(self, lambda emit: osint.run_investigation(t, emit), self._on_msg, self._on_done)

    def _on_msg(self, kind, val):
        if kind == "progress":
            self.progress.set(val)
        elif kind == "text":
            append_text(self.out, val)

    def _on_done(self, _res, err):
        self.run_btn.configure(state="normal")
        append_text(self.out, f"\n[ERROR] {err}\n" if err else "\nDone.\n")
