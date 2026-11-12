"""Terminal page: whitelisted read-only commands only, shell=False, metacharacters blocked."""
import customtkinter as ctk

from gui import BG, MUTED, OK, Page, append_text, button, entry, label, mono, output_box, set_text
from modules import common


class TerminalPage(Page):
    title = "Safe Terminal"

    def __init__(self, master, app):
        super().__init__(master, app)
        label(self, "Allowed: " + ", ".join(" ".join(c) for c in sorted(common.ALLOWED_COMMANDS)), 11, MUTED).pack(
            anchor="w", padx=26, pady=(0, 6))
        self.out = output_box(self)
        self.out.pack(fill="both", expand=True, padx=24, pady=(0, 8))
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=24, pady=(0, 24))
        label(row, "toolkit $", 13, OK, "bold").pack(side="left", padx=(0, 8))
        self.entry = entry(row, "type 'help' for commands", 500)
        self.entry.configure(font=mono(12))
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        button(row, "Run", self._submit, 90).pack(side="left")
        self.entry.bind("<Return>", lambda e: self._submit())
        self.entry.bind("<Up>", lambda e: self._hist(-1))
        self.entry.bind("<Down>", lambda e: self._hist(1))
        self.history, self.pos = [], 0
        set_text(self.out, "Read-only sandboxed terminal. Type 'help'.\n")

    def _hist(self, d):
        if self.history:
            self.pos = max(0, min(len(self.history), self.pos + d))
            self.entry.delete(0, "end")
            if self.pos < len(self.history):
                self.entry.insert(0, self.history[self.pos])

    def _submit(self):
        cmd = self.entry.get().strip()
        self.entry.delete(0, "end")
        if not cmd:
            return
        self.history.append(cmd)
        self.pos = len(self.history)
        append_text(self.out, f"\n$ {cmd}\n")
        if cmd == "help":
            append_text(self.out, "Allowed commands:\n  " + "\n  ".join(" ".join(c) for c in sorted(common.ALLOWED_COMMANDS)) + "\n  clear\n")
        elif cmd == "clear":
            set_text(self.out, "")
        else:
            common.run_async(self, lambda emit: common.safe_exec(cmd), None,
                             lambda res, err: append_text(self.out, (res or f"[ERROR] {err}") + "\n"))
