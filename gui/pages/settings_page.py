"""Settings page: grouped API keys (scrollable) and the safe-mode toggle."""
import customtkinter as ctk

from gui import ACCENT, ACCENT_HOVER, BG, DANGER, MUTED, OK, TEXT, Page, button, card, entry, label
from modules import common


class SettingsPage(Page):
    title = "Settings"

    def __init__(self, master, app):
        super().__init__(master, app)
        cfg = common.load_config()
        top = card(self)
        top.pack(fill="x", padx=24, pady=(0, 10))
        self.safe_var = ctk.BooleanVar(value=common.is_safe_mode())
        self.switch = ctk.CTkSwitch(top, text="Safe Mode (disables all active scanning)", variable=self.safe_var,
                                    command=self._toggle, progress_color=ACCENT, button_hover_color=ACCENT_HOVER, text_color=TEXT)
        self.switch.pack(side="left", padx=16, pady=14)
        if common.is_safe_forced():
            self.switch.configure(state="disabled")
            label(top, "(locked ON by --safe-mode flag)", 11, MUTED).pack(side="left")
        self.show_var = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(top, text="Show keys", variable=self.show_var, command=self._show, progress_color=ACCENT,
                      text_color=TEXT).pack(side="right", padx=16)
        scroll = ctk.CTkScrollableFrame(self, fg_color=BG, border_color="#263340", border_width=1)
        scroll.pack(fill="both", expand=True, padx=24, pady=(0, 8))
        self.entries, group = {}, None
        for key, text, grp in common.API_KEYS:
            if grp != group:
                group = grp
                label(scroll, group.upper(), 11, ACCENT_HOVER, "bold").pack(anchor="w", padx=8, pady=(14, 2))
            row = ctk.CTkFrame(scroll, fg_color="transparent")
            row.pack(fill="x", pady=2)
            label(row, text, 12, TEXT).pack(side="left", padx=8)
            e = entry(row, "not set", 420, show="*")
            e.pack(side="right", padx=8)
            e.insert(0, cfg.get(key, ""))
            self.entries[key] = e
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=24, pady=(0, 20))
        button(row, "Save", self._save, 120).pack(side="left")
        self.msg = label(row, "", 12, OK)
        self.msg.pack(side="left", padx=12)
        common.add_safe_listener(lambda on: self.safe_var.set(on))

    def _show(self):
        for e in self.entries.values():
            e.configure(show="" if self.show_var.get() else "*")

    def _toggle(self):
        if not common.set_safe_mode(self.safe_var.get()):
            self.safe_var.set(True)

    def _save(self):
        cfg = common.load_config()
        cfg.update({k: e.get().strip() for k, e in self.entries.items()})
        cfg["safe_mode"] = common.is_safe_mode()
        try:
            common.save_config(cfg)
            self.msg.configure(text="Saved to config/settings.json", text_color=OK)
        except OSError as e:
            self.msg.configure(text=f"Save failed: {e}", text_color=DANGER)
