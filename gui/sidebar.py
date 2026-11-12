"""Left navigation sidebar."""
import customtkinter as ctk

from gui import ACCENT, BORDER, MUTED, SIDEBAR, TEXT, font


class Sidebar(ctk.CTkFrame):
    def __init__(self, master, items, on_select):
        super().__init__(master, width=210, fg_color=SIDEBAR, corner_radius=0)
        self.pack_propagate(False)
        ctk.CTkLabel(self, text="SECURITY TOOLKIT", font=font(14, "bold"), text_color=TEXT).pack(pady=(22, 2))
        ctk.CTkLabel(self, text="Kali Linux Edition", font=font(10), text_color=MUTED).pack(pady=(0, 20))
        self.buttons = {}
        for name in items:
            btn = ctk.CTkButton(self, text=f"   {name}", anchor="w", height=40, corner_radius=6,
                                fg_color="transparent", hover_color=BORDER, text_color=TEXT,
                                font=font(13), command=lambda n=name: on_select(n))
            btn.pack(fill="x", padx=12, pady=3)
            self.buttons[name] = btn
        ctk.CTkLabel(self, text="Authorized use only", font=font(10), text_color=MUTED).pack(side="bottom", pady=14)

    def set_active(self, name):
        for n, b in self.buttons.items():
            b.configure(fg_color=ACCENT if n == name else "transparent")
