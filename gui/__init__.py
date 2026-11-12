"""GUI package: theme constants and shared widget helpers."""
from tkinter import ttk

import customtkinter as ctk

# ---- palette (dark, formal, deep teal-blue accent)
BG, SIDEBAR, CARD, BORDER = "#0d1117", "#111820", "#18212b", "#263340"
ACCENT, ACCENT_HOVER = "#1f7a8c", "#2a9bb3"
TEXT, MUTED = "#e6edf3", "#8b98a5"
OK, WARN, DANGER = "#3fb27f", "#d9a441", "#e5534b"
FONT, MONO = "DejaVu Sans", "DejaVu Sans Mono"


def font(size=13, weight="normal"):
    return ctk.CTkFont(family=FONT, size=size, weight=weight)


def mono(size=12):
    return ctk.CTkFont(family=MONO, size=size)


def button(parent, text, command, width=130, secondary=False):
    return ctk.CTkButton(parent, text=text, command=command, width=width, height=34, corner_radius=6,
                         font=font(12, "bold"), text_color=TEXT,
                         fg_color=BORDER if secondary else ACCENT,
                         hover_color="#34475a" if secondary else ACCENT_HOVER)


def entry(parent, placeholder="", width=300, show=None):
    return ctk.CTkEntry(parent, placeholder_text=placeholder, width=width, height=34, show=show,
                        fg_color=BG, border_color=BORDER, text_color=TEXT, font=font(12))


def label(parent, text, size=12, color=TEXT, weight="normal"):
    return ctk.CTkLabel(parent, text=text, text_color=color, font=font(size, weight))


def card(parent):
    return ctk.CTkFrame(parent, fg_color=CARD, border_color=BORDER, border_width=1, corner_radius=8)


def output_box(parent):
    box = ctk.CTkTextbox(parent, fg_color=CARD, text_color=TEXT, font=mono(), border_color=BORDER,
                         border_width=1, corner_radius=8, wrap="word")
    box.configure(state="disabled")
    return box


def set_text(box, text):
    box.configure(state="normal")
    box.delete("1.0", "end")
    box.insert("end", text)
    box.configure(state="disabled")


def append_text(box, text):
    box.configure(state="normal")
    box.insert("end", text)
    box.see("end")
    box.configure(state="disabled")


_styled = False


def make_tree(parent, columns, widths=None, height=10):
    """Dark-themed ttk.Treeview with a CTk scrollbar. Returns (container_frame, tree)."""
    global _styled
    if not _styled:
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT,
                    rowheight=26, borderwidth=0, font=(FONT, 10))
        s.configure("Treeview.Heading", background=SIDEBAR, foreground=TEXT, relief="flat",
                    font=(FONT, 10, "bold"))
        s.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "white")])
        s.map("Treeview.Heading", background=[("active", BORDER)])
        _styled = True
    frame = ctk.CTkFrame(parent, fg_color=CARD, border_color=BORDER, border_width=1, corner_radius=8)
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)
    tree = ttk.Treeview(frame, columns=columns, show="headings", height=height)
    sb = ctk.CTkScrollbar(frame, command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    tree.grid(row=0, column=0, sticky="nsew", padx=(2, 0), pady=2)
    sb.grid(row=0, column=1, sticky="ns", padx=2, pady=2)
    for i, col in enumerate(columns):
        tree.heading(col, text=col)
        tree.column(col, width=(widths[i] if widths else 120), anchor="w")
    return frame, tree


class Page(ctk.CTkFrame):
    """Base class for content pages."""
    title = ""

    def __init__(self, master, app):
        super().__init__(master, fg_color=BG, corner_radius=0)
        self.app = app
        label(self, self.title, 22, weight="bold").pack(anchor="w", padx=24, pady=(18, 10))

    def on_show(self):
        """Called whenever the page becomes visible."""
