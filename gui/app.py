import customtkinter as ctk

from gui import BG, DANGER, OK, SIDEBAR, TEXT, ACCENT, ACCENT_HOVER, font, label
from gui.pages.analysis_page import AnalysisPage
from gui.pages.case_page import CasePage
from gui.pages.dashboard import DashboardPage
from gui.pages.osint_page import OsintPage
from gui.pages.radar_page import RadarPage
from gui.pages.settings_page import SettingsPage
from gui.pages.terminal_page import TerminalPage
from gui.sidebar import Sidebar
from modules import common

NAV = [("Dashboard", DashboardPage), ("OSINT", OsintPage), ("Analysis", AnalysisPage),
       ("Case Manager", CasePage), ("Radar", RadarPage), ("Terminal", TerminalPage),
       ("Settings", SettingsPage)]


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        self.title("Kali Security Toolkit")
        self.geometry("1260x800")
        self.minsize(1020, 660)
        self.configure(fg_color=BG)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = Sidebar(self, [n for n, _ in NAV], self.show_page)
        self.sidebar.grid(row=0, column=0, sticky="ns")

        main = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(main, height=48, fg_color=SIDEBAR, corner_radius=0)
        top.grid(row=0, column=0, sticky="ew")
        label(top, "Kali Security Toolkit  |  Security Operations Dashboard", 13, TEXT, "bold").pack(side="left", padx=20)
        self.safe_label = ctk.CTkLabel(top, text="", font=font(12, "bold"))
        self.safe_label.pack(side="right", padx=20)

        container = ctk.CTkFrame(main, fg_color=BG, corner_radius=0)
        container.grid(row=1, column=0, sticky="nsew")
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)
        self.pages = {}
        for name, cls in NAV:
            page = cls(container, self)
            page.grid(row=0, column=0, sticky="nsew")
            self.pages[name] = page

        common.add_safe_listener(self._refresh_safe)
        self._refresh_safe(common.is_safe_mode())
        self.show_page("Dashboard")

    def show_page(self, name):
        self.pages[name].tkraise()
        self.pages[name].on_show()
        self.sidebar.set_active(name)

    def _refresh_safe(self, enabled):
        self.safe_label.configure(text=f"Safe Mode: {'ON' if enabled else 'OFF'}",
                                  text_color=OK if enabled else DANGER)
