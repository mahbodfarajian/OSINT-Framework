"""Dashboard: system, network, security and case overview (no chart libraries)."""
import platform
import socket
import time

import customtkinter as ctk
import psutil

from gui import ACCENT, CARD, DANGER, MUTED, OK, TEXT, WARN, Page, card, label, make_tree, output_box, set_text
from modules import case_mgmt, common, radar


class StatCard(ctk.CTkFrame):
    def __init__(self, master, title, bar=False):
        super().__init__(master, fg_color=CARD, border_color="#263340", border_width=1, corner_radius=8)
        label(self, title, 10, MUTED).pack(anchor="w", padx=14, pady=(12, 0))
        self.value = label(self, "-", 24, TEXT, "bold")
        self.value.pack(anchor="w", padx=14)
        self.sub = label(self, " ", 10, MUTED)
        self.sub.pack(anchor="w", padx=14, pady=(0, 4 if bar else 12))
        self.bar = None
        if bar:
            self.bar = ctk.CTkProgressBar(self, progress_color=ACCENT, fg_color="#263340", height=7)
            self.bar.set(0)
            self.bar.pack(fill="x", padx=14, pady=(0, 12))

    def update_value(self, text, sub=" ", frac=None, color=TEXT):
        self.value.configure(text=text, text_color=color)
        self.sub.configure(text=sub)
        if self.bar is not None and frac is not None:
            self.bar.set(max(0, min(1, frac)))
            self.bar.configure(progress_color=DANGER if frac > 0.9 else WARN if frac > 0.75 else ACCENT)


def _gb(n):
    return f"{n / 1024 ** 3:.1f} GB"


class DashboardPage(Page):
    title = "Dashboard"

    def __init__(self, master, app):
        super().__init__(master, app)
        self._busy, self._prev = False, None
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=14, pady=(0, 10))
        grid = ctk.CTkFrame(scroll, fg_color="transparent")
        grid.pack(fill="x")
        names = [("osint", "OSINT REPORTS"), ("cases", "ACTIVE CASES"), ("alerts", "NETWORK ALERTS"), ("conns", "ESTABLISHED CONNECTIONS"),
                 ("cpu", "CPU"), ("ram", "MEMORY"), ("disk", "DISK  /"), ("swap", "SWAP")]
        self.cards = {}
        for i, (k, t) in enumerate(names):
            c = StatCard(grid, t, bar=i >= 4)
            c.grid(row=i // 4, column=i % 4, sticky="nsew", padx=6, pady=6)
            self.cards[k] = c
        for c in range(4):
            grid.grid_columnconfigure(c, weight=1, uniform="c")

        mid = ctk.CTkFrame(scroll, fg_color="transparent")
        mid.pack(fill="x", pady=4)
        mid.grid_columnconfigure((0, 1), weight=1, uniform="m")
        sysbox = card(mid)
        sysbox.grid(row=0, column=0, sticky="nsew", padx=6)
        label(sysbox, "SYSTEM & NETWORK", 10, MUTED).pack(anchor="w", padx=14, pady=(12, 4))
        self.kv = {}
        for key in ("Host", "OS", "Kernel", "Uptime", "CPU", "Load average", "Processes", "Interface", "Local IP",
                    "Gateway", "Download", "Upload", "Total received", "Total sent", "Safe mode", "API keys set"):
            row = ctk.CTkFrame(sysbox, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=1)
            label(row, key, 11, MUTED).pack(side="left")
            self.kv[key] = label(row, "-", 11, TEXT, "bold")
            self.kv[key].pack(side="right")
        ctk.CTkFrame(sysbox, height=8, fg_color="transparent").pack()

        right = ctk.CTkFrame(mid, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=6)
        label(right, "TOP PROCESSES (CPU)", 10, MUTED).pack(anchor="w", pady=(2, 4))
        frame, self.proc_tree = make_tree(right, ("PID", "Process", "CPU %", "MEM %"), (70, 200, 70, 70), height=8)
        frame.pack(fill="x")
        alert = card(right)
        alert.pack(fill="x", pady=(10, 0))
        label(alert, "LAST RADAR ALERT", 10, MUTED).pack(anchor="w", padx=14, pady=(10, 0))
        self.alert_text = label(alert, "None", 12, WARN, "bold")
        self.alert_text.pack(anchor="w", padx=14, pady=(0, 6))
        label(alert, "LAST OSINT RUN", 10, MUTED).pack(anchor="w", padx=14)
        self.osint_text = label(alert, "None", 12, TEXT, "bold")
        self.osint_text.pack(anchor="w", padx=14, pady=(0, 6))
        label(alert, "CASES", 10, MUTED).pack(anchor="w", padx=14)
        self.case_text = label(alert, "-", 12, TEXT, "bold")
        self.case_text.pack(anchor="w", padx=14, pady=(0, 10))

        label(scroll, "Recent activity (logs/toolkit.log)", 11, MUTED).pack(anchor="w", padx=8, pady=(10, 4))
        self.log_box = output_box(scroll)
        self.log_box.configure(height=170)
        self.log_box.pack(fill="x", padx=6, pady=(0, 10))
        self.kv["Host"].configure(text=socket.gethostname())
        self.kv["OS"].configure(text=platform.freedesktop_os_release().get("PRETTY_NAME", platform.system())
                                if hasattr(platform, "freedesktop_os_release") else platform.system())
        self.kv["Kernel"].configure(text=platform.release())
        self.kv["CPU"].configure(text=f"{psutil.cpu_count(logical=False) or '?'}C / {psutil.cpu_count()}T")
        psutil.cpu_percent(None)
        self._tick()

    def on_show(self):
        self._refresh()

    def _tick(self):
        if self.winfo_ismapped():
            self._refresh()
        self.after(2000, self._tick)

    def _refresh(self):
        if self._busy:
            return
        self._busy = True
        iface = radar.default_route()[0] or radar.interfaces()[0]

        def work(emit):  # slow psutil calls run off the GUI thread
            procs = sorted(({"pid": p.info["pid"], "name": p.info["name"] or "?", "cpu": p.info["cpu_percent"] or 0,
                             "mem": p.info["memory_percent"] or 0}
                            for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"])),
                           key=lambda r: r["cpu"], reverse=True)
            return {"cpu": psutil.cpu_percent(None), "vm": psutil.virtual_memory(), "du": psutil.disk_usage("/"),
                    "sw": psutil.swap_memory(), "load": psutil.getloadavg(), "procs": procs,
                    "conns": sum(1 for c in radar.connections() if c["status"] == "ESTABLISHED"),
                    "io": radar.io_counters(iface), "iface": iface, "gw": radar.default_route()[1]}

        common.run_async(self, work, None, self._apply)

    def _apply(self, d, err):
        self._busy = False
        if err:
            return
        cases = case_mgmt.list_cases()
        active = [c for c in cases if c["status"] != "Closed"]
        alerts = common.get_stat("network_alerts", 0)
        c = self.cards
        c["osint"].update_value(str(common.get_stat("osint_reports", 0)), "reports generated")
        c["cases"].update_value(str(len(active)), f"{len(cases)} total, {sum(1 for x in active if x['priority'] in ('High', 'Critical'))} high priority")
        c["alerts"].update_value(str(alerts), "since first capture", color=DANGER if alerts else OK)
        c["conns"].update_value(str(d["conns"]), "TCP/UDP sessions")
        c["cpu"].update_value(f"{d['cpu']:.0f}%", f"load {d['load'][0]:.2f}", d["cpu"] / 100)
        c["ram"].update_value(f"{d['vm'].percent:.0f}%", f"{_gb(d['vm'].used)} / {_gb(d['vm'].total)}", d["vm"].percent / 100)
        c["disk"].update_value(f"{d['du'].percent:.0f}%", f"{_gb(d['du'].used)} / {_gb(d['du'].total)}", d["du"].percent / 100)
        c["swap"].update_value(f"{d['sw'].percent:.0f}%", f"{_gb(d['sw'].used)} / {_gb(d['sw'].total)}", d["sw"].percent / 100)

        now, (rx, tx) = time.time(), d["io"]
        down = up = 0
        if self._prev:
            dt = max(now - self._prev[0], 0.1)
            down, up = max(rx - self._prev[1], 0) / dt, max(tx - self._prev[2], 0) / dt
        self._prev = (now, rx, tx)
        up_s = int(now - psutil.boot_time())
        cfg = common.load_config()
        kv = self.kv
        kv["Uptime"].configure(text=f"{up_s // 86400}d {up_s % 86400 // 3600}h {up_s % 3600 // 60}m")
        kv["Load average"].configure(text=" / ".join(f"{x:.2f}" for x in d["load"]))
        kv["Processes"].configure(text=str(len(d["procs"])))
        kv["Interface"].configure(text=d["iface"])
        kv["Local IP"].configure(text=radar.iface_ipv4(d["iface"]))
        kv["Gateway"].configure(text=d["gw"])
        kv["Download"].configure(text=f"{common.human_size(down)}/s")
        kv["Upload"].configure(text=f"{common.human_size(up)}/s")
        kv["Total received"].configure(text=common.human_size(rx))
        kv["Total sent"].configure(text=common.human_size(tx))
        kv["Safe mode"].configure(text="ON" if common.is_safe_mode() else "OFF", text_color=OK if common.is_safe_mode() else DANGER)
        kv["API keys set"].configure(text=f"{sum(1 for k, _, _ in common.API_KEYS if cfg.get(k))} / {len(common.API_KEYS)}")

        self.proc_tree.delete(*self.proc_tree.get_children())
        for p in d["procs"][:8]:
            self.proc_tree.insert("", "end", values=(p["pid"], p["name"], f"{p['cpu']:.1f}", f"{p['mem']:.1f}"))
        self.alert_text.configure(text=common.get_stat("last_radar_alert", "None"))
        self.osint_text.configure(text=common.get_stat("last_osint", "None"))
        self.case_text.configure(text=" | ".join(f"{s}: {sum(1 for x in cases if x['status'] == s)}" for s in case_mgmt.STATUSES))
        try:
            set_text(self.log_box, "\n".join(common.LOG_PATH.read_text(encoding="utf-8").splitlines()[-12:]))
        except OSError:
            pass
