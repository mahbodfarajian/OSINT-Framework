"""Network radar: live connections, LAN devices, passive packet capture with attack detection."""
import time
from collections import deque
from tkinter import messagebox
import tkinter as tk

import customtkinter as ctk

from gui import ACCENT, ACCENT_HOVER, CARD, DANGER, FONT, MUTED, OK, TEXT, WARN, Page, button, card, entry, label, make_tree
from modules import common, radar

VIEWS = {
    "Connections": (("Proto", "Local", "Remote", "Status", "PID", "Process"), (60, 190, 200, 110, 70, 150)),
    "Listening": (("Proto", "Address", "PID", "Process"), (70, 240, 80, 220)),
    "LAN Devices": (("IP", "MAC", "Interface", "State"), (160, 190, 120, 120)),
    "Live Packets": (("Time", "Source", "Destination", "Proto", "Ports", "Len", "Info"), (75, 140, 140, 60, 110, 60, 200)),
    "Alerts": (("Time", "Severity", "Type", "Source", "Detail", "Suggested block command"), (70, 80, 120, 120, 330, 260)),
    "Top Talkers": (("IP", "Packets", "Sent", "Received"), (200, 100, 120, 120)),
}
OS_VIEWS = {"Connections", "Listening", "LAN Devices"}


def os_rows(view, target):
    """OS-level views (read-only). With a target IP set, connections are filtered to it."""
    if view == "LAN Devices":
        return [(r, "") for r in radar.lan_neighbors()]
    conns = radar.connections()
    if view == "Connections":
        rows = [((c["proto"], c["local"], c["remote"], c["status"], c["pid"], c["proc"]), "") for c in conns
                if c["status"] == "ESTABLISHED"]
        return [r for r in rows if target in r[0][2] or target in r[0][1]] if target else rows
    return [((c["proto"], c["local"], c["pid"], c["proc"]), "") for c in conns if c["status"] in ("LISTEN", "NONE")]


class RadarPage(Page):
    title = "Network Radar"

    def __init__(self, master, app):
        super().__init__(master, app)
        self.view, self._busy, self._n = "Connections", False, 0
        self.rx, self.tx, self._prev = deque(maxlen=60), deque(maxlen=60), None
        r0, gw = radar.default_route()
        self.iface_var = ctk.StringVar(value=r0 if r0 in radar.interfaces() else radar.interfaces()[0])

        ctl = card(self)
        ctl.pack(fill="x", padx=24, pady=(0, 8))
        label(ctl, "Interface", 11, MUTED).pack(side="left", padx=(14, 6), pady=12)
        ctk.CTkOptionMenu(ctl, values=radar.interfaces(), variable=self.iface_var, width=130, fg_color=CARD,
                          button_color=ACCENT, command=lambda _: self.rx.clear() or self.tx.clear()).pack(side="left")
        label(ctl, "Target IP (optional)", 11, MUTED).pack(side="left", padx=(16, 6))
        self.target = entry(ctl, "monitor traffic of one IP", 190)
        self.target.pack(side="left")
        self.cap_btn = button(ctl, "Start Capture", self._toggle_capture, 130)
        self.cap_btn.pack(side="left", padx=12)
        button(ctl, "Copy Block Command", self._copy_block, 160, True).pack(side="left")
        self.cap_msg = label(ctl, "", 11, MUTED)
        self.cap_msg.pack(side="left", padx=12)

        self.seg = ctk.CTkSegmentedButton(self, values=list(VIEWS), command=self._switch, selected_color=ACCENT,
                                          unselected_color=CARD, fg_color=CARD, text_color=TEXT)
        self.seg.set(self.view)
        self.seg.pack(anchor="w", padx=24, pady=(0, 8))

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(0, weight=1)
        frame, self.tree = make_tree(body, VIEWS["Connections"][0], VIEWS["Connections"][1])
        frame.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        self.tree.tag_configure("HIGH", foreground=DANGER)
        self.tree.tag_configure("MED", foreground=WARN)

        side = card(body)
        side.grid(row=0, column=1, sticky="ns")
        self.info = {}
        for key in ("Interface", "Local IP", "Gateway", "Capture", "Packets", "Traffic", "Alerts", "Protocols"):
            row = ctk.CTkFrame(side, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=1)
            label(row, key, 11, MUTED).pack(side="left")
            self.info[key] = label(row, "-", 11, TEXT, "bold")
            self.info[key].pack(side="right")
        self.rate = label(side, "down 0 B/s   up 0 B/s", 11, TEXT)
        self.rate.pack(pady=(12, 2))
        self.spark = tk.Canvas(side, width=240, height=90, bg=CARD, highlightthickness=0)
        self.spark.pack(padx=12, pady=(0, 12))
        label(side, "Blue = download   Green = upload", 10, MUTED).pack(pady=(0, 12))
        self.gateway = gw
        radar.system_snapshot()
        self._tick()

    # ---- controls
    def _toggle_capture(self):
        sn = radar.SNIFFER
        if sn.running:
            sn.stop()
            self.cap_btn.configure(text="Start Capture")
            return
        if not radar.is_root():
            self.cap_msg.configure(text="Capture needs root: run with sudo", text_color=DANGER)
            return
        try:
            sn.start(self.iface_var.get(), self.target.get().strip() or None)
        except ImportError:
            self.cap_msg.configure(text="scapy is not installed", text_color=DANGER)
        except ValueError:
            self.cap_msg.configure(text="Invalid target IP", text_color=DANGER)
        except Exception as e:  # noqa: BLE001
            self.cap_msg.configure(text=f"Capture failed: {e}", text_color=DANGER)
        else:
            self.cap_btn.configure(text="Stop Capture")
            self.cap_msg.configure(text="Passive capture running", text_color=OK)

    def _copy_block(self):
        sel = self.tree.selection()
        if self.view != "Alerts" or not sel:
            messagebox.showinfo("Radar", "Open the Alerts view and select an alert first.")
            return
        cmd = self.tree.item(sel[0], "values")[5]
        if cmd:
            self.clipboard_clear()
            self.clipboard_append(cmd)
            self.cap_msg.configure(text="Copied - run it yourself to block (not auto-executed)", text_color=OK)

    def _switch(self, view):
        self.view = view
        cols, widths = VIEWS[view]
        self.tree.delete(*self.tree.get_children())
        self.tree.configure(columns=cols)
        for c, w in zip(cols, widths):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w")
        self._n = 0

    # ---- refresh loop (1 s)
    def _tick(self):
        if self.winfo_ismapped():
            iface = self.iface_var.get()
            now, (rx, tx) = time.time(), radar.io_counters(iface)
            if self._prev:
                dt = max(now - self._prev[0], 0.1)
                self.rx.append(max(rx - self._prev[1], 0) / dt)
                self.tx.append(max(tx - self._prev[2], 0) / dt)
            self._prev = (now, rx, tx)
            snap = radar.SNIFFER.snapshot()
            self._update_side(iface, snap)
            if self.view in OS_VIEWS:
                if self._n % 2 == 0 and not self._busy:
                    self._busy, view, target = True, self.view, self.target.get().strip()
                    common.run_async(self, lambda emit: os_rows(view, target), None, lambda res, err: self._os_done(view, res, err))
            else:
                self._fill(self._sniff_rows(snap))
            self._n += 1
        self.after(1000, self._tick)

    def _os_done(self, view, rows, err):
        self._busy = False
        if not err and view == self.view:
            self._fill(rows)

    def _sniff_rows(self, snap):
        if self.view == "Live Packets":
            return [(p, "") for p in snap["packets"]]
        if self.view == "Alerts":
            return [(a, a[1]) for a in snap["alerts"]]
        return [((ip, p, common.human_size(s), common.human_size(r)), "") for ip, p, s, r in snap["talkers"]]

    def _fill(self, rows):
        top = self.tree.yview()[0]
        sel = self.tree.item(self.tree.selection()[0], "values") if self.tree.selection() else None
        self.tree.delete(*self.tree.get_children())
        for values, tag in rows:
            iid = self.tree.insert("", "end", values=values, tags=(tag,) if tag else ())
            if sel and [str(v) for v in values] == list(sel):
                self.tree.selection_set(iid)
        self.tree.yview_moveto(top)

    def _update_side(self, iface, snap):
        sn = radar.SNIFFER
        i = self.info
        i["Interface"].configure(text=iface)
        i["Local IP"].configure(text=radar.iface_ipv4(iface))
        i["Gateway"].configure(text=self.gateway)
        i["Capture"].configure(text="running" if sn.running else "stopped", text_color=OK if sn.running else MUTED)
        i["Packets"].configure(text=str(snap["total"]))
        i["Traffic"].configure(text=common.human_size(snap["bytes"]))
        i["Alerts"].configure(text=str(len(snap["alerts"])), text_color=DANGER if snap["alerts"] else OK)
        i["Protocols"].configure(text=" ".join(f"{k}:{v}" for k, v in sorted(snap["proto"].items(), key=lambda x: -x[1])[:3]) or "-")
        if snap["error"]:
            self.cap_msg.configure(text=f"Capture error: {snap['error']}", text_color=DANGER)
        if self.rx:
            self.rate.configure(text=f"down {common.human_size(self.rx[-1])}/s   up {common.human_size(self.tx[-1])}/s")
        self._draw_spark()

    def _draw_spark(self):
        c, w, h = self.spark, 240, 90
        c.delete("all")
        top = max(max(self.rx, default=0), max(self.tx, default=0), 1)
        for k in (0.25, 0.5, 0.75):
            c.create_line(0, h * k, w, h * k, fill="#263340")
        for data, col in ((self.rx, ACCENT_HOVER), (self.tx, OK)):
            if len(data) > 1:
                pts = []
                for n, v in enumerate(data):
                    pts += [n * w / 59, h - 4 - v / top * (h - 10)]
                c.create_line(*pts, fill=col, width=2)
        c.create_text(4, 3, anchor="nw", text=f"peak {common.human_size(top)}/s", fill=MUTED, font=(FONT, 8))
