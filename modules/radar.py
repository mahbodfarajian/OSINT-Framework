"""Read-only system radar: processes, resources, connections, LAN neighbors, kernel log, file integrity."""
import ipaddress
import json
import os
import socket
import struct
import subprocess
import threading
import time
from collections import Counter, defaultdict, deque
from datetime import datetime

import psutil

from modules import common

BASELINE_PATH = common.DATA_DIR / "baseline.json"
WATCH_FILES = ["/etc/passwd", "/etc/group", "/etc/hosts", "/etc/resolv.conf", "/etc/ssh/sshd_config",
               "/etc/sudoers", "/etc/crontab", "/etc/shadow"]


def _watchlist() -> set:
    try:
        lines = (common.DATA_DIR / "suspicious_processes.txt").read_text().splitlines()
        return {l.strip().lower() for l in lines if l.strip() and not l.startswith("#")}
    except OSError:
        return set()


def system_snapshot() -> dict:
    du = psutil.disk_usage("/")
    return {"cpu": psutil.cpu_percent(None), "ram": psutil.virtual_memory().percent, "disk": du.percent}


def process_inventory() -> list:
    watch, out = _watchlist(), []
    for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
        i = p.info
        name = i["name"] or "?"
        out.append({"pid": i["pid"], "name": name, "user": i["username"] or "?", "cpu": i["cpu_percent"] or 0.0,
                    "mem": i["memory_percent"] or 0.0, "flag": "WATCHLIST" if name.lower() in watch else ""})
    return sorted(out, key=lambda r: r["cpu"], reverse=True)[:400]


def process_alerts(procs) -> list:
    return [f"Watchlist process '{p['name']}' (PID {p['pid']}, user {p['user']})" for p in procs if p["flag"]]


def connections() -> list:
    names, out = {}, []
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return out
    for c in conns:
        proc = ""
        if c.pid:
            if c.pid not in names:
                try:
                    names[c.pid] = psutil.Process(c.pid).name()
                except psutil.Error:
                    names[c.pid] = "?"
            proc = names[c.pid]
        fmt = lambda a: f"{a.ip}:{a.port}" if a else "-"
        out.append({"proto": "TCP" if c.type == 1 else "UDP", "local": fmt(c.laddr), "remote": fmt(c.raddr),
                    "status": c.status, "pid": c.pid or "-", "proc": proc})
    return out


def lan_neighbors() -> list:
    """Passive: reads the kernel ARP cache; sends no packets."""
    rows = []
    try:
        for line in open("/proc/net/arp").read().splitlines()[1:]:
            ip, _, flags, mac, _, dev = line.split()[:6]
            rows.append((ip, mac, dev, "complete" if flags != "0x0" else "incomplete"))
    except OSError:
        pass
    return rows


def kernel_log(lines=60) -> list:
    for cmd in (["dmesg", "--level=err,warn"], ["journalctl", "-k", "-p", "warning", "-n", str(lines), "--no-pager"]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=8, shell=False)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip().splitlines()[-lines:]
        except (OSError, subprocess.TimeoutExpired):
            continue
    return ["Kernel log unavailable (insufficient privileges?). Try running with sudo."]


def _fingerprint(path) -> dict:
    import os
    st = os.stat(path)
    return {"sha256": common.sha256_file(path), "size": st.st_size, "mtime": int(st.st_mtime)}


def create_baseline(paths=None) -> int:
    base = {}
    for p in paths or WATCH_FILES:
        try:
            base[p] = _fingerprint(p)
        except OSError:
            continue  # missing or unreadable (e.g. /etc/shadow without root)
    BASELINE_PATH.write_text(json.dumps({"created": datetime.now().isoformat(timespec="seconds"), "files": base}, indent=2))
    common.log.info("Integrity baseline created (%d files)", len(base))
    return len(base)


def check_baseline() -> list:
    try:
        base = json.loads(BASELINE_PATH.read_text())["files"]
    except (OSError, json.JSONDecodeError, KeyError):
        return [("-", "NO BASELINE", "Click 'Create Baseline' first")]
    rows = []
    for p, old in base.items():
        try:
            new = _fingerprint(p)
        except FileNotFoundError:
            rows.append((p, "MISSING", ""))
            continue
        except OSError:
            rows.append((p, "UNREADABLE", ""))
            continue
        rows.append((p, "OK" if new["sha256"] == old["sha256"] else "MODIFIED",
                     "" if new["sha256"] == old["sha256"] else f"{old['sha256'][:12]} -> {new['sha256'][:12]}"))
    return rows


# ================================================================ network radar (passive)
def interfaces() -> list:
    return [n for n in psutil.net_if_addrs() if n != "lo"] or ["lo"]


def iface_ipv4(iface):
    for a in psutil.net_if_addrs().get(iface, []):
        if a.family == socket.AF_INET:
            return a.address
    return "-"


def default_route() -> tuple:
    """(interface, gateway) from /proc/net/route."""
    try:
        for line in open("/proc/net/route").read().splitlines()[1:]:
            f = line.split()
            if f[1] == "00000000":
                return f[0], socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
    except OSError:
        pass
    return None, "-"


def io_counters(iface) -> tuple:
    c = psutil.net_io_counters(pernic=True).get(iface)
    return (c.bytes_recv, c.bytes_sent) if c else (0, 0)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def block_command(ip) -> str:
    """Suggested (NOT executed) firewall rule. The IP is validated before it is placed in a command."""
    return f"sudo iptables -I INPUT -s {ipaddress.ip_address(ip)} -j DROP"


class Sniffer:
    """Passive packet capture with simple IDS-style detectors. Sends no packets; needs root."""
    WINDOW = 10        # seconds for scan / ICMP detection
    COOLDOWN = 60      # seconds before the same alert repeats

    def __init__(self):
        self.lock, self.sn, self.running, self.target = threading.Lock(), None, False, None
        self.reset()

    def reset(self):
        self.packets, self.alerts = deque(maxlen=400), []
        self.talkers = defaultdict(lambda: [0, 0, 0])   # ip -> [packets, bytes sent, bytes received]
        self.proto, self.total, self.bytes = Counter(), 0, 0
        self._scan, self._syn, self._icmp = defaultdict(deque), defaultdict(deque), defaultdict(deque)
        self._arp, self._cool = {}, {}

    def start(self, iface, target=None):
        from scapy.all import AsyncSniffer  # lazy: scapy is optional until capture starts
        if target:
            target = str(ipaddress.ip_address(target))
        self.reset()
        self.target = target
        self.sn = AsyncSniffer(iface=iface, prn=self._on, store=False, filter=f"host {target}" if target else None)
        self.sn.start()
        self.running = True
        common.log.info("Capture started on %s (target=%s)", iface, target or "all")

    def stop(self):
        try:
            if self.sn:
                self.sn.stop()
        except Exception:  # noqa: BLE001 - sniffer may already have died
            pass
        self.running = False
        common.log.info("Capture stopped")

    @staticmethod
    def _prune(dq, now, w):
        while dq and now - dq[0][0] > w:
            dq.popleft()

    def _alert(self, kind, src, detail, sev):
        now = time.time()
        if now - self._cool.get((kind, src), 0) < self.COOLDOWN:
            return
        self._cool[(kind, src)] = now
        try:
            cmd = block_command(src)
        except ValueError:
            cmd = ""
        self.alerts.append((time.strftime("%H:%M:%S"), sev, kind, src, detail, cmd))
        del self.alerts[:-200]
        common.log.warning("Network alert [%s] %s from %s: %s", sev, kind, src, detail)
        common.bump_stat("network_alerts")
        common.set_stat("last_radar_alert", f"{time.strftime('%H:%M:%S')}  {kind} from {src}")

    def _on(self, pkt):
        from scapy.layers.dns import DNSQR
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.l2 import ARP
        now, n, ts = time.time(), len(pkt), time.strftime("%H:%M:%S")
        with self.lock:
            self.total += 1
            self.bytes += n
            if pkt.haslayer(ARP):
                a = pkt[ARP]
                self.proto["ARP"] += 1
                self.packets.append((ts, a.psrc, a.pdst, "ARP", "", n, "who-has" if a.op == 1 else "is-at"))
                old = self._arp.get(a.psrc)
                if old and old != a.hwsrc:
                    self._alert("ARP spoofing", a.psrc, f"{a.psrc} changed MAC {old} -> {a.hwsrc}", "HIGH")
                self._arp[a.psrc] = a.hwsrc
                return
            if not pkt.haslayer(IP):
                self.proto["Other"] += 1
                return
            ip = pkt[IP]
            src, dst, proto, ports, info = ip.src, ip.dst, "IP", "", ""
            if pkt.haslayer(TCP):
                t = pkt[TCP]
                proto, ports, flags = "TCP", f"{t.sport}->{t.dport}", int(t.flags)
                info = str(t.flags)
                if flags & 0x02 and not flags & 0x10:   # bare SYN
                    d = self._scan[src]
                    d.append((now, dst, t.dport))
                    self._prune(d, now, self.WINDOW)
                    if len({(x[1], x[2]) for x in d}) >= 20:
                        self._alert("Port scan", src, f"{src} sent SYNs to {len({(x[1], x[2]) for x in d})} ports in {self.WINDOW}s", "HIGH")
                    s = self._syn[dst]
                    s.append((now, src))
                    self._prune(s, now, 5)
                    if len(s) >= 150:
                        self._alert("SYN flood", src, f"{len(s)} SYNs to {dst} in 5s from {len({x[1] for x in s})} source(s)", "HIGH")
            elif pkt.haslayer(UDP):
                u = pkt[UDP]
                proto, ports = "UDP", f"{u.sport}->{u.dport}"
                if pkt.haslayer(DNSQR):
                    q = pkt[DNSQR].qname.decode(errors="replace")
                    info = q
                    if len(q) > 60:
                        self._alert("Suspicious DNS", src, f"Very long query ({len(q)} chars) - possible tunneling: {q[:50]}...", "MED")
            elif pkt.haslayer(ICMP):
                proto = "ICMP"
                d = self._icmp[src]
                d.append((now,))
                self._prune(d, now, self.WINDOW)
                if len(d) >= 100:
                    self._alert("ICMP flood", src, f"{len(d)} ICMP packets in {self.WINDOW}s", "MED")
            self.proto[proto] += 1
            self.talkers[src][0] += 1
            self.talkers[src][1] += n
            self.talkers[dst][0] += 1
            self.talkers[dst][2] += n
            self.packets.append((ts, src, dst, proto, ports, n, info))

    def snapshot(self) -> dict:
        with self.lock:
            top = sorted(self.talkers.items(), key=lambda kv: kv[1][1] + kv[1][2], reverse=True)[:40]
            return {"total": self.total, "bytes": self.bytes, "proto": dict(self.proto),
                    "packets": list(self.packets)[::-1][:200], "alerts": list(self.alerts)[::-1],
                    "talkers": [(ip, v[0], v[1], v[2]) for ip, v in top],
                    "error": getattr(self.sn, "exception", None) if self.sn else None}


SNIFFER = Sniffer()
