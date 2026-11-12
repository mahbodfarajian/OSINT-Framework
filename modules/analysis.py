"""Static analysis backend. Files are only READ as bytes - samples are never executed."""
import csv
import json
import math
import re
import struct
from collections import Counter
from pathlib import Path

from modules import common
from modules.common import log

MAX_READ = 64 * 1024 * 1024  # cap memory use for hashing-independent parsing


def hashes(path) -> dict:
    import hashlib
    hs = {n: hashlib.new(n) for n in ("md5", "sha1", "sha256")}
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            for h in hs.values():
                h.update(block)
    return {n.upper(): h.hexdigest() for n, h in hs.items()}


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def ascii_chart(items, width=40) -> str:
    """Horizontal ASCII bar chart for (label, value) pairs."""
    items = list(items)
    if not items:
        return "(no data)"
    top = max(v for _, v in items) or 1
    lw = max(len(str(k)) for k, _ in items)
    return "\n".join(f"{str(k):<{lw}} | {'#' * max(1, int(v / top * width)) if v else ''} {v:g}" for k, v in items)


def block_entropy(path, blocks=24) -> list:
    size = Path(path).stat().st_size
    if size == 0:
        return []
    step, bs = max(size // blocks, 1), min(max(size // blocks, 1), 1 << 20)
    out = []
    with open(path, "rb") as f:
        for i in range(blocks):
            f.seek(i * step)
            chunk = f.read(bs)
            if chunk:
                out.append((f"{i * step:#010x}", round(shannon(chunk), 2)))
    return out


def extract_strings(data: bytes, min_len=6, limit=40) -> tuple:
    found = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    text = [s.decode() for s in found]
    interesting = [s for s in text if re.search(r"https?://|\b\d{1,3}(\.\d{1,3}){3}\b|passw|token|/bin/|\.dll|cmd\.exe", s, re.I)]
    return len(text), text[:limit], interesting[:25]


def _u16(d, o): return struct.unpack_from("<H", d, o)[0]
def _u32(d, o): return struct.unpack_from("<I", d, o)[0]


PE_MACHINES = {0x14c: "x86", 0x8664: "x86-64", 0x1c0: "ARM", 0xaa64: "ARM64"}
ELF_TYPES = {1: "relocatable", 2: "executable", 3: "shared/PIE", 4: "core"}
ELF_MACHINES = {3: "x86", 0x3e: "x86-64", 40: "ARM", 0xb7: "AArch64", 8: "MIPS", 0xf3: "RISC-V"}


def parse_pe(d: bytes):
    if d[:2] != b"MZ" or len(d) < 0x40:
        return None
    pe = _u32(d, 0x3C)
    if d[pe:pe + 4] != b"PE\0\0":
        return None
    machine, nsec, ts, _, _, optsz, chars = struct.unpack_from("<HHIIIHH", d, pe + 4)
    opt = pe + 24
    magic = _u16(d, opt)
    info = {"Format": "PE32+" if magic == 0x20B else "PE32", "Machine": PE_MACHINES.get(machine, hex(machine)),
            "Type": "DLL" if chars & 0x2000 else "EXE", "Compile timestamp (epoch)": ts,
            "Entry point RVA": hex(_u32(d, opt + 16)), "Subsystem": _u16(d, opt + 68), "Sections": []}
    flags = []
    for i in range(nsec):
        o = opt + optsz + i * 40
        name = d[o:o + 8].rstrip(b"\0").decode(errors="replace")
        vsize, _, rsize, rptr = struct.unpack_from("<IIII", d, o + 8)
        sc = _u32(d, o + 36)
        ent = shannon(d[rptr:rptr + rsize])
        info["Sections"].append(f"{name:<8} vsize={vsize:<9} raw={rsize:<9} entropy={ent:.2f}")
        if ent > 7.0:
            flags.append(f"{name}: high entropy (packed/encrypted?)")
        if sc & 0x20000000 and sc & 0x80000000:
            flags.append(f"{name}: writable AND executable")
    info["Flags"] = flags or ["none"]
    return info


def parse_elf(d: bytes):
    if d[:4] != b"\x7fELF" or len(d) < 64:
        return None
    is64, e = d[4] == 2, ("<" if d[5] == 1 else ">")
    if is64:
        t, m, _, entry, phoff, shoff = struct.unpack_from(e + "HHIQQQ", d, 16)
        phnum, shnum = struct.unpack_from(e + "H", d, 56)[0], struct.unpack_from(e + "H", d, 60)[0]
    else:
        t, m, _, entry, phoff, shoff = struct.unpack_from(e + "HHIIII", d, 16)
        phnum, shnum = struct.unpack_from(e + "H", d, 44)[0], struct.unpack_from(e + "H", d, 48)[0]
    return {"Format": f"ELF{64 if is64 else 32}", "Endianness": "little" if e == "<" else "big",
            "Type": ELF_TYPES.get(t, t), "Machine": ELF_MACHINES.get(m, hex(m)), "Entry point": hex(entry),
            "Program headers": phnum, "Section headers": shnum}


def _kv(d):
    return "\n".join(f"{k}: " + (("\n    " + "\n    ".join(v)) if isinstance(v, list) else str(v)) for k, v in d.items())


def analyze_binary(path, emit=None) -> str:
    p = Path(path)
    size = p.stat().st_size
    with open(p, "rb") as f:
        data = f.read(MAX_READ)
    out = ["[Static analysis only - the sample is never executed]", f"File: {p.name}", f"Size: {common.human_size(size)}"]
    try:
        import magic
        out.append(f"Type (libmagic): {magic.from_file(str(p))}")
    except Exception:  # noqa: BLE001
        out.append("Type (libmagic): unavailable")
    out += ["", "--- Hashes ---", _kv(hashes(p))]
    ent = shannon(data)
    out += ["", f"--- Entropy: {ent:.3f} / 8.0 " + ("(likely packed/encrypted)" if ent > 7.2 else "") + "---",
            ascii_chart(block_entropy(p), 32)]
    meta = parse_pe(data) or parse_elf(data)
    out += ["", "--- Executable metadata ---", _kv(meta) if meta else "Not a PE or ELF file"]
    total, first, hot = extract_strings(data)
    out += ["", f"--- Strings ({total} total, first {len(first)}) ---"] + first
    out += ["", "--- Interesting strings ---"] + (hot or ["none"])
    return "\n".join(out)


def analyze_pcap(path, emit=None, max_packets=200_000) -> str:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP
    from scapy.utils import PcapReader

    proto, src, dst, ports, dns_q = Counter(), Counter(), Counter(), Counter(), Counter()
    count = total_bytes = 0
    t0 = t1 = None
    with PcapReader(str(path)) as rd:
        for pkt in rd:
            count += 1
            total_bytes += len(pkt)
            ts = float(pkt.time)
            t0, t1 = (ts if t0 is None else t0), ts
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip:
                src[ip.src] += 1
                dst[ip.dst] += 1
            if pkt.haslayer(TCP):
                proto["TCP"] += 1
                ports[f"tcp/{pkt[TCP].dport}"] += 1
            elif pkt.haslayer(UDP):
                proto["UDP"] += 1
                ports[f"udp/{pkt[UDP].dport}"] += 1
            elif pkt.haslayer(ICMP):
                proto["ICMP"] += 1
            elif pkt.haslayer(ARP):
                proto["ARP"] += 1
            else:
                proto["Other"] += 1
            if pkt.haslayer(DNSQR) and pkt.haslayer(DNS):
                dns_q[pkt[DNSQR].qname.decode(errors="replace")] += 1
            if emit and count % 5000 == 0:
                emit("status", f"{count} packets...")
            if count >= max_packets:
                break
    out = [f"File: {Path(path).name}", f"Packets: {count}" + (" (capped)" if count >= max_packets else ""),
           f"Bytes: {common.human_size(total_bytes)}", f"Duration: {((t1 or 0) - (t0 or 0)):.2f} s", "",
           "--- Protocols ---", ascii_chart(proto.most_common())]
    for title, ctr in (("Top sources", src), ("Top destinations", dst), ("Top destination ports", ports), ("DNS queries", dns_q)):
        out += ["", f"--- {title} ---", ascii_chart(ctr.most_common(10)) if ctr else "(none)"]
    return "\n".join(out)


def analyze_data(path, emit=None) -> str:
    p = Path(path)
    if p.suffix.lower() == ".json":
        obj = json.loads(p.read_text(encoding="utf-8", errors="replace"))

        def depth(o):
            return 1 + max((depth(v) for v in (o.values() if isinstance(o, dict) else o)), default=0) \
                if isinstance(o, (dict, list)) else 0

        out = [f"File: {p.name}", f"Top-level type: {type(obj).__name__}", f"Nesting depth: {depth(obj)}"]
        if isinstance(obj, dict):
            out += [f"Keys ({len(obj)}):"] + [f"  - {k}: {type(v).__name__}" for k, v in list(obj.items())[:40]]
        elif isinstance(obj, list):
            out.append(f"Items: {len(obj)}")
            if obj and isinstance(obj[0], dict):
                out += ["Fields of first item:"] + [f"  - {k}" for k in obj[0]]
        return "\n".join(out)
    with open(p, newline="", encoding="utf-8", errors="replace") as f:
        rows = list(csv.DictReader(f))[:100_000]
    if not rows:
        return "Empty CSV"
    out = [f"File: {p.name}", f"Rows: {len(rows)}", f"Columns: {len(rows[0])}", ""]
    for col in rows[0]:
        vals = [r.get(col, "") for r in rows]
        filled = [v for v in vals if v not in ("", None)]
        nums = []
        for v in filled:
            try:
                nums.append(float(v))
            except ValueError:
                break
        line = f"{col}: filled={len(filled)} unique={len(set(filled))}"
        if nums and len(nums) == len(filled):
            line += f" min={min(nums):g} max={max(nums):g} mean={sum(nums) / len(nums):.3g}"
        else:
            line += " top=" + ", ".join(f"{k}({c})" for k, c in Counter(filled).most_common(3))
        out.append(line)
    return "\n".join(out)


def analyze(kind: str, path: str, emit=None) -> str:
    log.info("Analysis (%s): %s", kind, path)
    return {"pcap": analyze_pcap, "binary": analyze_binary, "data": analyze_data}[kind](path, emit)
