"""Case management: evidence with SHA-256, append-only hash-chained custody log, notes, timeline, reports."""
import getpass
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from modules import common
from modules.common import log

CASES_DIR = common.DATA_DIR / "cases"
GENESIS = "0" * 64
STATUSES = ["Open", "In Progress", "On Hold", "Closed"]
PRIORITIES = ["Low", "Medium", "High", "Critical"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def case_dir(cid) -> Path:
    d = CASES_DIR / cid
    if not d.is_dir():
        raise FileNotFoundError(f"Unknown case {cid}")
    return d


def _meta(cid) -> dict:
    return json.loads((case_dir(cid) / "case.json").read_text(encoding="utf-8"))


def _save_meta(cid, meta):
    (case_dir(cid) / "case.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")


# ---------------------------------------------------------------- custody chain
def _custody_append(cid, action, details):
    """Append one entry; each entry's hash covers its content AND the previous hash."""
    entries = read_custody(cid)
    entry = {"seq": len(entries) + 1, "time": _now(), "actor": getpass.getuser(), "action": action,
             "details": details, "prev_hash": entries[-1]["hash"] if entries else GENESIS}
    entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
    with open(case_dir(cid) / "custody.log", "a", encoding="utf-8") as f:  # append-only
        f.write(json.dumps(entry) + "\n")
    return entry


def read_custody(cid) -> list:
    p = case_dir(cid) / "custody.log"
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()] if p.exists() else []


def verify_custody(cid) -> tuple:
    prev = GENESIS
    for e in read_custody(cid):
        body = {k: v for k, v in e.items() if k != "hash"}
        if e["prev_hash"] != prev or hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != e["hash"]:
            return False, f"Chain BROKEN at entry #{e['seq']}"
        prev = e["hash"]
    return True, "Chain intact"


# ---------------------------------------------------------------- cases
def list_cases() -> list:
    out = []
    if CASES_DIR.is_dir():
        for d in sorted(CASES_DIR.iterdir()):
            try:
                m = json.loads((d / "case.json").read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            m.setdefault("priority", "Medium")
            m["evidence"] = len(list((d / "evidence").iterdir())) if (d / "evidence").is_dir() else 0
            out.append(m)
    return out


def create_case(title: str, description: str = "", priority: str = "Medium") -> dict:
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    nums = [int(c["id"][5:]) for c in list_cases() if c["id"][5:].isdigit()]
    cid = f"CASE-{max(nums, default=0) + 1:04d}"  # max+1 so deleted IDs are never reused
    d = CASES_DIR / cid
    (d / "evidence").mkdir(parents=True)
    _save_meta_new = {"id": cid, "title": title, "status": "Open", "priority": priority, "created": _now(),
                      "analyst": getpass.getuser()}
    (d / "case.json").write_text(json.dumps(_save_meta_new, indent=2), encoding="utf-8")
    (d / "description.txt").write_text(description, encoding="utf-8")
    _custody_append(cid, "CASE_CREATED", title)
    add_timeline(cid, f"Case created: {title}")
    log.info("Case created: %s", cid)
    return _save_meta_new


def _change(cid, field, value, label):
    m = _meta(cid)
    old, m[field] = m.get(field), value
    _save_meta(cid, m)
    _custody_append(cid, f"{label}_CHANGED", f"{old} -> {value}")
    add_timeline(cid, f"{label.title()}: {old} -> {value}")


def set_status(cid, status):
    if status in STATUSES:
        _change(cid, "status", status, "STATUS")


def set_priority(cid, priority):
    if priority in PRIORITIES:
        _change(cid, "priority", priority, "PRIORITY")


def rename_case(cid, title):
    _change(cid, "title", title, "TITLE")


def delete_case(cid):
    """Permanently remove a case folder (the deletion itself is recorded in logs/toolkit.log)."""
    shutil.rmtree(case_dir(cid))
    log.warning("Case DELETED: %s", cid)


def read_description(cid) -> str:
    return (case_dir(cid) / "description.txt").read_text(encoding="utf-8")


def read_notes(cid) -> str:
    p = case_dir(cid) / "notes.txt"
    return p.read_text(encoding="utf-8") if p.exists() else ""


# ---------------------------------------------------------------- evidence
def _evidence_path(cid, name) -> Path:
    base = (case_dir(cid) / "evidence").resolve()
    p = (base / name).resolve()
    if p.parent != base:
        raise ValueError("Invalid evidence name")
    return p


def add_evidence(cid, src, note="") -> dict:
    """Copy a file into the case, verify the copy by SHA-256 and log both hashes."""
    src = Path(src)
    dest = case_dir(cid) / "evidence" / src.name
    n = 1
    while dest.exists():  # never overwrite existing evidence
        dest = dest.with_name(f"{src.stem}_{n}{src.suffix}")
        n += 1
    h_src = common.sha256_file(src)
    shutil.copy2(src, dest)
    h_dst = common.sha256_file(dest)
    if h_src != h_dst:
        dest.unlink()
        raise IOError("Hash mismatch after copy; evidence discarded")
    _custody_append(cid, "EVIDENCE_ADDED", f"{dest.name} | sha256={h_dst} | source={src} | note={note}")
    add_timeline(cid, f"Evidence added: {dest.name}")
    log.info("Evidence %s added to %s (%s)", dest.name, cid, h_dst)
    return {"name": dest.name, "sha256": h_dst}


def list_evidence(cid) -> list:
    logged = {}
    for e in read_custody(cid):
        if e["action"] == "EVIDENCE_ADDED":
            parts = e["details"].split(" | ")
            logged[parts[0]] = (parts[1].removeprefix("sha256="), e["time"])
    out = []
    for f in sorted((case_dir(cid) / "evidence").iterdir()):
        sha, added = logged.get(f.name, ("(not logged)", "-"))
        out.append({"name": f.name, "size": f.stat().st_size, "sha256": sha, "added": added})
    return out


def verify_evidence(cid, name) -> tuple:
    p = _evidence_path(cid, name)
    expected = next((e["sha256"] for e in list_evidence(cid) if e["name"] == name), None)
    actual = common.sha256_file(p)
    ok = expected == actual
    _custody_append(cid, "EVIDENCE_VERIFIED", f"{name} | {'OK' if ok else 'MISMATCH'}")
    return ok, f"{'Hash matches' if ok else 'HASH MISMATCH'}\nlogged: {expected}\nactual: {actual}"


def remove_evidence(cid, name):
    p = _evidence_path(cid, name)
    sha = common.sha256_file(p)
    _custody_append(cid, "EVIDENCE_REMOVED", f"{name} | sha256={sha}")  # logged BEFORE deletion
    p.unlink()
    add_timeline(cid, f"Evidence removed: {name}")
    log.warning("Evidence %s removed from %s", name, cid)


# ---------------------------------------------------------------- notes / timeline / report
def add_timeline(cid, event):
    with open(case_dir(cid) / "timeline.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"time": _now(), "event": event}) + "\n")


def read_timeline(cid) -> list:
    p = case_dir(cid) / "timeline.jsonl"
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()] if p.exists() else []


def add_note(cid, text):
    with open(case_dir(cid) / "notes.txt", "a", encoding="utf-8") as f:
        f.write(f"[{_now()}] {text}\n")
    _custody_append(cid, "NOTE_ADDED", f"sha256={hashlib.sha256(text.encode()).hexdigest()[:16]}")
    add_timeline(cid, "Note added")


def export_report(cid):
    d, m = case_dir(cid), _meta(cid)
    ok, msg = verify_custody(cid)
    lines = [f"# {m['id']} - {m['title']}",
             f"Status: {m['status']} | Priority: {m.get('priority', 'Medium')} | Analyst: {m['analyst']} | Created: {m['created']}",
             "", "## Description", read_description(cid) or "(none)", "", "## Evidence"]
    lines += [f"- {e['name']}  sha256={e['sha256']}" for e in list_evidence(cid)] or ["(none)"]
    lines += ["", "## Timeline"] + [f"- {t['time']}  {t['event']}" for t in read_timeline(cid)]
    lines += ["", "## Notes", read_notes(cid) or "(none)", "", f"## Chain of custody ({msg})"]
    lines += [f"{e['seq']}. {e['time']} {e['actor']} {e['action']} {e['details']}\n   hash={e['hash']}" for e in read_custody(cid)]
    out = d / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    _custody_append(cid, "REPORT_EXPORTED", out.name)
    return out
