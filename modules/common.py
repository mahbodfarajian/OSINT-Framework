import hashlib
import json
import logging
import queue
import re
import subprocess
import threading
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config" / "settings.json"
LOG_PATH = BASE_DIR / "logs" / "toolkit.log"
DATA_DIR = BASE_DIR / "data"
STATS_PATH = DATA_DIR / "stats.json"

API_KEYS = [
    ("shodan_key", "Shodan API key", "Host / Infrastructure"),
    ("censys_key", "Censys credentials (ID:SECRET)", "Host / Infrastructure"),
    ("securitytrails_key", "SecurityTrails API key", "Domain / DNS"),
    ("whoisxml_key", "WhoisXML API key", "Domain / DNS"),
    ("urlscan_key", "URLScan.io API key (optional)", "Domain / DNS"),
    ("virustotal_key", "VirusTotal API key", "Threat Intelligence"),
    ("abuseipdb_key", "AbuseIPDB API key", "Threat Intelligence"),
    ("otx_key", "AlienVault OTX API key", "Threat Intelligence"),
    ("greynoise_key", "GreyNoise API key", "Threat Intelligence"),
    ("ipinfo_token", "IPinfo token", "IP Geolocation"),
    ("hibp_key", "Have I Been Pwned API key", "Email / Identity"),
    ("hunter_key", "Hunter.io API key", "Email / Identity"),
    ("github_token", "GitHub token (raises rate limit)", "Email / Identity"),
    ("numverify_key", "NumVerify API key (phone)", "Phone"),
]
DEFAULT_CONFIG = {"safe_mode": True, **{k: "" for k, _, _ in API_KEYS}}


def _setup_logging() -> logging.Logger:
    LOG_PATH.parent.mkdir(exist_ok=True)
    logger = logging.getLogger("toolkit")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(handler)
    return logger


log = _setup_logging()


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    try:
        cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        log.warning("Config missing or invalid; using defaults")
    return cfg


def save_config(cfg: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    try:
        CONFIG_PATH.chmod(0o600)
    except OSError:
        pass
    log.info("Configuration saved")


class _SafeState:
    enabled = True
    forced = False
    listeners = []


def is_safe_mode() -> bool:
    return _SafeState.enabled


def is_safe_forced() -> bool:
    return _SafeState.forced


def add_safe_listener(fn) -> None:
    _SafeState.listeners.append(fn)


def set_safe_mode(value: bool, force: bool = False) -> bool:
    if force:
        _SafeState.forced, value = True, True
    elif _SafeState.forced and not value:
        log.warning("Refused to disable safe mode (--safe-mode flag active)")
        return False
    _SafeState.enabled = bool(value)
    log.info("Safe mode %s", "ON" if value else "OFF")
    for fn in _SafeState.listeners:
        fn(_SafeState.enabled)
    return True


_stats_lock = threading.Lock()


def _read_stats() -> dict:
    try:
        return json.loads(STATS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def get_stat(name: str, default=0):
    return _read_stats().get(name, default)


def set_stat(name: str, value) -> None:
    with _stats_lock:
        stats = _read_stats()
        stats[name] = value
        STATS_PATH.write_text(json.dumps(stats), encoding="utf-8")


def bump_stat(name: str, n: int = 1) -> None:
    with _stats_lock:
        stats = _read_stats()
        stats[name] = stats.get(name, 0) + n
        STATS_PATH.write_text(json.dumps(stats), encoding="utf-8")


def sha256_file(path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def run_async(widget, work, on_msg=None, on_done=None, poll_ms: int = 80) -> None:
    q: queue.Queue = queue.Queue()

    def target():
        try:
            q.put(("__done__", work(lambda kind, val=None: q.put((kind, val)))))
        except Exception as exc:
            log.exception("Background task failed")
            q.put(("__error__", exc))

    def poll():
        try:
            while True:
                kind, val = q.get_nowait()
                if kind == "__done__":
                    return on_done and on_done(val, None)
                if kind == "__error__":
                    return on_done and on_done(None, val)
                if on_msg:
                    on_msg(kind, val)
        except queue.Empty:
            pass
        widget.after(poll_ms, poll)

    threading.Thread(target=target, daemon=True).start()
    widget.after(poll_ms, poll)


_FORBIDDEN = re.compile(r"[;|&><`$(){}\\\n\r\"'*?~]")
ALLOWED_COMMANDS = {
    ("ls",), ("pwd",), ("whoami",), ("uname", "-a"),
    ("ps", "aux"), ("ip", "a"), ("ss", "-tuln"), ("df", "-h"),
}


def safe_exec(cmdline: str) -> str:
    if _FORBIDDEN.search(cmdline):
        log.warning("Terminal blocked (metacharacter): %r", cmdline)
        return "[BLOCKED] Shell metacharacters are not allowed."
    argv = tuple(cmdline.split())
    if argv not in ALLOWED_COMMANDS:
        log.warning("Terminal blocked (not whitelisted): %r", cmdline)
        return "[BLOCKED] Command not whitelisted. Type 'help' for the list."
    log.info("Terminal exec: %s", " ".join(argv))
    try:
        res = subprocess.run(list(argv), capture_output=True, text=True, timeout=10,
                             shell=False, cwd=BASE_DIR)
        return (res.stdout + res.stderr).rstrip() or "(no output)"
    except FileNotFoundError:
        return f"[ERROR] '{argv[0]}' not found on this system."
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out."
