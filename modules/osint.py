"""OSINT backend. Passive by default; active checks require safe mode to be OFF."""
import hashlib
import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

from modules import common
from modules.common import log

HEADERS = {"User-Agent": "kali-security-toolkit/1.0 (authorized research)"}
TIMEOUT = 12
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$")
USER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")


def _get(url, **kw):
    return requests.get(url, headers={**HEADERS, **kw.pop("headers", {})}, timeout=TIMEOUT, **kw)


def _kv(data: dict) -> str:
    out = []
    for k, v in data.items():
        if isinstance(v, (list, tuple, set)):
            out.append(f"{k}:")
            out += [f"    - {x}" for x in v] or ["    (none)"]
        else:
            out.append(f"{k}: {v}")
    return "\n".join(out)


# ---------------------------------------------------------------- DNS / mail posture
def _resolve(name, rtype):
    try:
        import dns.resolver
        return [r.to_text() for r in dns.resolver.resolve(name, rtype, lifetime=5)]
    except ImportError:  # fallback: A/AAAA only via the OS resolver
        if rtype in ("A", "AAAA"):
            fam = socket.AF_INET if rtype == "A" else socket.AF_INET6
            try:
                return sorted({i[4][0] for i in socket.getaddrinfo(name, None, fam)})
            except socket.gaierror:
                return []
        return []
    except Exception:  # NXDOMAIN, NoAnswer, timeout
        return []


def dns_report(domain: str) -> dict:
    rec = {t: _resolve(domain, t) for t in ("A", "AAAA", "MX", "NS", "TXT")}
    spf = [t for t in rec["TXT"] if "v=spf1" in t.lower()]
    dmarc = [t for t in _resolve("_dmarc." + domain, "TXT") if "v=dmarc1" in t.lower()]
    notes = []
    if not spf:
        notes.append("SPF missing - domain can be spoofed more easily")
    elif "-all" in spf[0]:
        notes.append("SPF: strict (-all)")
    elif "~all" in spf[0]:
        notes.append("SPF: soft-fail (~all)")
    else:
        notes.append("SPF: weak/permissive policy")
    if not dmarc:
        notes.append("DMARC missing")
    else:
        m = re.search(r"p=(\w+)", dmarc[0], re.I)
        notes.append(f"DMARC policy: {m.group(1).lower() if m else 'unknown'}")
    rec["SPF record"], rec["DMARC record"], rec["Assessment"] = spf or ["-"], dmarc or ["-"], notes
    return rec


# ---------------------------------------------------------------- subdomains
def passive_subdomains(domain: str) -> list:
    """Certificate-transparency lookup via crt.sh (does not touch the target)."""
    r = _get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
    r.raise_for_status()
    names = set()
    for row in r.json():
        for n in row.get("name_value", "").split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain):
                names.add(n)
    return sorted(names)


def active_subdomains(domain: str) -> dict:
    """Wordlist resolution against the target's DNS. BLOCKED in safe mode."""
    if common.is_safe_mode():
        raise PermissionError("Active subdomain resolution is disabled while Safe Mode is ON")
    words = [w.strip() for w in (common.DATA_DIR / "subdomains.txt").read_text().splitlines() if w.strip()]

    def probe(w):
        try:
            return f"{w}.{domain}", socket.gethostbyname(f"{w}.{domain}")
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=10) as ex:
        return dict(r for r in ex.map(probe, words) if r)


# ---------------------------------------------------------------- IP context
def ip_context(ip: str, cfg: dict) -> dict:
    addr = ipaddress.ip_address(ip)
    out = {"IP": str(addr), "Type": "private/reserved" if (addr.is_private or addr.is_reserved) else "public"}
    try:
        out["Reverse DNS"] = socket.gethostbyaddr(ip)[0]
    except OSError:
        out["Reverse DNS"] = "-"
    if out["Type"] != "public":
        return out
    try:  # Shodan InternetDB: free, keyless, passive
        r = _get(f"https://internetdb.shodan.io/{ip}")
        if r.status_code == 200:
            j = r.json()
            out.update({"InternetDB ports": j.get("ports", []), "InternetDB hostnames": j.get("hostnames", []),
                        "InternetDB vulns": j.get("vulns", []), "InternetDB tags": j.get("tags", [])})
        else:
            out["InternetDB"] = "no data"
    except requests.RequestException as e:
        out["InternetDB"] = f"error: {e}"
    if cfg.get("shodan_key"):
        try:
            r = _get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": cfg["shodan_key"]})
            j = r.json()
            out.update({"Shodan org": j.get("org", "-"), "Shodan OS": j.get("os") or "-",
                        "Shodan country": j.get("country_name", "-")} if r.ok else {"Shodan": j.get("error", r.status_code)})
        except (requests.RequestException, ValueError) as e:
            out["Shodan"] = f"error: {e}"
    if cfg.get("censys_key") and ":" in cfg["censys_key"]:
        cid, sec = cfg["censys_key"].split(":", 1)
        try:
            r = _get(f"https://search.censys.io/api/v2/hosts/{ip}", auth=(cid, sec))
            if r.ok:
                res = r.json().get("result", {})
                out["Censys services"] = [f"{s.get('port')}/{s.get('service_name')}" for s in res.get("services", [])]
                out["Censys ASN"] = res.get("autonomous_system", {}).get("name", "-")
            else:
                out["Censys"] = f"HTTP {r.status_code}"
        except (requests.RequestException, ValueError) as e:
            out["Censys"] = f"error: {e}"
    return out


# ---------------------------------------------------------------- email / username / metadata
def email_footprint(email: str, cfg: dict) -> dict:
    m = EMAIL_RE.match(email)
    if not m:
        raise ValueError("Invalid email syntax")
    domain = m.group(1)
    out = {"Email": email, "Domain": domain, "MX records": _resolve(domain, "MX")}
    gh = hashlib.md5(email.lower().encode()).hexdigest()  # Gravatar mandates MD5 (not security use)
    try:
        out["Gravatar profile"] = "exists" if _get(f"https://www.gravatar.com/avatar/{gh}?d=404").status_code == 200 else "none"
    except requests.RequestException as e:
        out["Gravatar profile"] = f"error: {e}"
    if cfg.get("hibp_key"):
        try:
            r = _get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                     params={"truncateResponse": "true"}, headers={"hibp-api-key": cfg["hibp_key"]})
            out["HIBP breaches"] = [b["Name"] for b in r.json()] if r.status_code == 200 else (
                [] if r.status_code == 404 else [f"HTTP {r.status_code}"])
        except (requests.RequestException, ValueError) as e:
            out["HIBP breaches"] = [f"error: {e}"]
    else:
        out["HIBP breaches"] = ["skipped (no API key)"]
    return out


def github_profile(user: str, cfg: dict) -> dict:
    if not USER_RE.match(user):
        raise ValueError("Invalid GitHub username")
    h = {"Authorization": f"Bearer {cfg['github_token']}"} if cfg.get("github_token") else {}
    r = _get(f"https://api.github.com/users/{user}", headers=h)
    if r.status_code == 404:
        return {"GitHub": "no such user"}
    r.raise_for_status()
    j = r.json()
    keys = ("login", "name", "company", "blog", "location", "email", "bio", "public_repos", "followers", "created_at")
    return {k.replace("_", " ").title(): j.get(k) or "-" for k in keys}


def extract_metadata(path: str) -> dict:
    """EXIF / file metadata. The file is only read, never opened by external programs."""
    import exifread
    p = Path(path)
    out = {"File": p.name, "Size": common.human_size(p.stat().st_size), "SHA-256": common.sha256_file(p)}
    try:
        import magic
        out["Type"] = magic.from_file(str(p))
    except Exception:  # noqa: BLE001 - python-magic/libmagic optional
        pass
    with open(p, "rb") as f:
        tags = exifread.process_file(f, details=False)
    wanted = ("Image Make", "Image Model", "Image Software", "EXIF DateTimeOriginal", "Image Artist", "Image Copyright")
    for k in wanted:
        if k in tags:
            out[k] = str(tags[k])
    gps = [k for k in tags if k.startswith("GPS")]
    if gps:
        out["GPS data"] = "PRESENT - " + "; ".join(f"{k}={tags[k]}" for k in gps if "Latitude" in k or "Longitude" in k)
    out["EXIF tags found"] = len(tags)
    return out


# ---------------------------------------------------------------- correlation
def correlate(f: dict) -> list:
    notes = []
    d, ip, email, user = f.get("domain"), f.get("ip"), f.get("email"), f.get("username")
    if d and ip and ip in f.get("domain_ips", []):
        notes.append(f"IP {ip} is an A/AAAA record of {d}")
    if d and email and email.lower().endswith("@" + d.lower()):
        notes.append(f"Email {email} belongs to the investigated domain {d}")
    if email and user and email.split("@")[0].lower() == user.lower():
        notes.append(f"Username '{user}' matches the email local-part (likely same persona)")
    gh = f.get("github", {})
    if d and d.lower() in str(gh.get("Blog", "")).lower() + str(gh.get("Email", "")).lower():
        notes.append(f"GitHub profile references {d}")
    if f.get("gps"):
        notes.append("Attached file leaks GPS coordinates")
    return notes or ["No cross-entity links found"]


# ---------------------------------------------------------------- API enrichment (keys from Settings)
def _j(url, **kw):
    r = _get(url, **kw)
    if r.status_code in (401, 403):
        return {"error": "auth failed (check API key)"}
    if r.status_code == 404:
        return {"error": "not found"}
    r.raise_for_status()
    return r.json()


def _api(out, name, url, fmt, **kw):
    try:
        j = _j(url, **kw)
        out[name] = f"error: {j['error']}" if "error" in j else fmt(j)
    except Exception as e:  # noqa: BLE001 - one failing API must not stop the run
        out[name] = f"error: {e}"


def _vt(j):
    a = j["data"]["attributes"]
    s = a.get("last_analysis_stats", {})
    return (f"malicious={s.get('malicious', 0)} suspicious={s.get('suspicious', 0)} harmless={s.get('harmless', 0)}"
            f" | owner/registrar={a.get('as_owner') or a.get('registrar') or '-'} | reputation={a.get('reputation', '-')}")


def intel_ip(ip, cfg) -> dict:
    out = {}
    if cfg.get("virustotal_key"):
        _api(out, "VirusTotal", f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", _vt,
             headers={"x-apikey": cfg["virustotal_key"]})
    if cfg.get("abuseipdb_key"):
        _api(out, "AbuseIPDB", "https://api.abuseipdb.com/api/v2/check",
             lambda j: f"score={j['data']['abuseConfidenceScore']}% reports={j['data']['totalReports']} "
                       f"country={j['data'].get('countryCode')} isp={j['data'].get('isp')}",
             params={"ipAddress": ip, "maxAgeInDays": 90}, headers={"Key": cfg["abuseipdb_key"], "Accept": "application/json"})
    if cfg.get("otx_key"):
        _api(out, "AlienVault OTX", f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
             lambda j: f"pulses={j.get('pulse_info', {}).get('count', 0)} reputation={j.get('reputation', '-')}",
             headers={"X-OTX-API-KEY": cfg["otx_key"]})
    if cfg.get("greynoise_key"):
        _api(out, "GreyNoise", f"https://api.greynoise.io/v3/community/{ip}",
             lambda j: f"{j.get('classification')} noise={j.get('noise')} riot={j.get('riot')} name={j.get('name', '-')}",
             headers={"key": cfg["greynoise_key"]})
    if cfg.get("ipinfo_token"):
        _api(out, "IPinfo", f"https://ipinfo.io/{ip}",
             lambda j: f"{j.get('city')}, {j.get('region')}, {j.get('country')} | {j.get('org')} | loc={j.get('loc')}",
             params={"token": cfg["ipinfo_token"]})
    return out


def intel_domain(d, cfg) -> dict:
    out = {}
    if cfg.get("virustotal_key"):
        _api(out, "VirusTotal", f"https://www.virustotal.com/api/v3/domains/{d}", _vt, headers={"x-apikey": cfg["virustotal_key"]})
    if cfg.get("otx_key"):
        _api(out, "AlienVault OTX", f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/general",
             lambda j: f"pulses={j.get('pulse_info', {}).get('count', 0)}", headers={"X-OTX-API-KEY": cfg["otx_key"]})
    if cfg.get("securitytrails_key"):
        _api(out, "SecurityTrails", f"https://api.securitytrails.com/v1/domain/{d}/subdomains",
             lambda j: f"{len(j.get('subdomains', []))} subdomains: " + ", ".join(f"{x}.{d}" for x in j.get("subdomains", [])[:20]),
             headers={"APIKEY": cfg["securitytrails_key"]})
    if cfg.get("hunter_key"):
        _api(out, "Hunter.io", "https://api.hunter.io/v2/domain-search",
             lambda j: f"pattern={j['data'].get('pattern')} | " + ", ".join(e["value"] for e in j["data"].get("emails", [])[:10]),
             params={"domain": d, "api_key": cfg["hunter_key"]})
    if cfg.get("whoisxml_key"):
        _api(out, "WhoisXML", "https://www.whoisxmlapi.com/whoisserver/WhoisService",
             lambda j: f"registrar={j['WhoisRecord'].get('registrarName')} created={j['WhoisRecord'].get('createdDate')} "
                       f"expires={j['WhoisRecord'].get('expiresDate')}",
             params={"apiKey": cfg["whoisxml_key"], "domainName": d, "outputFormat": "JSON"})
    h = {"API-Key": cfg["urlscan_key"]} if cfg.get("urlscan_key") else {}
    _api(out, "URLScan.io", "https://urlscan.io/api/v1/search/",
         lambda j: f"{j.get('total', 0)} public scans" + (f"; latest {j['results'][0]['task']['time']} ip={j['results'][0]['page'].get('ip', '-')}"
                                                           if j.get("results") else ""),
         params={"q": f"domain:{d}", "size": 1}, headers=h)
    return out


def network_info(target, cfg) -> dict:
    """CIDR or ASN overview via RIPEstat (passive) plus InternetDB for a few sample hosts."""
    import itertools
    if target.upper().startswith("AS"):
        j = _j("https://stat.ripe.net/data/as-overview/data.json", params={"resource": target})
        d = j.get("data", {})
        return {"ASN": target.upper(), "Holder": d.get("holder", "-"), "Announced": d.get("announced", "-")}
    net = ipaddress.ip_network(target, strict=False)
    out = {"Network": str(net), "Addresses": net.num_addresses, "Scope": "private" if net.is_private else "public"}
    if net.is_private:
        return out
    d = _j("https://stat.ripe.net/data/prefix-overview/data.json", params={"resource": str(net)}).get("data", {})
    out["Announced"] = d.get("announced", "-")
    out["Origin ASNs"] = [f"AS{a.get('asn')} {a.get('holder', '')}" for a in d.get("asns", [])]
    samples = {}
    for h in itertools.islice(net.hosts(), 8):  # passive third-party data only, target is not contacted
        try:
            r = _get(f"https://internetdb.shodan.io/{h}")
            if r.status_code == 200 and r.json().get("ports"):
                samples[str(h)] = r.json()["ports"]
        except requests.RequestException:
            break
    out["Sample hosts with known open ports (InternetDB)"] = [f"{h}: {p}" for h, p in samples.items()]
    return out


SITES = {"GitLab": "https://gitlab.com/{}", "Reddit": "https://www.reddit.com/user/{}/about.json",
         "Keybase": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}", "Dev.to": "https://dev.to/{}",
         "Docker Hub": "https://hub.docker.com/v2/users/{}/", "HackerNews": "https://hacker-news.firebaseio.com/v0/user/{}.json"}


def username_sites(u) -> dict:
    if not USER_RE.match(u):
        raise ValueError("Invalid username")

    def probe(item):
        name, url = item
        try:
            r = _get(url.format(u))
            ok = r.status_code == 200
            if ok and name == "HackerNews":
                ok = r.text.strip() != "null"
            if ok and name == "Keybase":
                ok = r.json().get("them", [None])[0] is not None
            return name, "FOUND " + url.format(u).split("?")[0] if ok else "not found"
        except (requests.RequestException, ValueError):
            return name, "error"

    with ThreadPoolExecutor(max_workers=6) as ex:
        return dict(ex.map(probe, SITES.items()))


def phone_info(number, region, cfg) -> dict:
    out = {"Input": number}
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone
        n = phonenumbers.parse(number, region.upper() or None)
        kinds = {0: "fixed line", 1: "mobile", 2: "fixed/mobile", 3: "toll-free", 4: "premium", 6: "VoIP"}
        out.update({"Valid": phonenumbers.is_valid_number(n),
                    "International": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                    "Country code": f"+{n.country_code}", "Location": geocoder.description_for_number(n, "en") or "-",
                    "Carrier": carrier.name_for_number(n, "en") or "-",
                    "Line type": kinds.get(phonenumbers.number_type(n), "other"),
                    "Time zones": list(timezone.time_zones_for_number(n))})
    except ImportError:
        out["Valid (E.164 format)"] = bool(re.match(r"^\+?[1-9]\d{6,14}$", number))
        out["Note"] = "pip install phonenumbers for offline carrier/location parsing"
    if cfg.get("numverify_key"):
        _api(out, "NumVerify", "https://apilayer.net/api/validate",
             lambda j: f"valid={j.get('valid')} carrier={j.get('carrier') or '-'} line={j.get('line_type')} location={j.get('location')}",
             params={"access_key": cfg["numverify_key"], "number": number.lstrip("+")})
    return out


# ---------------------------------------------------------------- orchestration
def run_investigation(t: dict, emit) -> None:
    """Run every requested step; emit('text', str) and emit('progress', 0..1) for the GUI."""
    cfg = common.load_config()
    f, steps = {}, []
    g = lambda k: (t.get(k) or "").strip()  # noqa: E731
    d, ip, email, user, path, phone, net = (g(k) for k in ("domain", "ip", "email", "username", "file", "phone", "network"))
    summary = d or ip or email or user or phone or net or path

    if d:
        if not DOMAIN_RE.match(d):
            raise ValueError("Invalid domain")
        f["domain"] = d.lower()

        def s_dns():
            r = dns_report(d)
            f["domain_ips"] = r["A"] + r["AAAA"]
            return _kv(r)

        def s_subs():
            subs = passive_subdomains(d)
            return f"{len(subs)} unique names\n" + "\n".join(f"  {s}" for s in subs[:150]) + (
                f"\n  ... (+{len(subs) - 150} more)" if len(subs) > 150 else "")

        steps += [("DNS / SPF / DMARC", s_dns), ("Passive subdomains (crt.sh)", s_subs),
                  ("Domain intelligence (APIs)", lambda: _kv(intel_domain(d, cfg)))]
        if t.get("active"):
            steps.append(("Active subdomain resolution (wordlist)", lambda: _kv(active_subdomains(d)) or "(none resolved)"))
    if ip:
        f["ip"] = ip
        steps += [("IP context", lambda: _kv(ip_context(ip, cfg))),
                  ("IP reputation (APIs)", lambda: _kv(intel_ip(ip, cfg)) or "(no API keys configured - add them in Settings)")]
    if net:
        steps.append(("Network overview", lambda: _kv(network_info(net, cfg))))
    if email:
        f["email"] = email
        steps.append(("Email footprint", lambda: _kv(email_footprint(email, cfg))))
    if user:
        f["username"] = user

        def s_gh():
            f["github"] = github_profile(user, cfg)
            return _kv(f["github"])

        steps += [("GitHub profile", s_gh), ("Username presence (public sites)", lambda: _kv(username_sites(user)))]
    if phone:
        steps.append(("Phone number", lambda: _kv(phone_info(phone, g("region"), cfg))))
    if path:
        def s_meta():
            m = extract_metadata(path)
            f["gps"] = "GPS data" in m
            return _kv(m)

        steps.append(("File metadata", s_meta))

    for i, (name, fn) in enumerate(steps):
        log.info("OSINT step: %s", name)
        emit("text", f"\n=== {name} ===\n")
        try:
            emit("text", fn() + "\n")
        except PermissionError as e:
            emit("text", f"[BLOCKED] {e}\n")
        except Exception as e:  # noqa: BLE001
            log.warning("OSINT step %s failed: %s", name, e)
            emit("text", f"[ERROR] {e}\n")
        emit("progress", (i + 1) / (len(steps) + 1))
    emit("text", "\n=== Entity correlation ===\n" + "\n".join(f"  * {n}" for n in correlate(f)) + "\n")
    emit("progress", 1.0)
    common.bump_stat("osint_reports")
    common.set_stat("last_osint", f"{__import__('time').strftime('%H:%M')}  {summary}")
    log.info("OSINT investigation finished (%d steps)", len(steps))
