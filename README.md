# Kali Security Toolkit

A modular, terminal and GUI-based cybersecurity toolkit for authorized security work on Kali Linux.

## Why this project?

I built this as part of my journey learning cybersecurity from scratch. It started as a terminal tool and evolved into a CustomTkinter dashboard. The goal was not to replace professional tools like Maltego or Burp Suite, but to understand how OSINT, forensic case management, and passive network monitoring actually work under the hood.

## Features

- **OSINT Suite**: DNS/SPF/DMARC analysis, passive subdomain discovery (crt.sh), IP reputation (Shodan, VirusTotal, AbuseIPDB), email footprinting, GitHub profile enrichment, metadata extraction, and entity correlation.
- **Analysis Suite**: PCAP parsing with protocol statistics, static binary analysis (hashes, entropy, PE/ELF headers, strings), and CSV/JSON summaries.
- **Case Management**: Local case folders, SHA-256 evidence verification, append-only hash-chained custody log, notes, timeline, and Markdown report export.
- **System & Network Radar**: Live process and connection monitoring, passive LAN neighbor view, kernel log review, and a simple radar sweep visualization.
- **Safe Terminal**: Whitelisted read-only commands only, with shell metacharacters blocked.

## Safety

- Safe Mode is enabled by default and blocks all active scanning.
- All actions are logged to `logs/toolkit.log`.
- The toolkit is for authorized use only. Use it only on systems you own or have explicit permission to test.

## Setup

```bash
sudo apt install python3-tk libmagic1
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config/settings.example.json config/settings.json
python main.py
```

## Optional API keys
- Edit config/settings.json or set environment variables. Without keys, only passive checks (DNS, crt.sh, InternetDB) are available.

## Status

- This is a learning project. It is under active development. Some modules are functional and tested; others are still being refined. Feedback and suggestions are welcome.

## Author

- Mahbod Farajian — learning cybersecurity and network security fundamentals.