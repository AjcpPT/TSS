# TSS — Tuga Security Scan

A lightweight Linux security GUI integrating **ClamAV** (antivirus) and **rkhunter/chkrootkit** (anti-rootkit) into a single interface. Scan, monitor, quarantine and update — all in one place.

---

## Features

- **ClamAV Scan** — Scan files, folders, USB drives and downloads folder
- **Rootkit Scan** — Detect rootkits and system compromises with rkhunter and chkrootkit
- **Full Scan** — Run both ClamAV and rootkit scan together
- **Real-time Monitor** — Always-on protection with enable/disable toggle
- **Quarantine** — Isolate infected files, restore or delete permanently
- **Updates** — Update ClamAV databases (free and paid), rkhunter and the app itself
- **Scheduler** — Schedule automatic scans (daily, weekly, monthly)
- **Logs** — Full event logging with export to PDF or TXT
- **Settings** — Persistent user preferences

---

## Included Tools

| Tool | Purpose |
|---|---|
| [ClamAV](https://www.clamav.net/) | Open-source antivirus engine |
| [rkhunter](http://rkhunter.sourceforge.net/) | Rootkit, backdoor and exploit scanner |
| [chkrootkit](http://www.chkrootkit.org/) | Locally checks for signs of rootkits |

---

## Requirements

- Linux (Debian/Ubuntu based)
- Python 3.10+
- GTK4 + libadwaita
- ClamAV
- rkhunter
- chkrootkit

---

## Installation

```bash
# Install dependencies
sudo apt install clamav rkhunter chkrootkit python3-gi

# Install TSS
sudo dpkg -i tss_1.0.0_amd64.deb
```

---

## Project Structure

```
securityscan/
├── debian/                  # .deb packaging files
├── data/                    # Desktop entry and icon
├── securityscan/
│   ├── core/                # Backend modules
│   │   ├── scanner_clamav.py
│   │   ├── scanner_rootkit.py
│   │   ├── scanner_full.py
│   │   ├── quarantine.py
│   │   ├── monitor.py
│   │   ├── updater_clamav.py
│   │   ├── updater_rootkit.py
│   │   ├── updater_app.py
│   │   ├── scheduler.py
│   │   ├── logger.py
│   │   └── settings.py
│   └── ui/                  # GTK4 frontend
│       ├── window.py
│       └── tabs/
├── requirements.txt
└── pyproject.toml
```

---

## Support the Project

If you like TSS and want to support its development, you can buy me a coffee!☕

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/ajcppt)

---

## License

This project is licensed under the **GNU General Public License v3.0** — see the [LICENSE](LICENSE) file for details.

---

## Author

**AjcpPT** — [github.com/AjcpPT](https://github.com/AjcpPT)

---

> ⚠️ This project is under active development. Not yet ready for production use.
