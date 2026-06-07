# OSINT-Based Reconnaissance Framework

**Automated Attack Surface Mapping Tool** for Vulnerability Assessment and Penetration Testing (VAPT)

---

## 📋 Overview

This project is an **OSINT-Based Reconnaissance Framework** developed as part of the **VAPT Laboratory (23CYL65)** at M S Ramaiah Institute of Technology. It automates passive reconnaissance to map an organization's public attack surface using industry-standard tools.

The framework collects, correlates, and analyzes publicly available information about a target domain **without sending any packets** to the target — making it completely legal and stealthy.

---

## ✨ Features

- **DNS Enumeration** using DNSRecon
- **Email & Subdomain Harvesting** using theHarvester
- **Infrastructure Footprinting** using Shodan Python API
- **Breach Intelligence** using HaveIBeenPwned API
- **Domain Intelligence** using Whois (system binary)
- **Visual Relationship Mapping** using SpiderFoot
- **Maltego Integration** via launch script
- **Professional Reporting** — HTML + JSON per domain

---

## 🛠️ Tech Stack

| Component | Tool / Library |
|---|---|
| Language | Python 3.12 |
| DNS Enumeration | DNSRecon (cloned, installed locally) |
| Email & Subdomain Harvesting | theHarvester (cloned, installed locally) |
| Infrastructure Scanning | Shodan Python Library |
| Breach Detection | HaveIBeenPwned REST API v3 |
| Domain Registration Info | `whois` (system binary) |
| Visual Graph Mapping | SpiderFoot (cloned, self-hosted) |
| Graph Analysis UI | Maltego (macOS desktop app) |
| Output Formats | HTML Report, JSON, XML |
| Environment | macOS / Kali Linux + virtualenv |

---

## 📦 Installation

> **Note:** The following tools are not included in this repository (excluded via `.gitignore`) because they are large external projects with their own dependencies. Clone and install each one separately as shown below.

### Prerequisites

- Python 3.12 or higher
- Git
- `whois` (pre-installed on macOS and most Linux distros)
- Maltego desktop app (macOS) — download from [maltego.com](https://www.maltego.com/downloads/)

### Step-by-Step Installation

```bash
# 1. Clone this repository
git clone https://github.com/Keertanm/OSINT-Based-Recon-Framework.git
cd OSINT-Based-Recon-Framework

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate          # macOS/Linux
# venv\Scripts\activate           # Windows

# 3. Upgrade pip and install Python dependencies
pip install --upgrade pip
pip install shodan requests python-dotenv

# 4. Install DNSRecon
# Source: https://github.com/darkoperator/dnsrecon
git clone https://github.com/darkoperator/dnsrecon.git
cd dnsrecon
pip install -r requirements.txt
pip install .
cd ..

# 5. Install theHarvester
# Source: https://github.com/laramies/theHarvester
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
pip install -r requirements/base.txt
pip install -e .
cd ..

# 6. Install SpiderFoot
# Source: https://github.com/smicallef/spiderfoot
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
pip install -r requirements.txt
cd ..

# 7. Configure Shodan API key
# Get your key from: https://account.shodan.io/
shodan init YOUR_SHODAN_API_KEY

# 8. Set up environment variables
cp .env.example .env
# Open .env and replace the placeholder with your actual Shodan API key
# The file should look like:
# SHODAN_API_KEY=your_actual_key_here
```

> **Note:** The `.env` file is gitignored and stays on your machine only. Never commit it.

---

## 🚀 Usage

### Run the main recon framework

```bash
source venv/bin/activate
python main.py
```

Enter a target domain when prompted (e.g., `msrit.edu`). The framework runs all modules sequentially and generates a report under `reports/`.

### Launch SpiderFoot (visual graph UI)

```bash
bash start_spiderfoot.sh
```

Then open `http://127.0.0.1:5001` in your browser to access the SpiderFoot web interface.

### Launch Maltego (macOS only)

```bash
bash launch_maltego.sh
```

Opens the Maltego desktop app directly from the terminal.

---

## 📁 Project Structure

```
osint_framework/
├── main.py                    # Orchestrator — runs all recon modules in sequence
├── modules/
│   ├── dns_parser.py          # Parses DNSRecon XML output
│   ├── harvester_parser.py    # Parses theHarvester XML/JSON output
│   └── report.py              # Generates HTML + JSON reports, HIBP + Whois queries
├── outputs/
│   ├── dns/                   # Raw DNSRecon XML output files
│   ├── harvester/             # Raw theHarvester output files
│   ├── maltego/               # CSV exports for Maltego import
│   └── spiderfoot/            # SpiderFoot CSV output
├── reports/                   # Final HTML + JSON reports per domain
├── launch_maltego.sh          # Launches Maltego desktop app (macOS)
├── start_spiderfoot.sh        # Starts SpiderFoot web UI on port 5001
├── .gitignore
└── README.md
```

> **Not in repo (install separately):** `venv/`, `dnsrecon/`, `theHarvester/`, `spiderfoot/`

---

## 🔄 How It Works — Module Integration

### Execution Flow (`main.py`)

`main.py` is the central orchestrator. Running `python main.py` triggers this pipeline:

```
User Input (domain)
       │
       ▼
  DNSRecon CLI  ──────────→  outputs/dns/dnsrecon_std.xml
       │
       ▼
  dns_parser.py  ──────────→  Extracts IPs, A/MX/NS/TXT records
       │
       ▼
  theHarvester CLI  ───────→  outputs/harvester.xml
       │
       ▼
  harvester_parser.py  ────→  Extracts emails, subdomains, URLs
       │
       ▼
  Shodan Python API  ──────→  Queries open ports for discovered IPs (top 3)
       │
       ▼
  report.py  ──────────────→  HIBP check + Whois + HTML/JSON report
       │
       ▼
  SpiderFoot (optional)  ──→  Visual relationship graph
```

---

### `main.py` — Orchestrator

Drives the entire pipeline using `subprocess.run()` to invoke CLI tools, then feeds their output files into the parser modules.

- Calls `dnsrecon -d <domain> -t std -x outputs/dns/dnsrecon_std.xml` and filters stdout to show only meaningful DNS record lines (`A`, `MX`, `NS`, `TXT`, `SOA`)
- Calls `theHarvester -d <domain> -b duckduckgo,crtsh,rapiddns,urlscan -l 200 -f outputs/harvester.xml`
- Uses the `shodan` Python library directly (not CLI) to query host info for up to 3 IPs discovered by DNSRecon
- Passes all collected data to `generate_report()` in `report.py`
- Optionally runs SpiderFoot via `python3 spiderfoot/sf.py -s <domain> -m footprint -o csv`

---

### `modules/dns_parser.py` — DNS Output Parser

Parses the XML file produced by DNSRecon.

- Uses `xml.etree.ElementTree` to walk all `<record>` elements
- Extracts **IP addresses** from `type="A"` records into `dns_data["ips"]`
- Extracts all other record types (`MX`, `NS`, `TXT`, `SOA`) into `dns_data["records"]`
- Returns a dict consumed by both `main.py` (Shodan IP lookup) and `report.py` (findings)

---

### `modules/harvester_parser.py` — Harvester Output Parser

Parses the XML file produced by theHarvester.

- Walks `<email>`, `<url>`, and `<host>` XML tags to extract discovered assets
- Falls back to the `.json` file (same base path) if XML parsing fails, reading `interesting_urls`
- Deduplicates all lists with `set()` before returning
- Returns a dict with `emails`, `urls`, `hosts`, and `subdomains` keys consumed by `report.py`

---

### `modules/report.py` — Report Generator

The most feature-rich module — handles three external data sources and produces the final deliverables.

**Whois (`get_whois`):**
Runs the system `whois` binary via `subprocess`, then uses regex to extract creation date, expiry date, registrar, and name servers from raw text output. Handles privacy-protected domains gracefully with fallback strings.

**HaveIBeenPwned (`check_hibp`):**
Queries the HIBP REST API v3 at `haveibeenpwned.com/api/v3/breachedaccount/<email>` for each of the first 5 discovered emails. Returns breach names for exposed accounts or a clean status for safe ones.

**Report generation (`generate_report`):**
Aggregates all findings (IPs, emails, subdomains, URLs, open ports) with severity ratings (Critical / High / Medium), combines Whois + HIBP results, writes a structured `reports/<domain>_report.json`, and renders a styled `reports/<domain>_report.html` with color-coded severity rows and a recommendations section.

---

### `start_spiderfoot.sh` — SpiderFoot Web UI

```bash
cd /path/to/osint_framework/spiderfoot
python3 sf.py -l 127.0.0.1:5001
```

Starts SpiderFoot's built-in web server locally on port 5001. Access the UI at `http://127.0.0.1:5001` to run scans, view relationship graphs, and explore discovered entities visually. SpiderFoot is not called automatically by `main.py` for the web UI — the main pipeline uses it in headless CSV mode only.

---

### `launch_maltego.sh` — Maltego Desktop Launcher

```bash
/Applications/Maltego.app/Contents/MacOS/Maltego --nosplash -J-Djava.security.manager=allow
```

Launches the Maltego desktop application on macOS with the Java security manager flag required for newer JVM versions. Maltego can import the CSV exports from `outputs/maltego/` to build visual entity relationship graphs from the recon data.

---

## 📊 Sample Output

Each run produces two files under `reports/`:

- `<domain>_report.html` — color-coded findings table with severity ratings, Whois info, HIBP results, and hardening recommendations
- `<domain>_report.json` — structured data for further scripting or import into other tools

**Domains tested during development:**
`msrit.edu`, `mccblr.edu.in`, `rvce.edu.in`, `fnp.com`, `testphp.vulnweb.com`

---

## 🎯 Use Cases

- Academic VAPT / Cybersecurity lab projects
- Red teaming preparation and asset discovery
- Attack surface management for organizations
- Security awareness training

---

## 🔧 Troubleshooting

### `shodan: command not found`
Ensure the virtual environment is active before running `shodan init`:
```bash
source venv/bin/activate
shodan init YOUR_SHODAN_API_KEY
```

### `ModuleNotFoundError` for any package
Re-run the install step inside the activated virtual environment:
```bash
source venv/bin/activate
pip install shodan requests python-dotenv
```

### `theHarvester` or `dnsrecon` not recognized
Make sure you ran `pip install .` (DNSRecon) and `pip install -e .` (theHarvester) from inside their respective cloned directories while the venv is active.

### Permission errors on macOS/Linux
Avoid using `sudo` with pip inside a virtual environment. Confirm the venv is active — `which python` should point inside your `venv/` folder.

### Shodan API returns no results
- Verify your API key at [account.shodan.io](https://account.shodan.io/)
- Free-tier keys have limited query credits — check your usage dashboard
- Some domains may have no indexed Shodan data

### SpiderFoot port already in use
Change the port in `start_spiderfoot.sh` from `5001` to any free port (e.g., `5002`):
```bash
python3 sf.py -l 127.0.0.1:5002
```

### Maltego won't launch on newer macOS
If `launch_maltego.sh` fails, open Maltego directly from `/Applications` and import CSVs from `outputs/maltego/` manually.

### HIBP returns 401 / 403
The free HIBP API endpoint used here (`/api/v3/breachedaccount/`) requires an API key for production use. For academic use, the framework handles failed checks gracefully and continues report generation.

---

## ⚠️ Important Notes

- This tool performs **only passive reconnaissance**
- All data is collected from **publicly available sources**
- Intended for **educational and authorized security testing purposes only**
- Do not run against domains you do not own or have explicit written permission to test
