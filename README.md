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
- **Infrastructure Footprinting** using Shodan
- **Breach Intelligence** using HaveIBeenPwned
- **Domain Intelligence** using Whois
- **Professional Reporting** (HTML + JSON)
- **Maltego-compatible CSV Export** for visual mapping
- **Modular & Extensible** Python architecture

---

## 🛠️ Tech Stack

- **Language**: Python 3.12
- **Tools**: DNSRecon, theHarvester, Shodan (Python Library), HaveIBeenPwned API
- **Output**: HTML Report, JSON, CSV (Maltego)
- **Environment**: macOS / Kali Linux (Virtual Environment supported)

---

## 📦 Installation

### Prerequisites

- Python 3.12 or higher
- Git

### Step-by-Step Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/osint-recon-framework.git
cd osint-recon-framework

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate          # On macOS/Linux
# venv\Scripts\activate           # On Windows

# 3. Upgrade pip
pip install --upgrade pip

# 4. Install required Python packages
pip install shodan requests python-dotenv

# 5. Install DNSRecon
git clone https://github.com/darkoperator/dnsrecon.git
cd dnsrecon
pip install -r requirements.txt
pip install .
cd ..

# 6. Install theHarvester
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
pip install -r requirements/base.txt
python setup.py install
cd ..

# 7. Configure Shodan (Get your API key from https://account.shodan.io/)
shodan init YOUR_SHODAN_API_KEY
```

---

## 🚀 Usage

```bash
# Activate virtual environment (if not already active)
source venv/bin/activate

# Run the framework
python main.py
```

Enter your target domain when prompted (e.g., `msrit.edu`).

---

## 📁 Project Structure

```
osint_framework/
├── main.py
├── modules/
│   ├── dns_parser.py
│   ├── harvester_parser.py
│   └── report.py
├── outputs/
├── reports/          # HTML + JSON reports generated here
├── screenshots/
└── venv/
```

---

## 📊 Sample Output

- Generates a **professional HTML report** with severity ratings and recommendations
- Creates structured **JSON** for further analysis
- Exports data for **Maltego** visual relationship mapping

---

## 🎯 Use Cases

- Academic VAPT / Cybersecurity projects
- Red teaming preparation
- Attack surface management
- Security awareness training

---

## 🔧 Troubleshooting

### `shodan: command not found`
Ensure the virtual environment is activated before running `shodan init`:
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
Make sure you ran `pip install .` (DNSRecon) and `python setup.py install` (theHarvester) from inside their respective cloned directories while the venv is active.

### Permission errors on macOS/Linux
Avoid using `sudo` with pip inside a virtual environment. If you encounter permission issues, confirm the venv is active (`which python` should point inside your `venv/` folder).

### Shodan API returns no results
- Verify your API key at [account.shodan.io](https://account.shodan.io/)
- Free-tier Shodan API keys have limited query credits — check your usage dashboard
- Some domains may have no indexed Shodan data

### `python setup.py install` deprecation warning (theHarvester)
On newer pip versions, you may see a deprecation warning. It is safe to ignore for now, or use:
```bash
pip install -e .
```
as an alternative inside the `theHarvester` directory.

---

## ⚠️ Important Notes

- This tool performs **only passive reconnaissance**
- All data is collected from public sources
- Intended for educational and authorized security testing purposes only
