# 🛡️ IOC Threat Intelligence Dashboard

A cybersecurity database project that ingests **Indicators of Compromise (IOCs)** from AlienVault OTX, converts them to **STIX 2.1** format, stores them in a fully normalized **SQLite** database, detects threat relationships, and auto-generates detection rules for SOC environments.

---

## 📋 Table of Contents

- [Features](#features)
- [Getting Your OTX API Key](#getting-your-otx-api-key)
- [Installation](#installation)
- [Running the App](#running-the-app)
- [File Structure](#file-structure)
- [Database Schema](#database-schema)
- [How to Use](#how-to-use)
- [License](#license)

---

## ✨ Features

| Feature | Description |
|---|---|
| **OTX Ingest** | Fetches live threat intelligence pulses from AlienVault OTX |
| **STIX 2.1 Conversion** | Converts all IOCs to structured STIX Indicator + Bundle objects |
| **SQLite Database** | 10-table normalized schema, zero NULL values, indexed views |
| **IOC Explorer** | Searchable, filterable table with expandable detail panels |
| **Relationship Engine** | Detects IP↔malware links, ASN clusters, hash reuse, temporal bursts |
| **Graph Visualization** | Interactive NetworkX + PyVis relationship maps |
| **Detection Rule Generator** | Auto-generates Sigma, YARA, Suricata, and Snort rules |
| **Light Dashboard** | Clean single-page app with charts and real-time DB queries |

---

## 🔑 Getting Your OTX API Key

AlienVault OTX (Open Threat Exchange) is a free threat intelligence platform. You need an account to get an API key.

### Step 1 — Create a free account
Go to [https://otx.alienvault.com](https://otx.alienvault.com) and click **Sign Up**. It's completely free.

### Step 2 — Find your API key
1. Log in to OTX
2. Click your **profile icon** in the top right
3. Click **Settings**
4. Your API key is listed under the **OTX Key** section
5. Click **Copy** to copy it

### Step 3 — Use it in the dashboard
1. Open the dashboard at `http://localhost:5000`
2. Click **Sync / Ingest** in the left sidebar
3. Paste your key into the **OTX API Key** field
4. Set how many **Days Back** you want to fetch (default: 30)
5. Click **Sync from OTX**

> **No key?** Click **Load Demo Data** instead — it loads 4 pre-built threat campaigns (APT29, LockBit, phishing, Cobalt Strike) with full relationships and rules so you can explore the dashboard immediately.

---

## ⚙️ Installation

### Prerequisites
- Python 3.9 or higher
- pip

### Step 1 — Clone the repository
```bash
git clone https://github.com/yourusername/ioc-dashboard.git
cd ioc-dashboard
```

### Step 2 — Create a virtual environment (recommended)
```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate
```

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Verify installation
```bash
python -c "import flask, stix2, networkx, pyvis; print('All dependencies OK')"
```

---

## ▶️ Running the App

```bash
python app.py
```

Then open your browser and go to:
```
http://localhost:5000
```

The database (`ioc_data.db`) is created automatically on first run — no setup needed.

---

## 📁 File Structure

```
ioc-dashboard/
│
├── app.py                          # Flask web app — all API routes
├── requirements.txt                # Python dependencies
├── README.md                       # This file
├── .gitignore                      # Excludes db, cache, graphs
│
├── modules/                        # Core backend logic
│   ├── __init__.py
│   ├── database.py                 # SQLite schema, CRUD, views, stats
│   ├── otx_fetcher.py              # OTX API client + STIX 2.1 converter
│   ├── relationship_engine.py      # NetworkX graph + cluster detection
│   └── rule_generator.py           # Sigma/YARA/Suricata/Snort generator
│
├── templates/
│   └── index.html                  # Single-page app shell
│
├── static/
│   ├── css/
│   │   └── dashboard.css           # Full light theme stylesheet
│   ├── js/
│   │   └── dashboard.js            # All frontend logic and API calls
│   └── graphs/
│       └── .gitkeep                # Placeholder — graphs generated at runtime
│
└── lib/                            # Vendored JS libraries (PyVis dependencies)
    ├── bindings/
    │   └── utils.js
    ├── tom-select/
    │   ├── tom-select.complete.min.js
    │   └── tom-select.css
    └── vis-9.1.2/
        ├── vis-network.min.js
        └── vis-network.css
```



## 🗄️ Database Schema

10 tables, all with zero NULL values enforced:

```
pulses               — OTX threat campaigns / reports
iocs                 — Individual indicators (IP, domain, hash, URL, email...)
ioc_enrichment       — GeoIP, WHOIS, ASN, file metadata (1:1 with iocs)
ioc_relationships    — Pairwise links between related IOCs
relationship_clusters — Detected threat patterns and clusters
detection_rules      — Generated Sigma/YARA/Suricata/Snort rules
stix_bundles         — Full STIX 2.1 bundle JSON per pulse
sync_log             — History of all ingest operations

Views:
  v_ioc_summary      — Joined iocs + pulses for fast dashboard queries
  v_stats            — Aggregated counters for the dashboard overview
```

---

## 🖥️ How to Use

### Loading data
- **Demo data** → Sync / Ingest → Load Demo Data
- **Live OTX data** → Sync / Ingest → paste API key → Sync from OTX

### Exploring IOCs
- Go to **IOC Explorer**
- Filter by type (IPv4, domain, hash, URL...)
- Search by indicator value, malware family, or country
- **Click any row** to open the detail panel showing enrichment, relationships, rules, and STIX JSON

### Detecting relationships
- Go to **Relationships**
- Click **Run Detectors** — scans the DB for patterns
- Click **Build Graph** — generates an interactive visualization
- Click any cluster card to see its specific subgraph

### Generating detection rules
- Go to **Detection Rules**
- Click **Generate All Rules** — creates Sigma, YARA, Suricata, Snort rules for every IOC
- Filter by rule type using the tabs
- Click any rule card to expand and copy the rule content

### Viewing STIX bundles
- Go to **STIX Bundles**
- Click **View JSON** on any bundle to see the full STIX 2.1 structured output

---

## 📦 Dependencies

| Library | Purpose |
|---|---|
| `flask` | Web framework and API server |
| `flask-cors` | Cross-origin request handling |
| `stix2` | STIX 2.1 object and bundle creation |
| `networkx` | Graph construction and analysis |
| `pyvis` | Interactive HTML graph visualization |
| `requests` | OTX API HTTP calls |
| `python-dateutil` | Date parsing and normalization |

---

## 📄 License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## ⚠️ Disclaimer

This tool is intended for educational and research purposes. All threat intelligence data is sourced from the public AlienVault OTX feed. Do not use this tool for any illegal or unauthorized activity.
