# SOC Toolkit

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat-square&logo=typescript&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

Modular SOC analyst toolkit with REST API backend and React frontend. Designed for day-to-day security operations: email triage, log investigation, and threat intelligence enrichment.

## Modules

### Phishing Analyzer
Upload `.eml` files for automated analysis:
- **Header analysis** - SPF/DKIM/DMARC verification, sender anomaly detection, Received chain tracing
- **URL scanning** - Pattern-based detection (brand impersonation, suspicious TLDs, shorteners) + VirusTotal/URLScan.io lookup
- **Attachment scanning** - Hash computation, double extension detection, VirusTotal/MalwareBazaar lookup
- **Verdict engine** - Automated risk scoring (0-100) with confidence level and actionable recommendations

### Log Analyzer
Upload log files for threat detection:
- **SSH logs** - Brute force detection, failed/successful login correlation, attacker IP geolocation
- **Web logs** - SQL injection, path traversal, command injection, scanner/enumeration detection
- **Windows Security logs** - Event ID correlation (4625, 4697, 7045...), lateral movement detection, persistence mechanism alerts
- **Alert engine** - Severity-based alerts with AbuseIPDB enrichment and MITRE ATT&CK mapping

### IOC Extractor
Extract indicators from threat reports, emails, and raw text:
- **Supported IOC types** - IPv4, domains, URLs, email addresses, MD5/SHA1/SHA256 hashes, CVE identifiers
- **Input formats** - PDF (threat reports), .eml (emails), plain text, HTML, CSV
- **Enrichment** - Automated validation via VirusTotal, AbuseIPDB, AlienVault OTX
- **Context preservation** - Surrounding text captured for each IOC

## Architecture

```
┌──────────────────────────────────────────────┐
│                  Frontend                     │
│            React + TypeScript + Vite          │
│         Tailwind CSS + shadcn/ui              │
└──────────────────┬───────────────────────────┘
                   │ REST API
┌──────────────────▼───────────────────────────┐
│                  Backend                      │
│              FastAPI (Python)                 │
│                                               │
│  ┌────────────┐ ┌──────────┐ ┌────────────┐  │
│  │  Phishing  │ │   Logs   │ │    IOC     │  │
│  │  Analyzer  │ │ Analyzer │ │ Extractor  │  │
│  └─────┬──────┘ └────┬─────┘ └─────┬──────┘  │
│        └──────────────┼─────────────┘         │
│                       │                       │
│  ┌────────────────────▼──────────────────┐    │
│  │           Integrations                │    │
│  │  VirusTotal │ AbuseIPDB │ Shodan      │    │
│  │  URLScan.io │ MalwareBazaar │ OTX     │    │
│  └───────────────────────────────────────┘    │
│                       │                       │
│  ┌────────────────────▼──────────────────┐    │
│  │     SQLite Cache + Rate Limiter       │    │
│  └───────────────────────────────────────┘    │
└──────────────────────────────────────────────┘
```

## Quick Start

### Docker (recommended)

```bash
cp .env.example .env
# Edit .env with your API keys
docker compose up --build
```
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000/api/docs

### Local Development

**Backend:**
```bash
cd backend
poetry install
cp ../.env.example ../.env
poetry run uvicorn api.app:app --reload
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

### CLI

```bash
cd backend
poetry run python cli.py phishing suspicious_email.eml
poetry run python cli.py logs /var/log/auth.log --log-type ssh
poetry run python cli.py ioc threat_report.pdf
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/phishing/analyze` | Analyze an email file (.eml) |
| `POST` | `/api/phishing/check-url` | Check a single URL |
| `POST` | `/api/logs/analyze` | Analyze a log file |
| `POST` | `/api/ioc/extract` | Extract IOCs from a file |
| `POST` | `/api/ioc/extract-text` | Extract IOCs from raw text |
| `POST` | `/api/reports/export` | Export results (JSON/CSV/PDF) |
| `GET`  | `/api/health` | Health check + configured APIs |

Full interactive docs at `/api/docs` (Swagger UI).

## Integrations

| Service | API Tier | Rate Limit | Used For |
|---------|----------|------------|----------|
| [VirusTotal](https://www.virustotal.com/) | Free | 4 req/min | URL, hash, IP, domain lookup |
| [AbuseIPDB](https://www.abuseipdb.com/) | Free | 1000/day | IP reputation and abuse reports |
| [Shodan](https://www.shodan.io/) | Free | Limited | IP reconnaissance, open ports |
| [URLScan.io](https://urlscan.io/) | Free | 50 scans/day | URL scanning and screenshots |
| [MalwareBazaar](https://bazaar.abuse.ch/) | Free | No key needed | Malware sample lookup |
| [AlienVault OTX](https://otx.alienvault.com/) | Free | Unlimited | Threat intelligence pulses |

## Export Formats

- **JSON** - Machine-readable, for SIEM import or further processing
- **CSV** - Spreadsheet-compatible, for IOC lists and alert tables
- **PDF** - Professional reports with severity badges, suitable for management

## Tech Stack

- **Backend:** Python 3.12, FastAPI, SQLAlchemy, Pydantic, WeasyPrint
- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui
- **Database:** SQLite (API response caching)
- **Deployment:** Docker Compose
- **CI/CD:** GitHub Actions (Ruff linting, MyPy type checking, pytest)

## License

MIT License - see [LICENSE](LICENSE) for details.