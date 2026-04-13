# Setup Guide

## Prerequisites

- Python 3.12+
- Node.js 20+
- Poetry 1.8+
- Docker and Docker Compose (optional, for containerized deployment)

## Quick Start with Docker

```bash
# Clone the repository
git clone https://github.com/Nicholas-Arcari/soc-toolkit.git
cd soc-toolkit

# Configure API keys
cp .env.example .env
nano .env  # Add your API keys

# Start all services
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000/api/docs
- Health check: http://localhost:8000/api/health

## Local Development Setup

### Backend

```bash
cd backend

# Install dependencies
poetry install

# Configure environment
cp ../.env.example ../.env
nano ../.env

# Run development server
poetry run uvicorn api.app:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at http://localhost:8000 with auto-reload on code changes.

### Frontend

```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev
```

The frontend will be available at http://localhost:5173 with hot module replacement. API requests are proxied to the backend automatically.

### CLI

```bash
cd backend

# Analyze a phishing email
poetry run python cli.py phishing ../samples/emails/phishing_sample.eml

# Analyze SSH logs
poetry run python cli.py logs ../samples/logs/auth.log --log-type ssh

# Extract IOCs from a threat report
poetry run python cli.py ioc ../samples/reports/threat_report_sample.txt
```

## API Keys Configuration

All API keys are configured via the `.env` file. The toolkit works without API keys (threat intelligence enrichment will be skipped), but for full functionality:

| Service | Free Tier | Get API Key |
|---------|-----------|-------------|
| VirusTotal | 4 requests/min | https://www.virustotal.com/gui/my-apikey |
| AbuseIPDB | 1000 checks/day | https://www.abuseipdb.com/account/api |
| Shodan | Limited queries | https://account.shodan.io/ |
| URLScan.io | 50 scans/day | https://urlscan.io/user/profile/ |
| AlienVault OTX | Unlimited | https://otx.alienvault.com/api |
| MalwareBazaar | No key needed | https://bazaar.abuse.ch/api/ |

## Running Tests

```bash
cd backend
poetry run pytest --cov=core --cov-report=term-missing -v
```

## Linting and Type Checking

```bash
cd backend

# Lint with Ruff
poetry run ruff check .

# Type check with MyPy
poetry run mypy --ignore-missing-imports .
```

## Production Deployment

For production, update the `.env` file:

```bash
APP_ENV=production
APP_DEBUG=false
APP_SECRET_KEY=<generate-a-random-key>
```

Then build and run with Docker:

```bash
docker compose up --build -d
```

## Troubleshooting

**Backend won't start:**
- Check that Python 3.12+ is installed: `python --version`
- Check that all dependencies are installed: `poetry install`
- Verify `.env` file exists in the project root

**Frontend can't reach backend:**
- Ensure backend is running on port 8000
- Check CORS settings in `backend/api/app.py`
- In development, Vite proxies `/api` requests automatically

**API enrichment not working:**
- Run `GET /api/health` to see which APIs are configured
- Verify API keys in `.env` are valid and not expired
- Check rate limits (VirusTotal free tier: 4 req/min)

**WeasyPrint PDF errors:**
- Install system dependencies: `apt-get install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0`
