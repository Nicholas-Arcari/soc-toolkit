# Architecture

## Overview

SOC Toolkit follows a modular monolith architecture with clear separation between the API layer, business logic, and external integrations.

```
┌─────────────────────────────────────────────────────────────┐
│                      Frontend (React)                       │
│  Dashboard │ PhishingAnalyzer │ LogAnalyzer │ IOCExtractor  │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP/REST
┌──────────────────────────▼──────────────────────────────────┐
│                    API Layer (FastAPI)                       │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
│  │ Phishing │  │   Logs   │  │   IOC    │  │  Reports   │  │
│  │  Routes  │  │  Routes  │  │  Routes  │  │   Routes   │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └─────┬──────┘  │
│       │              │             │               │        │
│  ┌────▼──────────────▼─────────────▼───────────────▼────┐   │
│  │                  Middleware                           │   │
│  │         Rate Limiter │ Error Handler │ CORS           │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                    Core (Business Logic)                     │
│                                                             │
│  ┌─────────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │    Phishing      │  │     Logs     │  │      IOC      │  │
│  │                  │  │              │  │               │  │
│  │ header_analyzer  │  │ ssh_analyzer │  │ text_extractor│  │
│  │ url_checker      │  │ web_analyzer │  │ pdf_extractor │  │
│  │ attachment_scan  │  │ win_analyzer │  │ email_extract │  │
│  │ verdict_engine   │  │ alert_engine │  │ ioc_validator │  │
│  └────────┬─────────┘  └──────┬───────┘  └───────┬───────┘  │
│           └───────────────────┼───────────────────┘         │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                     Integrations                            │
│                                                             │
│  BaseAPIClient (rate limiting, retries, error handling)      │
│       │                                                     │
│  ┌────▼────┐ ┌──────────┐ ┌────────┐ ┌─────────┐           │
│  │VirusTotal│ │AbuseIPDB │ │ Shodan │ │URLScan  │           │
│  └─────────┘ └──────────┘ └────────┘ └─────────┘           │
│  ┌──────────────┐ ┌────────────────┐                        │
│  │MalwareBazaar │ │AlienVault OTX  │                        │
│  └──────────────┘ └────────────────┘                        │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│              Cache (SQLite) + Export (JSON/CSV/PDF)          │
└─────────────────────────────────────────────────────────────┘
```

## Design Decisions

### Why FastAPI over Flask/Django?

- **Async support** - External API calls (VirusTotal, AbuseIPDB) benefit from non-blocking I/O
- **Auto-generated OpenAPI docs** - Swagger UI at `/api/docs` with zero configuration
- **Pydantic validation** - Request/response models with automatic type checking
- **Performance** - ASGI server handles concurrent requests efficiently

### Why SQLite for caching?

- **Zero configuration** - No external database server needed
- **Single file** - Easy to backup, move, or reset
- **Sufficient for cache** - We only store API responses with TTL, not relational data
- **Docker-friendly** - Just mount a volume

### Why a monolith instead of microservices?

- **Simplicity** - Three modules don't justify the overhead of separate services
- **Shared integrations** - VirusTotal is used by all three modules
- **Single deployment** - One Docker Compose, one CI pipeline
- **Appropriate scale** - This is a single-user analyst tool, not a multi-tenant SaaS

### Rate Limiting Strategy

External APIs have strict free-tier limits:

| Service | Limit | Strategy |
|---------|-------|----------|
| VirusTotal | 4/min | Token bucket, 15s spacing |
| AbuseIPDB | 1000/day | Per-request tracking |
| Shodan | Very limited | 60s spacing |
| URLScan.io | 50/day | Daily counter |

The `BaseAPIClient` implements:
1. **Token bucket rate limiter** per service
2. **Automatic retry** with exponential backoff (3 attempts)
3. **429 handling** with Retry-After header respect
4. **SQLite cache** to avoid duplicate queries (configurable TTL)

### Frontend Architecture

Single-page application with client-side routing:

- **Dashboard** - Health check, module navigation
- **Module pages** - Self-contained with FileUpload, analysis display, and export
- **Shared components** - Sidebar, FileUpload, SeverityBadge

State is managed locally per page (no global state store needed at this scale).

## Data Flow

### Phishing Analysis

```
User uploads .eml
  → Parse email headers (SPF, DKIM, DMARC, anomalies)
  → Extract and check URLs (pattern matching + VirusTotal + URLScan.io)
  → Extract and scan attachments (hash + VirusTotal + MalwareBazaar)
  → Verdict engine scores all findings (0-100)
  → Return verdict + indicators + recommendations
```

### Log Analysis

```
User uploads log file
  → Auto-detect log type (SSH, Apache, Nginx, Windows)
  → Parse entries with type-specific analyzer
  → Aggregate by IP, timeline, patterns
  → Enrich top IPs via AbuseIPDB
  → Generate severity-based alerts with MITRE mapping
  → Return alerts + timeline + top IPs + summary
```

### IOC Extraction

```
User uploads file (PDF, EML, TXT)
  → Extract text (PyMuPDF for PDF, email parser for EML)
  → Regex extraction: IPs, domains, URLs, hashes, emails, CVEs
  → Deduplicate and filter (skip internal IPs, common FPs)
  → Enrich via VirusTotal + AbuseIPDB + AlienVault OTX
  → Return IOCs with enrichment + malicious verdict
```

## Testing Strategy

- **Unit tests** for core business logic (extractors, analyzers, verdict engine)
- **Integration tests** for API endpoints (mocked external services)
- **Sample data** in `samples/` for manual testing without API keys
- **CI/CD** runs Ruff linting, MyPy type checking, and pytest on every push
