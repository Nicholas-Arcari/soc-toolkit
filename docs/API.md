# API Reference

Base URL: `http://localhost:8000/api`

Interactive documentation available at `/api/docs` (Swagger UI) and `/api/redoc` (ReDoc).

## Authentication

No authentication required for local usage. API keys for external services (VirusTotal, AbuseIPDB, etc.) are configured via `.env` file.

## Endpoints

### Health Check

```
GET /api/health
```

Returns system status and configured API integrations.

**Response:**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "configured_apis": ["virustotal", "abuseipdb", "shodan"]
}
```

---

### Phishing Analyzer

#### Analyze Email

```
POST /api/phishing/analyze
Content-Type: multipart/form-data
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `file` | File (.eml) | Email file to analyze |

**Response:**
```json
{
  "verdict": "MALICIOUS",
  "confidence": 0.92,
  "risk_score": 85,
  "headers": {
    "from": "attacker@evil.com",
    "spf": { "status": "fail" },
    "dkim": { "status": "fail" },
    "dmarc": { "status": "fail" },
    "suspicious_indicators": ["Return-Path mismatch", "SPF fail"]
  },
  "urls": [
    {
      "url": "https://evil.tk/phish",
      "malicious": true,
      "suspicious_patterns": ["Suspicious TLD"]
    }
  ],
  "attachments": [
    {
      "filename": "invoice.pdf.exe",
      "malicious": true,
      "hashes": { "sha256": "abc123..." }
    }
  ],
  "indicators": ["Malicious URL detected", "Double extension attachment"],
  "recommendations": ["Do NOT click any links", "Report to security team"]
}
```

Verdicts: `CLEAN` | `CAUTIOUS` | `SUSPICIOUS` | `MALICIOUS`

#### Check Single URL

```
POST /api/phishing/check-url?url=https://example.com
```

---

### Log Analyzer

#### Analyze Log File

```
POST /api/logs/analyze?log_type=auto
Content-Type: multipart/form-data
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `file` | File | Log file to analyze |
| `log_type` | Query string | `auto`, `ssh`, `apache`, `nginx`, `windows` |

**Response:**
```json
{
  "log_type": "ssh",
  "total_lines": 500,
  "suspicious_entries": 47,
  "alerts": [
    {
      "severity": "high",
      "message": "Brute force detected: 150 attempts from 45.33.32.156",
      "source_ip": "45.33.32.156",
      "geo": {
        "country": "US",
        "isp": "Linode",
        "abuse_score": 85
      },
      "count": 150,
      "mitre_technique": "T1110 - Brute Force"
    }
  ],
  "top_ips": [
    { "ip": "45.33.32.156", "attempts": 150 }
  ],
  "timeline": [
    { "hour": "06", "count": 45 },
    { "hour": "07", "count": 2 }
  ],
  "summary": "Total lines: 500 | Failed attempts: 47 | Brute force IPs: 3"
}
```

Alert severities: `info` | `low` | `medium` | `high` | `critical`

---

### IOC Extractor

#### Extract from File

```
POST /api/ioc/extract
Content-Type: multipart/form-data
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `file` | File | PDF, .eml, .txt, .html, or .csv file |

**Response:**
```json
{
  "source": "threat_report.pdf",
  "total_iocs": 12,
  "iocs": [
    {
      "type": "ipv4",
      "value": "203.0.113.42",
      "context": "C2 server at 203.0.113.42",
      "enrichment": {
        "virustotal": { "positives": 5, "total": 90 },
        "abuseipdb": { "abuse_score": 95, "country": "NL" }
      },
      "malicious": true
    }
  ],
  "stats": { "ipv4": 3, "domain": 2, "sha256": 4, "url": 2, "cve": 1 }
}
```

IOC types: `ipv4` | `domain` | `url` | `email` | `md5` | `sha1` | `sha256` | `cve`

#### Extract from Text

```
POST /api/ioc/extract-text?text=Check IP 203.0.113.42 and domain evil.com
```

---

### Reports

#### Export Report

```
POST /api/reports/export
Content-Type: application/json
```

**Request body:**
```json
{
  "data": { ... },
  "report_type": "phishing",
  "format": "pdf"
}
```

| Parameter | Values |
|-----------|--------|
| `report_type` | `phishing`, `logs`, `ioc` |
| `format` | `json`, `csv`, `pdf` |

Returns a file download with the appropriate Content-Type.

---

## Error Responses

All errors return JSON:

```json
{
  "detail": "Error message here"
}
```

| Status | Description |
|--------|-------------|
| 400 | Bad request (invalid input) |
| 422 | Validation error (missing required fields) |
| 429 | Rate limit exceeded |
| 500 | Internal server error |

## Rate Limiting

Default: 30 requests per minute per IP. Configurable via `RATE_LIMIT_PER_MINUTE` in `.env`.

Exempt endpoints: `/api/health`, `/api/docs`.
