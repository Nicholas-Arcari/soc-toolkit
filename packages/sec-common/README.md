# sec-common

[![CI](https://github.com/Nicholas-Arcari/soc-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/Nicholas-Arcari/soc-toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

Shared primitives used by both [`soc-toolkit`](../soc-toolkit/) and
[`osint-toolkit`](../osint-toolkit/). Pulled out of the original
`backend/` so new apps (and community forks) can reuse it without coupling
to SOC-specific code.

## What's inside

- **`http/base_client.py`** - `BaseAPIClient` with per-client token-bucket
  rate limiting, shared `httpx.AsyncClient`, and an opinionated degraded
  path when an API key is missing. Every integration in the repo extends
  it.
- **`cache/db.py`** - Disk-backed response cache keyed on
  `(service, query_type, query_value)`. Async SQLAlchemy. Survives restarts
  so reruns don't burn rate-limit budget.
- **`ioc/`** - Regex extractor + validator. Accepts raw text, returns a
  typed list of IOCs (ipv4, domain, url, email, md5/sha1/sha256, cve).
- **`integrations/`** - VirusTotal, AbuseIPDB, Shodan, URLScan, OTX,
  MalwareBazaar, crt.sh, SecurityTrails, ipwhois, Team Cymru, HIBP.
  Every integration has a documented degraded mode - missing API keys
  return a structured empty/error response, never raise.
- **`config/base.py`** - `BaseSettings` scaffold + `has_api_key` helper
  that downstream apps extend with their own settings.

## Using it

`sec-common` ships `py.typed`, so downstream apps get its types for free.

```python
from sec_common.http import BaseAPIClient
from sec_common.cache import ResponseCache
from sec_common.ioc import extract_from_text
from sec_common.integrations import VirusTotalClient
```

Everything is `async`. The cache is process-safe; the rate limiter is
per-client, so two integrations with different quotas don't starve each
other.

## Development

```bash
cd packages/sec-common/python
poetry install
poetry run ruff check .
poetry run mypy .
poetry run pytest -q
```

Target coverage is **≥70%**. Mock network I/O with `respx` - CI has no
API keys, so any test that hits a real endpoint will flake.

## Adding a new integration

See [`CONTRIBUTING.md`](../../CONTRIBUTING.md#adding-a-new-integration)
at the repo root for the checklist (rate limit, degraded mode,
`.env.example` entry, tests).

## License

MIT - see [LICENSE](../../LICENSE).
