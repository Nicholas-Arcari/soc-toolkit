# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Per-user JWT authentication.** `sec-common` now ships an
  `auth/` module (PyJWT + bcrypt) with a first-run signup flow,
  `/api/auth/{login,signup,me,logout}` routes, and a React
  `AuthProvider` that wraps both toolkits. Disabled by default -
  set `AUTH_SECRET` in `.env` to opt in.
- **Prometheus metrics.** Every backend exposes `/metrics` with
  request counter, in-flight gauge and latency histogram keyed on
  templated routes. Grafana dashboard JSON at
  `docs/grafana/sec-toolkit-overview.json`.
- **Playwright E2E smoke tests.** New `e2e/` workspace drives both
  UIs against the running compose stack; `e2e-smoke` CI job boots
  `--profile all` and uploads the HTML report on failure.
- **Demo seed + screenshot guide.** `scripts/seed-demo.sh` populates
  a known demo state (SOC samples analysed, OSINT target created +
  scanned) so README screenshots stay reproducible. Convention
  documented in `docs/regenerating-screenshots.md`.
- **Supply-chain hardening for releases.** Tagged builds now sign
  each published image with cosign keyless, emit a SLSA build-L2
  provenance attestation, and attach a buildx SBOM attestation
  alongside the existing SPDX release asset. Verification recipes
  in `SECURITY.md`.

## [0.1.0] - 2026-04-22

First public release. The repository started life as a single FastAPI +
React SOC-analyst app and has been reshaped into a three-workspace
monorepo. Users of the pre-monorepo layout: the `backend/` and
`frontend/` you used to run now live under `packages/soc-toolkit/`.

### Added - `sec-common`

Shared library used by both toolkits. Extracted out of the original
`backend/` so new apps (and community forks) can reuse it without
coupling to SOC-specific code.

- `BaseAPIClient` with per-client token-bucket rate limiting.
- Disk-backed response cache keyed on `(service, query_type, query_value)`.
- IOC regex extractor + validator (`extract_from_text`).
- Integrations: VirusTotal, AbuseIPDB, Shodan, URLScan, OTX,
  MalwareBazaar, crt.sh, SecurityTrails, ipwhois, Team Cymru, HIBP.
- Every integration has a documented degraded mode - missing API keys
  return a structured empty/error response, never raise.

### Added - `soc-toolkit`

Blue-team analyst app. Frontend pages for every backend route it
exposes:

- **Phishing Analyzer** - upload `.eml`, get verdict, indicators, URL
  triage, attachment hash + YARA verdict.
- **Log Analyzer** - SSH / web / Windows parsers with alert aggregation,
  MITRE technique mapping, IP geo enrichment.
- **IOC Extractor** - paste/upload text, get typed IOC list with
  per-type enrichment (VT, AbuseIPDB, OTX).
- **IOC Pivot** - drill down a single indicator across CT logs, passive
  DNS, WHOIS history, reverse DNS, ASN, Shodan, Censys.
- **YARA Scanner** - file upload + rule-match surface with severity,
  MITRE technique, reference links.
- **Sigma Detection** - rule library inspector + JSON event evaluator.
- **MISP Enrichment** - paste text, extract IOCs, flag which ones MISP
  already knows.
- PDF report export (WeasyPrint) for phishing and log analysis results.

### Added - `osint-toolkit`

Attack-surface management + investigative OSINT, a second app with a
different paradigm: stateful targets, scan history, findings that
outlive scans.

- **Target registry** - authorized perimeters with a scope-filter that
  rejects neighbor domains server-side. Authorization flag cannot be
  revoked via PATCH.
- **Passive subdomain enumeration** - merges crt.sh + SecurityTrails
  (if keyed), scope-filtered, first/last-seen tracking on re-scan.
- **DNS mapping** - resolves A / AAAA / MX / NS / TXT per scope root,
  parses SPF/DMARC, emits findings for missing/permissive policies.
- **Service discovery** - Shodan IP lookup per resolved subdomain with
  IP deduplication; CVEs surface as both Service metadata and
  high-severity findings.
- **Investigate** - a second persona workflow:
  - Username search across 12 curated platforms (Sherlock-style HTTP
    probes, absence-marker classification).
  - HIBP breach lookup (account + domain) with degraded mode.
  - EXIF/GPS extraction via Pillow, DMS → decimal with altitude sign.
  - Entity graph (`react-cytoscapejs`) populated from every response.
- **Passive-by-default** - active scanning (Amass/Subfinder) is gated
  behind `OSINT_ENABLE_ACTIVE_SCANNING`, default false.

### Added - infrastructure

- Poetry + npm workspaces, `docker-compose` with `soc` and `osint`
  profiles for selective stack bring-up.
- GitHub Actions matrix CI with `dorny/paths-filter@v3` - only the
  workspaces that changed run. Separate coverage gates per workspace
  (`sec-common` 70%, `osint-toolkit` 50%, `soc-toolkit` 30%).
- Alembic migrations for `osint-toolkit` persistent state
  (`targets / scans / subdomains / services / findings`). CI verifies
  migrations apply cleanly against a fresh DB.
- Strict mypy across every workspace. `sec-common` ships `py.typed`
  so downstream apps get its types.

### Security + ethics

- `ETHICS.md` sits next to `osint-toolkit/README.md` with the
  authorization gate the toolkit enforces plus pointers to the legal
  framework (GDPR Art. 6, L. 547/1993, art. 615-ter c.p., CFAA).
- Create-target server-side rejects `authorized_to_scan: false`, so
  bypassing the UI checkbox doesn't bypass the gate.
- Every integration degrades cleanly without keys - an install without
  any API key stays functional, it just returns empty enrichment.

[Unreleased]: https://github.com/Nicholas-Arcari/soc-toolkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Nicholas-Arcari/soc-toolkit/releases/tag/v0.1.0
