# Examples

Canonical inputs for every workflow in the toolkit. Use these to take the
apps for a test drive without collecting your own samples.

## Phishing analyzer

```bash
cd packages/soc-toolkit/backend
poetry run python cli.py phishing ../../../packages/soc-toolkit/samples/emails/phishing_sample.eml
poetry run python cli.py phishing ../../../packages/soc-toolkit/samples/emails/legitimate_sample.eml
```

Or via the web UI: http://localhost:3000/phishing and upload one of the
`.eml` files from `packages/soc-toolkit/samples/emails/`.

## Log analyzer

```bash
poetry run python cli.py logs ../../../packages/soc-toolkit/samples/logs/auth.log --log-type ssh
poetry run python cli.py logs ../../../packages/soc-toolkit/samples/logs/access.log --log-type web
poetry run python cli.py logs ../../../packages/soc-toolkit/samples/logs/windows_security.log --log-type windows
```

- `auth.log` - 28-line SSH brute force from `203.0.113.42`, triggers MITRE `T1110`.
- `access.log` - mixed SQLi + path traversal attempts.
- `windows_security.log` - Event 4625 + 7045 pattern (failed logons + service install).

## IOC extractor

```bash
poetry run python cli.py ioc ../../../packages/soc-toolkit/samples/reports/threat_report_sample.txt
```

Sample report contains 20 IOCs: 3 IPv4, 9 domains, 1 URL, 2 emails, 2
SHA256, 1 MD5, 2 CVEs. Use this to validate the extractor before feeding
real threat-intel reports.

## Sigma detection

Sample event files live in [`sigma_events/`](sigma_events/). Paste them
into the **Sigma** page's JSON evaluator (the app pre-fills an SSH login
event; swap it out with the files here to test additional detectors).

- [`ssh_bruteforce.json`](sigma_events/ssh_bruteforce.json) - ten failed
  SSH logons from the same source within 60s.
- [`web_sqli.json`](sigma_events/web_sqli.json) - access log entry
  matching a classic `UNION SELECT` pattern.
- [`windows_persistence.json`](sigma_events/windows_persistence.json) -
  Event ID 7045 (new service installed).

## OSINT requests

Copy-paste curl invocations to exercise every OSINT endpoint end-to-end.
See [`osint_requests/README.md`](osint_requests/README.md).

## Want to contribute samples?

PRs welcome - the only rule is that samples must be **sanitized**. No
real victim PII, no live malware binaries (use hashes/domains only), no
API keys even if expired. See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for
the rest.
