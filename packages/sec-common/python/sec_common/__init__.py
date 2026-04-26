"""sec-common: shared primitives for sec-toolkit apps.

Exposes HTTP client + rate limiting, SQLite response cache, IOC extraction
helpers, and configurable clients for external security APIs (VirusTotal,
AbuseIPDB, Shodan, URLScan, MalwareBazaar, AlienVault OTX).

Consumed by `soc-toolkit` and the forthcoming `osint-toolkit`.
"""

__version__ = "0.1.0"
