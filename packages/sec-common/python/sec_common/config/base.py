"""Base Settings for sec-toolkit apps.

Apps subclass `BaseAppSettings` and add their own keys plus an app-specific
`model_config` that sets `env_file`. Shared external-API keys (VirusTotal,
AbuseIPDB, Shodan, URLScan, OTX, SecurityTrails, Censys) live here so both
SOC and OSINT toolkits pick them up from a single `.env`.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class BaseAppSettings(BaseSettings):
    # Subclasses should override model_config to set env_file; this default
    # keeps extra vars (e.g. VITE_API_URL shared with the frontend) from
    # breaking Settings initialization.
    model_config = SettingsConfigDict(
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Environment
    app_env: str = "development"

    # Shared external-threat-intel API keys (used by any sec-toolkit app)
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    shodan_api_key: str = ""
    urlscan_api_key: str = ""
    otx_api_key: str = ""

    # OSINT / IOC pivoting API keys.
    # SecurityTrails follows the single-key pattern; Censys requires both
    # an ID and a secret, so it gets a dedicated `has_censys()` helper.
    securitytrails_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""

    # Investigative OSINT - HIBP requires a paid subscription key (~$3.95/mo)
    # since v3. The breach module degrades cleanly when missing: clients
    # without a key still get a well-formed response explaining the limitation.
    hibp_api_key: str = ""

    # Optional shared secret that gates every /api/* route except the
    # exempt probes (see `ApiKeyMiddleware`). Empty by default - the
    # toolkit is unauth by default, which is the right call for a
    # localhost dev instance. Set this in .env for anything exposed
    # beyond loopback.
    api_key: str = ""

    # JWT-based per-user auth. When `auth_secret` is empty, the auth
    # middleware is a no-op (dev-friendly default). Set a 32+ byte random
    # secret in .env and a first admin can be created via the signup
    # endpoint - after which signup is disabled and only login works.
    auth_secret: str = ""
    auth_token_ttl_minutes: int = 60
    # Relative path resolved against the backend working directory -
    # ends up alongside the SQLite cache/DB in the `data/` volume.
    auth_users_file: str = "data/users.json"

    def has_auth(self) -> bool:
        """Per-user auth is enabled when a signing secret is configured.

        Minimum 32 bytes - RFC 7518 §3.2 recommendation for HS256. Shorter
        secrets are treated as "auth disabled" to fail loud on a stub value.
        """
        return bool(self.auth_secret) and len(self.auth_secret) >= 32

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"

    def has_api_key(self, service: str) -> bool:
        """True when a configured key exists and isn't a placeholder.

        The `your_*` prefix is the convention in .env.example - treating
        those as unset prevents shipping a half-configured instance.
        """
        key = getattr(self, f"{service}_api_key", "")
        return bool(key) and not key.startswith("your_")

    def get_api_key(self, service: str) -> str:
        """Effective API key, or empty string when unset/placeholder.

        Lets call sites pass the key directly to injected clients without
        re-checking `has_api_key` - the client just sees "" when nothing
        real is configured.
        """
        return getattr(self, f"{service}_api_key", "") if self.has_api_key(service) else ""

    def has_censys(self) -> bool:
        """Censys needs both ID and secret - convenience check."""
        return (
            bool(self.censys_api_id)
            and not self.censys_api_id.startswith("your_")
            and bool(self.censys_api_secret)
            and not self.censys_api_secret.startswith("your_")
        )
