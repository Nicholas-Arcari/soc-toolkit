"""Base Settings for sec-toolkit apps.

Apps subclass `BaseAppSettings` and add their own keys plus an app-specific
`model_config` that sets `env_file`. Shared external-API keys (VirusTotal,
AbuseIPDB, Shodan, URLScan, OTX, SecurityTrails, Censys) live here so both
SOC and OSINT toolkits pick them up from a single `.env`.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict

from sec_common.runtime_keys import request_api_key_override


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
    # Relative path resolved against the backend working directory - ends up
    # alongside the SQLite cache/DB in the `data/` volume. SQLite-backed; a
    # legacy users.json in the same dir is imported once on first start.
    auth_users_file: str = "data/users.db"
    # Registration posture. "single-tenant" (default) keeps the first-run
    # admin-only flow: the first signup becomes admin, every later signup
    # is rejected - the right call for a self-hosted clone. "saas" opens
    # self-registration: each account after the first admin is a trial
    # user that expires after `trial_days`. Only meaningful on the hosted
    # instance you operate; a clone has no reason to turn it on.
    auth_mode: str = "single-tenant"
    trial_days: int = 7
    # Directory (relative to the backend working dir) for uploaded profile
    # images - sits next to users.json in the data/ volume. Local-disk
    # storage today; swappable for object storage without touching routes.
    avatar_dir: str = "data/avatars"
    # License authority for SaaS paid plans (the separate license-server).
    # Empty = licensing disabled (the right posture for a self-hosted clone).
    # The hosted SaaS instance points these at its license-server.
    license_server_url: str = ""
    license_server_api_key: str = ""
    # Email delivery for verification + password reset. Empty smtp_host keeps
    # dev mode (links are logged via ConsoleEmailSender, not sent).
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "no-reply@soc-toolkit.local"
    smtp_starttls: bool = True
    # Public base URL of the frontend, used to build verification/reset links.
    app_base_url: str = "http://localhost:5173"
    # Brute-force throttle on /login: lock a username after this many failed
    # attempts within the rolling window (seconds).
    login_max_attempts: int = 5
    login_window_seconds: int = 900
    # Per-IP cap on the outbound-fetch endpoints (link tracer, website
    # fingerprint) so the server can't be driven as a scanning proxy.
    outbound_fetch_per_minute: int = 10

    def has_auth(self) -> bool:
        """Per-user auth is enabled when a signing secret is configured.

        Minimum 32 bytes - RFC 7518 §3.2 recommendation for HS256. Shorter
        secrets are treated as "auth disabled" to fail loud on a stub value.
        """
        return bool(self.auth_secret) and len(self.auth_secret) >= 32

    def has_smtp(self) -> bool:
        """Real email delivery is configured (otherwise dev/console mode)."""
        return bool(self.smtp_host)

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"

    def has_api_key(self, service: str) -> bool:
        """True when a usable key exists for ``service``.

        A per-request override (a SaaS user's own key, supplied via header)
        counts; otherwise the configured env key, ignoring the `your_*`
        placeholder convention from .env.example.
        """
        if request_api_key_override(service):
            return True
        key = getattr(self, f"{service}_api_key", "")
        return bool(key) and not key.startswith("your_")

    def get_api_key(self, service: str) -> str:
        """Effective API key, or empty string when unset/placeholder.

        A per-request override wins over the env key, so a SaaS user who
        entered their own keys in the UI uses those without the server ever
        persisting them. Call sites pass the result straight to clients.
        """
        override = request_api_key_override(service)
        if override:
            return override
        if not self.has_api_key(service):
            return ""
        return getattr(self, f"{service}_api_key", "")

    def has_censys(self) -> bool:
        """Censys needs both ID and secret - convenience check."""
        return (
            bool(self.censys_api_id)
            and not self.censys_api_id.startswith("your_")
            and bool(self.censys_api_secret)
            and not self.censys_api_secret.startswith("your_")
        )
