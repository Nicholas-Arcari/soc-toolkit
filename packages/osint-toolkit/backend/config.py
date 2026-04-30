from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import SettingsConfigDict
from sec_common.config import BaseAppSettings

# packages/osint-toolkit/backend/config.py → parents[3] is repo root.
# Shared .env at the root means both toolkits pick up the same API keys
# (VirusTotal, SecurityTrails, Shodan, ...). Scope the rest to this app.
_REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseAppSettings):
    model_config = SettingsConfigDict(
        env_file=str(_REPO_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application - port 8001 / 3001 to avoid collision with soc-toolkit.
    app_debug: bool = True
    app_host: str = "0.0.0.0"  # nosec B104 - container isolation is the real boundary
    app_port: int = 8001
    app_secret_key: str = "change-this-to-a-random-secret-key"

    # Persistent DB - unlike soc-toolkit's disposable cache, target
    # history and scan results are first-class state here. The env var is
    # namespaced (`OSINT_DATABASE_URL`) so the shared `.env` can hold a
    # separate `DATABASE_URL` for soc-toolkit's cache without collision.
    database_url: str = Field(
        default="sqlite+aiosqlite:///./osint_toolkit.db",
        validation_alias="OSINT_DATABASE_URL",
    )

    rate_limit_per_minute: int = 30

    # Active scanning (Amass/Subfinder subprocess) is gated by this
    # flag. Default off: the toolkit is passive-by-default so it's safe
    # to run against targets you don't own. Flipping this to True must
    # be a conscious decision, not an accidental dependency.
    enable_active_scanning: bool = False

    # Optional outbound webhook for severe findings. When set, the
    # toolkit POSTs a JSON payload for every new high/critical finding.
    # Compatible with Slack/Discord/Teams incoming webhook URLs and
    # generic JSON endpoints alike.
    webhook_url: str = Field(default="", validation_alias="OSINT_WEBHOOK_URL")

    @field_validator("database_url")
    @classmethod
    def _ensure_async_driver(cls, value: str) -> str:
        """Force the aiosqlite driver for bare sqlite URLs.

        The app runs on an AsyncEngine (Alembic env + runtime session), so
        `sqlite:///...` would blow up with "pysqlite is not async". We
        quietly upgrade bare sqlite URLs instead of requiring every user to
        remember the `+aiosqlite` suffix in their `.env`.
        """
        if value.startswith("sqlite:///"):
            return value.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
        return value


settings = Settings()
