from pathlib import Path

from pydantic_settings import SettingsConfigDict
from sec_common.config import BaseAppSettings

# Repo root is packages/soc-toolkit/backend/config.py → parents[3]
# Keeping .env at the repo root lets both toolkits share API keys
_REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseAppSettings):
    model_config = SettingsConfigDict(
        env_file=str(_REPO_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_debug: bool = True
    # Binding to 0.0.0.0 is required so the uvicorn process inside the Docker
    # container is reachable from the host network. Container isolation is the
    # security boundary here, not the bind address.
    app_host: str = "0.0.0.0"  # nosec B104
    app_port: int = 8000
    app_secret_key: str = "change-this-to-a-random-secret-key"

    # Database
    database_url: str = "sqlite+aiosqlite:///./soc_toolkit.db"

    # Rate limiting
    rate_limit_per_minute: int = 30

    # MISP is tenant-specific (self-hosted), so URL + key live together.
    # verify_tls defaults to True; set to False only for lab instances with
    # self-signed certificates - never for production MISPs.
    misp_url: str = ""
    misp_api_key: str = ""
    misp_verify_tls: bool = True

    def has_misp(self) -> bool:
        """MISP needs both URL and API key - convenience check."""
        return bool(self.misp_url) and self.has_api_key("misp")


settings = Settings()
