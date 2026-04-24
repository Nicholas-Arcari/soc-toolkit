from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file="../.env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    app_env: str = "development"
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

    # API Keys
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    shodan_api_key: str = ""
    urlscan_api_key: str = ""
    otx_api_key: str = ""
    # MISP is tenant-specific (self-hosted), so URL + key live together.
    # verify_tls defaults to True; set to False only for lab instances with
    # self-signed certificates - never for production MISPs.
    misp_url: str = ""
    misp_api_key: str = ""
    misp_verify_tls: bool = True

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"

    def has_api_key(self, service: str) -> bool:
        key = getattr(self, f"{service}_api_key", "")
        return bool(key) and not key.startswith("your_")

    def has_misp(self) -> bool:
        """MISP needs both URL and API key - convenience check."""
        return bool(self.misp_url) and self.has_api_key("misp")


settings = Settings()
