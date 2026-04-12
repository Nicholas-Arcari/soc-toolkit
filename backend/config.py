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
    app_host: str = "0.0.0.0"
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

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"

    def has_api_key(self, service: str) -> bool:
        key = getattr(self, f"{service}_api_key", "")
        return bool(key) and not key.startswith("your_")


settings = Settings()
