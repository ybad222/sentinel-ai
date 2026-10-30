"""Centralised configuration, loaded from the environment (12-factor app)."""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[3]


class LLMBackend(StrEnum):
    OLLAMA = "ollama"
    OPENAI = "openai"  # OpenAI or any OpenAI-compatible API
    AZURE_OPENAI = "azure_openai"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ROOT / ".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- General -----------------------------------------------------------
    env: str = "dev"
    debug: bool = False
    data_dir: Path = ROOT / "data"

    # --- LLM ---------------------------------------------------------------
    llm_backend: LLMBackend = LLMBackend.OLLAMA
    llm_model: str = "qwen2.5:3b"
    llm_temperature: float = 0.0
    llm_max_tokens: int = 1024
    llm_num_ctx: int = 8192
    llm_timeout_s: int = 180
    ollama_base_url: str = "http://localhost:11434"
    embedding_model: str = "nomic-embed-text"

    openai_api_key: SecretStr | None = None
    openai_base_url: str | None = None
    azure_openai_endpoint: str | None = None
    azure_openai_api_key: SecretStr | None = None
    azure_openai_deployment: str = "gpt-4o-mini"
    azure_openai_api_version: str = "2024-10-21"

    # --- Threat intelligence ----------------------------------------------
    abuseipdb_api_key: SecretStr | None = None
    virustotal_api_key: SecretStr | None = None
    otx_api_key: SecretStr | None = None
    intel_cache_ttl_s: int = 3600

    # --- Infrastructure ----------------------------------------------------
    redis_url: str = "redis://localhost:6379/0"
    wazuh_alerts_file: Path = ROOT / "data" / "alerts" / "wazuh_alerts.jsonl"

    # --- Security ----------------------------------------------------------
    jwt_secret: SecretStr = SecretStr("CHANGE_ME_dev_only")
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    audit_hmac_key: SecretStr = SecretStr("CHANGE_ME_audit_dev_only")
    allowed_origins: list[str] = ["http://localhost:8501"]

    # --- Agent autonomy policy --------------------------------------------
    # 0 = observe only | 1 = recommend (default) | 2 = auto low-risk | 3 = full auto (never in prod)
    autonomy_level: int = Field(default=1, ge=0, le=3)
    require_approval_above_risk: int = 40
    agent_max_iterations: int = 6

    # --- Observability -----------------------------------------------------
    log_level: str = "INFO"
    log_json: bool = True

    @model_validator(mode="after")
    def _no_default_secrets_in_prod(self) -> Settings:
        if self.env == "prod":
            for name in ("jwt_secret", "audit_hmac_key"):
                if getattr(self, name).get_secret_value().startswith("CHANGE_ME"):
                    raise ValueError(f"{name} must be set to a real secret in prod")
            if self.autonomy_level > 2:
                raise ValueError("autonomy_level 3 is forbidden in prod")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
