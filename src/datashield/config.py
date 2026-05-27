from __future__ import annotations

from pydantic_settings import BaseSettings


class DataShieldSettings(BaseSettings):
    model_config = {
        "env_prefix": "DATASHIELD_",
        "env_file": ".env",
        "extra": "forbid",
    }

    debug: bool = False
    threshold: float = 0.0
    exclude_fields: list[str] = []
    default_epsilon: float = 1.0
    default_k: int = 5
    mcpscop_url: str | None = None
    mcpscop_api_key: str | None = None
    max_size_mb: int = 500


settings = DataShieldSettings()
