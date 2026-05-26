from __future__ import annotations

from datashield.config import DataShieldSettings


class TestConfig:
    def test_default_settings(self):
        settings = DataShieldSettings()
        assert settings.debug is False
        assert settings.threshold == 0.0
        assert settings.exclude_fields == []
        assert settings.default_epsilon == 1.0
        assert settings.default_k == 5
        assert settings.mcpscop_url is None
        assert settings.mcpscop_api_key is None

    def test_env_prefix(self):
        assert DataShieldSettings.model_config["env_prefix"] == "DATASHIELD_"

    def test_custom_settings(self):
        settings = DataShieldSettings(
            debug=True,
            threshold=0.5,
            exclude_fields=["internal"],
            default_epsilon=0.1,
            default_k=10,
            mcpscop_url="http://test:8080",
            mcpscop_api_key="key123",
        )
        assert settings.debug is True
        assert settings.threshold == 0.5
        assert settings.exclude_fields == ["internal"]
        assert settings.mcpscop_url == "http://test:8080"
