from __future__ import annotations

import httpx
import pytest

try:
    from mcp_taxonomy.core import TaxonomyEvent  # noqa: F401

    _HAS_MCP_TAXONOMY = True
except ImportError:
    _HAS_MCP_TAXONOMY = False

from datashield.integrations.mcpscop import MCPscopClient
from datashield.scanner import (
    Confidence,
    DataCategory,
    DetectorType,
    Finding,
    ScanReport,
    Severity,
)


class TestMCPscopClient:
    def test_init(self):
        client = MCPscopClient("http://test:8080", api_key="key123")
        assert client.base_url == "http://test:8080"
        assert client.api_key == "key123"

    def test_init_trailing_slash(self):
        client = MCPscopClient("http://test:8080/")
        assert client.base_url == "http://test:8080"

    @pytest.mark.asyncio
    @pytest.mark.skipif(not _HAS_MCP_TAXONOMY, reason="mcp-taxonomy not installed")
    async def test_send_report_connection_error(self):
        client = MCPscopClient("http://localhost:1")
        report = ScanReport(
            total_findings=1,
            findings=[
                Finding(
                    detector="test",
                    detector_type=DetectorType.PATTERN,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title="Test",
                    description="",
                    category=DataCategory.PII,
                ),
            ],
        )
        with pytest.raises(httpx.ConnectError):
            await client.send_report(report)
        await client.close()

    @pytest.mark.skipif(not _HAS_MCP_TAXONOMY, reason="mcp-taxonomy not installed")
    def test_event_shape(self):
        from datashield.taxonomy import datashield_finding_to_taxonomy

        finding = Finding(
            detector="pii",
            detector_type=DetectorType.PII,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Email",
            description="Email found",
            field_path="user.email",
            value="test@test.com",
            category=DataCategory.PII,
        )
        event = datashield_finding_to_taxonomy(finding)
        assert event.source == "datashield"
        assert event.attack_category.value == "injection"
        assert event.severity.value == "high"
