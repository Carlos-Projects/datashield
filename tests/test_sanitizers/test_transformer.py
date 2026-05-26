from __future__ import annotations

import pytest

from datashield.sanitizers.transformer import Transformer
from datashield.scanner import Confidence, DataCategory, DetectorType, Finding, Severity


@pytest.fixture
def transformer():
    return Transformer()


class TestTransformer:
    async def test_transform_pii(self, transformer):
        records = [{"email": "user@example.com"}]
        finding = Finding(
            detector="pii",
            detector_type=DetectorType.PII,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            title="Email",
            description="",
            field_path="email",
            value="",
            category=DataCategory.PII,
        )
        results = await transformer.sanitize(records, [finding])
        assert results[0].sanitized["email"] != "user@example.com"
        assert "email" in results[0].modified_fields

    async def test_transform_credential(self, transformer):
        records = [{"api_key": "sk-1234567890abcdef"}]
        finding = Finding(
            detector="secret",
            detector_type=DetectorType.SECRET,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            title="Key",
            description="",
            field_path="api_key",
            value="",
            category=DataCategory.CREDENTIAL,
        )
        results = await transformer.sanitize(records, [finding])
        assert results[0].sanitized["api_key"] == "[REDACTED]"

    async def test_transform_financial(self, transformer):
        records = [{"card": "4111111111111111"}]
        finding = Finding(
            detector="pattern",
            detector_type=DetectorType.PATTERN,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Card",
            description="",
            field_path="card",
            value="",
            category=DataCategory.FINANCIAL,
        )
        results = await transformer.sanitize(records, [finding])
        assert "XXXX" in results[0].sanitized["card"]

    async def test_no_findings_no_change(self, transformer):
        records = [{"name": "Alice"}]
        results = await transformer.sanitize(records, [])
        assert results[0].sanitized == records[0]

    async def test_custom_transform(self):
        custom = {DataCategory.PII: lambda v: "CUSTOM_" + v}
        t = Transformer(transform_functions=custom)
        records = [{"name": "Alice"}]
        finding = Finding(
            detector="pii",
            detector_type=DetectorType.PII,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            title="Name",
            description="",
            field_path="name",
            value="",
            category=DataCategory.PII,
        )
        results = await t.sanitize(records, [finding])
        assert results[0].sanitized["name"] == "CUSTOM_Alice"
