from __future__ import annotations

import pytest

from datashield.sanitizers.redactor import Redactor
from datashield.scanner import Confidence, DataCategory, DetectorType, Finding, Severity


@pytest.fixture
def redactor():
    return Redactor()


@pytest.fixture
def findings():
    return [
        Finding(
            detector="pii",
            detector_type=DetectorType.PII,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="SSN",
            description="",
            field_path="ssn",
            value="",
            category=DataCategory.PII,
        ),
        Finding(
            detector="secret",
            detector_type=DetectorType.SECRET,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            title="Key",
            description="",
            field_path="api_key",
            value="",
            category=DataCategory.CREDENTIAL,
        ),
    ]


class TestRedactor:
    async def test_redact_fields(self, redactor, findings):
        records = [{"ssn": "123-45-6789", "api_key": "secret123", "name": "Alice"}]
        results = await redactor.sanitize(records, findings)
        assert results[0].sanitized["ssn"] == "[REDACTED]"
        assert results[0].sanitized["api_key"] == "[REDACTED]"
        assert results[0].sanitized["name"] == "Alice"
        assert len(results[0].modified_fields) == 2

    async def test_custom_token(self):
        r = Redactor(redaction_token="***HIDDEN***")
        records = [{"ssn": "123-45-6789"}]
        finding = Finding(
            detector="pii",
            detector_type=DetectorType.PII,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="SSN",
            description="",
            field_path="ssn",
            value="",
            category=DataCategory.PII,
        )
        results = await r.sanitize(records, [finding])
        assert results[0].sanitized["ssn"] == "***HIDDEN***"

    async def test_no_findings_no_change(self, redactor):
        records = [{"name": "Alice"}]
        results = await redactor.sanitize(records, [])
        assert results[0].sanitized == records[0]
        assert results[0].modified_fields == []

    async def test_empty_records(self, redactor):
        results = await redactor.sanitize([])
        assert results == []

    async def test_field_not_present(self, redactor, findings):
        records = [{"name": "Alice"}]
        results = await redactor.sanitize(records, findings)
        assert results[0].sanitized == records[0]
        assert results[0].modified_fields == []
