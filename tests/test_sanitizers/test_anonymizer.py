from __future__ import annotations

import pytest

from datashield.sanitizers.anonymizer import Anonymizer
from datashield.scanner import Confidence, DataCategory, DetectorType, Finding, Severity


@pytest.fixture
def anonymizer():
    return Anonymizer()


@pytest.fixture
def sample_finding():
    return Finding(
        detector="pii_detector",
        detector_type=DetectorType.PII,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        title="Email",
        description="Email found",
        field_path="email",
        value="user@example.com",
        category=DataCategory.PII,
    )


class TestAnonymizer:
    async def test_anonymize_field(self, anonymizer, sample_finding):
        records = [{"email": "user@example.com", "name": "Alice"}]
        results = await anonymizer.sanitize(records, [sample_finding])
        assert len(results) == 1
        assert results[0].sanitized["email"].startswith("ANON_")
        assert results[0].sanitized["name"] == "Alice"
        assert "email" in results[0].modified_fields

    async def test_no_findings_no_changes(self, anonymizer):
        records = [{"name": "Alice", "age": 30}]
        results = await anonymizer.sanitize(records, [])
        assert len(results) == 1
        assert results[0].sanitized == records[0]
        assert results[0].modified_fields == []

    async def test_multiple_records(self, anonymizer):
        records = [{"email": "a@b.com"}, {"email": "c@d.com"}]
        findings = [
            Finding(
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
        ]
        results = await anonymizer.sanitize(records, findings)
        assert len(results) == 2
        assert all(r.sanitized["email"].startswith("ANON_") for r in results)

    async def test_deterministic_anonymization(self, anonymizer):
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
        r1 = await anonymizer.sanitize([{"email": "same@value.com"}], [finding])
        r2 = await anonymizer.sanitize([{"email": "same@value.com"}], [finding])
        assert r1[0].sanitized["email"] == r2[0].sanitized["email"]

    async def test_empty_records(self, anonymizer):
        results = await anonymizer.sanitize([])
        assert results == []
