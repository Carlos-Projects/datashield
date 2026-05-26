from __future__ import annotations

import pytest

from datashield.sanitizers.minimizer import Minimizer
from datashield.scanner import Confidence, DataCategory, DetectorType, Finding, Severity


@pytest.fixture
def minimizer():
    return Minimizer()


@pytest.fixture
def pii_finding():
    return Finding(
        detector="pii",
        detector_type=DetectorType.PII,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="Email",
        description="",
        field_path="email",
        value="",
        category=DataCategory.PII,
    )


class TestMinimizer:
    async def test_remove_pii_field(self, minimizer, pii_finding):
        records = [{"email": "user@test.com", "name": "Alice", "id": 1}]
        results = await minimizer.sanitize(records, [pii_finding])
        assert "email" not in results[0].sanitized
        assert "name" in results[0].sanitized
        assert "email" in results[0].removed_fields

    async def test_keep_id_field(self, minimizer, pii_finding):
        records = [{"email": "user@test.com", "id": 1}]
        results = await minimizer.sanitize(records, [pii_finding])
        assert results[0].sanitized.get("id") == 1

    async def test_no_findings_removes_non_kept(self, minimizer):
        records = [{"unnecessary": "data", "id": 1, "name": "Alice"}]
        results = await minimizer.sanitize(records, [])
        assert "unnecessary" in results[0].removed_fields
        assert "id" in results[0].sanitized

    async def test_empty_records(self, minimizer):
        results = await minimizer.sanitize([])
        assert results == []

    async def test_custom_keep_fields(self):
        m = Minimizer(keep_fields={"custom_id"})
        records = [{"custom_id": 1, "email": "a@b.com", "other": "x"}]
        finding = Finding(
            detector="pii",
            detector_type=DetectorType.PII,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Email",
            description="",
            field_path="email",
            value="",
            category=DataCategory.PII,
        )
        results = await m.sanitize(records, [finding])
        assert results[0].sanitized.get("custom_id") == 1
        assert "email" not in results[0].sanitized
