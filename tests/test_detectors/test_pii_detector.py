from __future__ import annotations

import pytest

from datashield.detectors.pii_detector import PIIDetector
from datashield.scanner import DataCategory


@pytest.fixture
def detector():
    return PIIDetector()


class TestPIIDetector:
    async def test_detect_email(self, detector):
        findings = await detector.detect([{"email": "user@domain.com"}])
        assert len(findings) >= 1

    async def test_detect_phone(self, detector):
        findings = await detector.detect([{"phone": "+1-555-123-4567"}])
        assert len(findings) >= 1
        assert any(f.category == DataCategory.PII for f in findings)

    async def test_detect_ssn(self, detector):
        findings = await detector.detect([{"ssn": "123-45-6789"}])
        assert len(findings) >= 1
        assert any("ssn" in f.title.lower() or "social" in f.title.lower() for f in findings)

    async def test_detect_passport(self, detector):
        findings = await detector.detect([{"passport": "AB1234567"}])
        assert len(findings) >= 1

    async def test_detect_national_id(self, detector):
        findings = await detector.detect([{"national_id": "123-456-789-01"}])
        assert len(findings) >= 1

    async def test_no_false_positives(self, detector):
        findings = await detector.detect([{"notes": "This is harmless data", "count": 42}])
        assert len(findings) == 0

    async def test_multiple_records(self, detector):
        records = [
            {"email": "a@b.com"},
            {"email": "c@d.com"},
            {"notes": "clean"},
        ]
        findings = await detector.detect(records)
        emails = [f for f in findings if f.category == DataCategory.PII]
        assert len(emails) >= 2

    async def test_detector_metadata(self, detector):
        assert detector.name == "pii_detector"
        assert detector.detector_type.value == "pii_detector"
