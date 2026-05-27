from __future__ import annotations

import pytest

from datashield.scanner import (
    BaseDetector,
    BaseSanitizer,
    Confidence,
    DataCategory,
    DetectorType,
    Finding,
    SanitizedRecord,
    Scanner,
    Severity,
)


class _MockDetector(BaseDetector):
    name = "mock"
    detector_type = DetectorType.PATTERN

    async def detect(self, records):
        return [
            Finding(
                detector=self.name,
                detector_type=self.detector_type,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Mock finding",
                description="Test",
                field_path="test_field",
                value="sensitive",
                category=DataCategory.PII,
            )
        ]


class _EmptyDetector(BaseDetector):
    name = "empty"
    detector_type = DetectorType.PATTERN

    async def detect(self, records):
        return []


class _MockSanitizer(BaseSanitizer):
    name = "mock_sanitizer"

    async def sanitize(self, records, findings=None):
        results = []
        for i, record in enumerate(records):
            sanitized = dict(record)
            modified = []
            if "test_field" in sanitized:
                sanitized["test_field"] = "[REDACTED]"
                modified.append("test_field")
            results.append(
                SanitizedRecord(
                    index=i,
                    original=record,
                    sanitized=sanitized,
                    modified_fields=modified,
                    findings=findings or [],
                )
            )
        return results


@pytest.fixture
def sample_records():
    return [
        {"name": "Alice", "email": "alice@example.com", "age": 30},
        {"name": "Bob", "email": "bob@test.com", "ssn": "123-45-6789"},
    ]


class TestScanner:
    async def test_empty_detectors(self):
        scanner = Scanner(detectors=[])
        report = await scanner.scan([{"a": 1}])
        assert report.total_findings == 0
        assert report.risk_score == 0.0

    async def test_single_detector(self):
        scanner = Scanner(detectors=[_MockDetector()])
        report = await scanner.scan([{"test_field": "sensitive"}])
        assert report.total_findings == 1
        assert report.findings[0].title == "Mock finding"

    async def test_multiple_detectors(self):
        scanner = Scanner(detectors=[_MockDetector(), _EmptyDetector()])
        report = await scanner.scan([{"a": 1}])
        assert report.total_findings == 1

    async def test_risk_score_critical(self):
        findings = [
            Finding(
                detector="t",
                detector_type=DetectorType.PATTERN,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                title="Critical",
                description="",
                category=DataCategory.PII,
            )
            for _ in range(3)
        ]
        scanner = Scanner()
        score = scanner.compute_risk_score(findings)
        assert score >= 70

    async def test_risk_score_safe(self):
        scanner = Scanner()
        score = scanner.compute_risk_score([])
        assert score == 0.0

    async def test_risk_category_mapping(self):
        scanner = Scanner()
        assert scanner._risk_category(0) == "safe"
        assert scanner._risk_category(10) == "low"
        assert scanner._risk_category(30) == "medium"
        assert scanner._risk_category(50) == "high"
        assert scanner._risk_category(80) == "critical"

    async def test_single_record_scan(self):
        scanner = Scanner(detectors=[_EmptyDetector()])
        report = await scanner.scan({"single": "record"})
        assert report.total_records == 1

    async def test_with_sanitizer(self):
        scanner = Scanner(
            detectors=[_MockDetector()],
            sanitizers=[_MockSanitizer()],
        )
        report = await scanner.scan([{"test_field": "sensitive"}])
        assert report.total_findings == 1
        assert report.risk_score > 0

    async def test_finding_model_defaults(self):
        f = Finding(
            detector="test",
            detector_type=DetectorType.PATTERN,
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            title="Test",
            description="",
            category=DataCategory.OTHER,
        )
        assert f.id is not None
        assert len(f.id) == 12
        assert f.timestamp is not None
        assert f.metadata == {}


class TestModels:
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.INFO.value == "info"

    def test_confidence_values(self):
        assert Confidence.HIGH.value == "high"
        assert Confidence.LOW.value == "low"

    def test_data_category_values(self):
        assert DataCategory.PII.value == "pii"
        assert DataCategory.MEDICAL.value == "medical"

    def test_detector_type_values(self):
        assert DetectorType.PII.value == "pii_detector"
        assert DetectorType.SECRET.value == "secret_scanner"

    def test_sanitized_record_defaults(self):
        r = SanitizedRecord()
        assert r.index == 0
        assert r.original == {}
        assert r.sanitized == {}
        assert r.removed_fields == []
        assert r.modified_fields == []
        assert r.findings == []
