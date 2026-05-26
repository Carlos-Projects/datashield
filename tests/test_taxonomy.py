from __future__ import annotations

from mcp_taxonomy.core import (
    AttackCategory,
    DetectionMethod,
    TaxonomyEvent,
)

from datashield.scanner import (
    Confidence,
    DataCategory,
    DetectorType,
    Finding,
    Severity,
)
from datashield.taxonomy import datashield_finding_to_taxonomy


class TestTaxonomyAdapter:
    def test_pii_finding_to_taxonomy(self):
        finding = Finding(
            detector="pii_detector",
            detector_type=DetectorType.PII,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Email detected",
            description="Found email in field",
            field_path="user.email",
            value="user@test.com",
            category=DataCategory.PII,
            recommendation="Remove email",
            snippet="user@test.com",
        )
        event = datashield_finding_to_taxonomy(finding)
        assert isinstance(event, TaxonomyEvent)
        assert event.source == "datashield"
        assert event.attack_category == AttackCategory.INJECTION
        assert event.detection_method == DetectionMethod.HIDDEN_TEXT

    def test_secret_finding_to_taxonomy(self):
        finding = Finding(
            detector="secret_scanner",
            detector_type=DetectorType.SECRET,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            title="API Key found",
            description="Found API key",
            field_path="config.api_key",
            value="sk-1234",
            category=DataCategory.CREDENTIAL,
        )
        event = datashield_finding_to_taxonomy(finding)
        assert event.attack_category == AttackCategory.TOOL_POISONING
        assert event.detection_method == DetectionMethod.INJECTION_PATTERNS

    def test_medical_finding_to_taxonomy(self):
        finding = Finding(
            detector="sensitive_classifier",
            detector_type=DetectorType.CLASSIFIER,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            title="Medical data",
            description="Medical data found",
            field_path="patient.diagnosis",
            value="diabetes",
            category=DataCategory.MEDICAL,
        )
        event = datashield_finding_to_taxonomy(finding)
        assert event.attack_category == AttackCategory.POLICY_VIOLATION
        assert event.detection_method == DetectionMethod.INSTRUCTION_CLASSIFIER

    def test_dict_input(self):
        finding_dict = {
            "detector": "pattern_matcher",
            "detector_type": DetectorType.PATTERN.value,
            "severity": Severity.LOW.value,
            "confidence": Confidence.LOW.value,
            "title": "IP address",
            "description": "IP found",
            "field_path": "ip",
            "value": "192.168.1.1",
            "category": DataCategory.LOCATION.value,
        }
        event = datashield_finding_to_taxonomy(finding_dict)
        assert event.source == "datashield"
        assert isinstance(event, TaxonomyEvent)

    def test_unknown_category_default(self):
        from datashield.scanner import DataCategory

        finding = Finding(
            detector="test",
            detector_type=DetectorType.PATTERN,
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            title="Test",
            description="Test",
            category=DataCategory.OTHER,
        )
        event = datashield_finding_to_taxonomy(finding)
        assert event.attack_category == AttackCategory.ANOMALY

    def test_risk_score_computed(self):
        finding = Finding(
            detector="test",
            detector_type=DetectorType.PATTERN,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            title="Critical",
            description="Critical finding",
            category=DataCategory.PII,
        )
        event = datashield_finding_to_taxonomy(finding)
        assert event.risk_score > 0
