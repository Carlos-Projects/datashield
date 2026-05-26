from __future__ import annotations

import json

import pytest

from datashield.reporters.console import ConsoleReporter
from datashield.reporters.html import HTMLReporter
from datashield.reporters.json import JSONReporter
from datashield.scanner import (
    ComplianceResult,
    Confidence,
    DataCategory,
    DetectorType,
    Finding,
    ScanReport,
    Severity,
)


@pytest.fixture
def sample_report():
    return ScanReport(
        source="test",
        total_records=2,
        total_findings=2,
        findings=[
            Finding(
                detector="pii",
                detector_type=DetectorType.PII,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Email detected",
                description="Found email",
                field_path="email",
                value="user@test.com",
                category=DataCategory.PII,
                recommendation="Remove email",
            ),
            Finding(
                detector="secret",
                detector_type=DetectorType.SECRET,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                title="API Key",
                description="Found key",
                field_path="api_key",
                value="sk-1234",
                category=DataCategory.CREDENTIAL,
                recommendation="Rotate key",
            ),
        ],
        risk_score=45.0,
        risk_category="high",
        summary={"high": 1, "critical": 1},
    )


class TestJSONReporter:
    def test_render(self, sample_report):
        reporter = JSONReporter()
        output = reporter.render(sample_report)
        parsed = json.loads(output)
        assert parsed["metadata"]["risk_score"] == 45.0
        assert parsed["metadata"]["total_findings"] == 2
        assert len(parsed["findings"]) == 2
        assert parsed["findings"][0]["title"] == "Email detected"

    def test_empty_report(self):
        report = ScanReport()
        reporter = JSONReporter()
        output = reporter.render(report)
        parsed = json.loads(output)
        assert parsed["metadata"]["total_findings"] == 0
        assert parsed["findings"] == []


class TestHTMLReporter:
    def test_render_high(self, sample_report):
        reporter = HTMLReporter()
        output = reporter.render(sample_report)
        assert "DataShield" in output
        assert "Email detected" in output
        assert "API Key" in output
        assert "45.0" in output

    def test_render_critical_category(self):
        report = ScanReport(risk_score=85, risk_category="critical")
        output = HTMLReporter().render(report)
        assert "85" in output
        assert "CRITICAL" in output

    def test_render_medium_category(self):
        report = ScanReport(risk_score=35, risk_category="medium")
        output = HTMLReporter().render(report)
        assert "35" in output
        assert "MEDIUM" in output

    def test_render_low_category(self):
        report = ScanReport(risk_score=10, risk_category="low")
        output = HTMLReporter().render(report)
        assert "10" in output
        assert "LOW" in output

    def test_render_safe_category(self):
        report = ScanReport(risk_score=0, risk_category="safe")
        output = HTMLReporter().render(report)
        assert "0/100" in output
        assert "SAFE" in output

    def test_empty_report(self):
        reporter = HTMLReporter()
        output = reporter.render(ScanReport())
        assert "DataShield" in output
        assert "0/100" in output

    def test_report_with_findings(self):
        report = ScanReport(
            risk_score=10,
            risk_category="low",
            findings=[
                Finding(
                    detector="t",
                    detector_type=DetectorType.PATTERN,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    title="Test",
                    description="Desc",
                    field_path="x",
                    value="v",
                    category=DataCategory.OTHER,
                    recommendation="Fix it",
                ),
            ],
        )
        output = HTMLReporter().render(report)
        assert "Test" in output
        assert "Fix it" in output


class TestConsoleReporter:
    def test_render(self, sample_report):
        reporter = ConsoleReporter()
        reporter.render(sample_report)

    def test_empty_report(self):
        reporter = ConsoleReporter()
        reporter.render(ScanReport())

    def test_report_anonymization_satisfied(self):
        reporter = ConsoleReporter()
        reporter.report_anonymization(
            epsilon=1.0,
            k=5,
            epsilon_estimate=1.5,
            dp_modified=10,
            k_satisfied=True,
        )

    def test_report_anonymization_not_satisfied(self):
        reporter = ConsoleReporter()
        reporter.report_anonymization(
            epsilon=0.5,
            k=10,
            epsilon_estimate=0.8,
            dp_modified=5,
            k_satisfied=False,
        )

    def test_report_compliance_all_pass(self):
        reporter = ConsoleReporter()
        results = [
            ComplianceResult(
                regulation="GDPR",
                compliant=True,
                checks=[{"article": "art_5", "check": "OK", "passed": True}],
                violations=[],
                score=100.0,
            ),
        ]
        reporter.report_compliance(results)

    def test_report_compliance_with_violations(self):
        reporter = ConsoleReporter()
        results = [
            ComplianceResult(
                regulation="HIPAA",
                compliant=False,
                checks=[{"rule": "privacy", "check": "PHI found", "passed": False}],
                violations=["PHI detected"],
                score=25.0,
            ),
        ]
        reporter.report_compliance(results)

    def test_report_compliance_mixed(self):
        reporter = ConsoleReporter()
        results = [
            ComplianceResult(
                regulation="GDPR",
                compliant=True,
                checks=[],
                violations=[],
                score=100.0,
            ),
            ComplianceResult(
                regulation="HIPAA",
                compliant=False,
                checks=[],
                violations=["Violation"],
                score=50.0,
            ),
        ]
        reporter.report_compliance(results)
