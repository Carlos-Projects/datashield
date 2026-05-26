from __future__ import annotations

import tempfile
from pathlib import Path

import yaml

from datashield.policies.mcpguard import MCPGuardPolicy, MCPGuardPolicyGenerator
from datashield.scanner import (
    Confidence,
    DataCategory,
    DetectorType,
    Finding,
    ScanReport,
    Severity,
)


class TestMCPGuardPolicy:
    def test_default_policy(self):
        policy = MCPGuardPolicy()
        assert policy.mode == "http"
        assert policy.listen_port == 8080
        assert policy.rate_limit == 100

    def test_generator_from_findings_critical(self):
        gen = MCPGuardPolicyGenerator()
        findings = [
            Finding(
                detector="test",
                detector_type=DetectorType.PATTERN,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                title="Critical",
                description="",
                field_path="exec",
                category=DataCategory.CREDENTIAL,
            ),
        ]
        policy = gen.from_findings(findings)
        assert policy.rate_limit == 30
        assert policy.block_on_poisoning is True
        assert policy.block_on_injection is True

    def test_generator_from_findings_high(self):
        gen = MCPGuardPolicyGenerator()
        findings = [
            Finding(
                detector="test",
                detector_type=DetectorType.PATTERN,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="High",
                description="",
                field_path="delete_",
                category=DataCategory.PII,
            ),
        ]
        policy = gen.from_findings(findings)
        assert policy.rate_limit == 60

    def test_generator_from_findings_low(self):
        gen = MCPGuardPolicyGenerator()
        findings = [
            Finding(
                detector="test",
                detector_type=DetectorType.PATTERN,
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                title="Low",
                description="",
                field_path="test",
                category=DataCategory.OTHER,
            ),
        ]
        policy = gen.from_findings(findings)
        assert policy.rate_limit == 100

    def test_from_scan_report(self):
        gen = MCPGuardPolicyGenerator()
        report = ScanReport(
            total_findings=1,
            findings=[
                Finding(
                    detector="test",
                    detector_type=DetectorType.PATTERN,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    title="Critical",
                    description="",
                    category=DataCategory.SECRET,
                ),
            ],
        )
        policy = gen.from_scan_report(report)
        assert policy.rate_limit == 30

    def test_to_yaml_output(self):
        gen = MCPGuardPolicyGenerator()
        policy = MCPGuardPolicy(
            deny=["exec", "shell"],
            rate_limit=30,
            block_on_injection=True,
        )
        yaml_str = gen.to_yaml(policy)
        parsed = yaml.safe_load(yaml_str)
        assert parsed["deny"] == ["exec", "shell"]
        assert parsed["rate_limit"] == 30
        assert parsed["block_on_injection"] is True

    def test_save_to_file(self):
        gen = MCPGuardPolicyGenerator()
        policy = MCPGuardPolicy(target_url="http://test:8000")
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            path = f.name
        gen.save(path, policy)
        assert Path(path).exists()
        content = Path(path).read_text()
        assert "target_url: http://test:8000" in content
        Path(path).unlink(missing_ok=True)

    def test_custom_policy_params(self):
        policy = MCPGuardPolicy(
            mode="stdio",
            listen_host="0.0.0.0",
            listen_port=9090,
            rate_limit=50,
            rate_window=30,
        )
        assert policy.mode == "stdio"
        assert policy.listen_host == "0.0.0.0"
        assert policy.listen_port == 9090
        assert policy.rate_window == 30
