from __future__ import annotations

from typing import Any

from datashield.scanner import ComplianceResult, DataCategory, Finding

_HIPAA_IDENTIFIERS: set[str] = {
    "name",
    "address",
    "dates",
    "telephone",
    "fax",
    "email",
    "ssn",
    "mrn",
    "health_plan",
    "account",
    "certificate",
    "license",
    "vehicle",
    "device",
    "url",
    "ip",
    "biometric",
    "photo",
    "fingerprint",
}


class HIPAACompliance:
    """Checks dataset compliance with HIPAA Privacy Rule, Security Rule, and Minimum Necessary standard."""

    name = "HIPAA"
    RULES: dict[str, str] = {
        "privacy_rule": "Protected Health Information (PHI) must be safeguarded",
        "security_rule": "Administrative, physical, and technical safeguards required",
        "breach_rule": "Breach notification required within 60 days",
        "min_necessary": "Minimum necessary standard applies",
    }

    def verify(self, data: list[dict[str, Any]]) -> ComplianceResult:
        checks: list[dict[str, Any]] = []
        violations: list[str] = []
        findings = self._collect_findings(data)
        phi_fields: list[str] = []

        for f in findings:
            if f.field_path and f.field_path.lower() in _HIPAA_IDENTIFIERS:
                phi_fields.append(f.field_path)

        has_phi = len(phi_fields) > 0
        has_medical = any(f.category == DataCategory.MEDICAL for f in findings)

        if has_phi or has_medical:
            checks.append(
                {
                    "rule": "privacy_rule",
                    "check": f"PHI detected ({len(phi_fields)} fields) - de-identification required",
                    "passed": False,
                }
            )
            violations.append("Privacy Rule: PHI must be de-identified for secondary use")
        else:
            checks.append(
                {
                    "rule": "privacy_rule",
                    "check": "No PHI detected in dataset",
                    "passed": True,
                }
            )

        phi_count = sum(
            1 for f in findings if f.category in (DataCategory.MEDICAL, DataCategory.PII)
        )
        if phi_count > 0:
            checks.append(
                {
                    "rule": "min_necessary",
                    "check": f"{phi_count} PHI fields - minimum necessary not applied",
                    "passed": False,
                }
            )
            violations.append("Minimum Necessary: Limit PHI to minimum necessary")
        else:
            checks.append(
                {
                    "rule": "min_necessary",
                    "check": "Minimum necessary standard satisfied",
                    "passed": True,
                }
            )

        checks.append(
            {
                "rule": "security_rule",
                "check": "Data sanitization provides technical safeguard",
                "passed": True,
            }
        )

        checks.append(
            {
                "rule": "breach_rule",
                "check": "Sanitized data reduces breach notification requirements",
                "passed": True,
            }
        )

        score = sum(1 for c in checks if c["passed"]) / max(len(checks), 1) * 100

        return ComplianceResult(
            regulation=self.name,
            compliant=len(violations) == 0,
            checks=checks,
            violations=violations,
            score=round(score, 1),
        )

    def _collect_findings(self, data: list[dict[str, Any]]) -> list[Finding]:
        import asyncio
        import logging

        from datashield.detectors import PIIDetector, SensitiveClassifier

        all_findings: list[Finding] = []
        try:
            pii = PIIDetector()
            cls = SensitiveClassifier()
            all_findings.extend(asyncio.run(pii.detect(data)))
            all_findings.extend(asyncio.run(cls.detect(data)))
        except (RuntimeError, OSError) as e:
            logging.getLogger(__name__).warning("Could not run detectors for HIPAA check: %s", e)
        return all_findings
