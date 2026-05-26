from __future__ import annotations

from typing import Any

from datashield.scanner import ComplianceResult, DataCategory, Finding


class GDPRCompliance:
    name = "GDPR"
    ARTICLES: dict[str, str] = {
        "art_5": "Personal data shall be processed lawfully, fairly and transparently",
        "art_17": "Right to erasure ('right to be forgotten')",
        "art_20": "Right to data portability",
        "art_25": "Data protection by design and by default",
        "art_32": "Security of processing",
        "art_33": "Notification of a personal data breach",
        "art_35": "Data protection impact assessment",
    }
    SPECIAL_CATEGORIES: set[DataCategory] = {
        DataCategory.PERSONAL,
        DataCategory.MEDICAL,
        DataCategory.LEGAL,
    }

    def verify(self, data: list[dict[str, Any]]) -> ComplianceResult:
        checks: list[dict[str, Any]] = []
        violations: list[str] = []
        findings = self._collect_findings(data)

        has_pii = any(f.category == DataCategory.PII for f in findings)
        has_special = any(f.category in self.SPECIAL_CATEGORIES for f in findings)
        has_identifiable = has_pii or has_special

        if not has_identifiable:
            checks.append(
                {
                    "article": "art_5",
                    "check": "Data minimization - no PII found",
                    "passed": True,
                }
            )
        else:
            checks.append(
                {
                    "article": "art_5",
                    "check": "PII detected - verify lawful basis for processing",
                    "passed": False,
                }
            )
            violations.append("Art. 5: PII present without explicit consent verification")

        if has_special:
            checks.append(
                {
                    "article": "art_9",
                    "check": "Special category data detected - explicit consent required",
                    "passed": False,
                }
            )
            violations.append("Art. 9: Special category data requires explicit consent")
        else:
            checks.append(
                {
                    "article": "art_9",
                    "check": "No special category data detected",
                    "passed": True,
                }
            )

        if not has_special and not has_pii:
            checks.append(
                {
                    "article": "art_17",
                    "check": "Right to erasure - no personal data to erase",
                    "passed": True,
                }
            )
        else:
            checks.append(
                {
                    "article": "art_17",
                    "check": "Personal data found - erasure capability recommended",
                    "passed": False,
                }
            )
            violations.append("Art. 17: Implement right to erasure capability")

        encryption_check = self._check_encryption(data)
        checks.append(encryption_check)
        if not encryption_check["passed"]:
            violations.append("Art. 32: Data should be encrypted at rest and in transit")

        pii_count = sum(1 for f in findings if f.category == DataCategory.PII)
        if pii_count > 0:
            violations.append(f"Art. 35: DPIA recommended ({pii_count} PII fields found)")

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

        from datashield.detectors import PIIDetector

        detector = PIIDetector()
        try:
            return asyncio.run(detector.detect(data))
        except RuntimeError:
            import warnings

            warnings.warn("Could not run PII detection for GDPR check", stacklevel=2)
            return []

    def _check_encryption(self, data: list[dict[str, Any]]) -> dict[str, Any]:
        for record in data:
            for value in record.values():
                if isinstance(value, str) and len(value) > 20:
                    has_mixed = any(c.isupper() for c in value) and any(c.islower() for c in value)
                    has_digits = any(c.isdigit() for c in value)
                    if has_mixed and has_digits and len(value) > 30:
                        return {
                            "article": "art_32",
                            "check": "Potential encrypted/hashed data detected",
                            "passed": True,
                        }
        return {
            "article": "art_32",
            "check": "Verify encryption status - no encrypted fields detected",
            "passed": False,
        }
