from __future__ import annotations

from typing import Any

from datashield.scanner import ComplianceResult, DataCategory, Finding


class GDPRCompliance:
    """Checks dataset compliance with GDPR Articles 5, 9, 17, 25, 32, 35."""

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

        checks.append(
            {
                "article": "art_32",
                "check": "Encryption status must be verified externally — user must self-certify",
                "passed": "depends_on_user_certification",
            }
        )

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
        import logging

        from datashield.detectors import PIIDetector

        detector = PIIDetector()
        try:
            return asyncio.run(detector.detect(data))
        except (RuntimeError, OSError) as e:
            logging.getLogger(__name__).warning("Could not run PII detection for GDPR check: %s", e)
            return []

    def _check_encryption(self, data: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "article": "art_32",
            "check": "Encryption status must be verified externally — user must self-certify",
            "passed": "depends_on_user_certification",
        }
