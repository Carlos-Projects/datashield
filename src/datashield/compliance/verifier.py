from __future__ import annotations

from typing import Any

from datashield.scanner import ComplianceResult


class ComplianceVerifier:
    def __init__(self) -> None:
        self._results: list[ComplianceResult] = []

    def verify_all(self, data: list[dict[str, Any]]) -> list[ComplianceResult]:
        from datashield.compliance.gdpr import GDPRCompliance
        from datashield.compliance.hipaa import HIPAACompliance

        results: list[ComplianceResult] = []
        results.append(GDPRCompliance().verify(data))
        results.append(HIPAACompliance().verify(data))
        self._results = results
        return results

    def compare(
        self, original: list[dict[str, Any]], sanitized: list[dict[str, Any]]
    ) -> dict[str, Any]:
        original_pii = self._count_pii_fields(original)
        sanitized_pii = self._count_pii_fields(sanitized)
        reduction = 0
        if original_pii > 0:
            reduction = round((original_pii - sanitized_pii) / original_pii * 100, 1)
        return {
            "original_pii_fields": original_pii,
            "sanitized_pii_fields": sanitized_pii,
            "reduction_percentage": reduction,
            "fields_removed": original_pii - sanitized_pii,
        }

    def _count_pii_fields(self, data: list[dict[str, Any]]) -> int:
        import asyncio

        from datashield.detectors import PIIDetector

        try:
            detector = PIIDetector()
            findings = asyncio.run(detector.detect(data))
            return len(findings)
        except RuntimeError:
            return 0
