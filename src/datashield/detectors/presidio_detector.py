from __future__ import annotations

from typing import Any

from datashield.scanner import (
    BaseDetector,
    Confidence,
    DataCategory,
    DetectorType,
    Finding,
    Severity,
)

_PRESIDIO_ENTITY_MAP: dict[str, tuple[DataCategory, Severity, Confidence]] = {
    "PERSON": (DataCategory.PERSONAL, Severity.MEDIUM, Confidence.HIGH),
    "EMAIL_ADDRESS": (DataCategory.PII, Severity.MEDIUM, Confidence.HIGH),
    "PHONE_NUMBER": (DataCategory.PII, Severity.MEDIUM, Confidence.HIGH),
    "CREDIT_CARD": (DataCategory.FINANCIAL, Severity.CRITICAL, Confidence.HIGH),
    "US_SSN": (DataCategory.PII, Severity.CRITICAL, Confidence.HIGH),
    "US_DRIVER_LICENSE": (DataCategory.PII, Severity.HIGH, Confidence.HIGH),
    "US_PASSPORT": (DataCategory.PII, Severity.HIGH, Confidence.HIGH),
    "US_BANK_NUMBER": (DataCategory.FINANCIAL, Severity.CRITICAL, Confidence.HIGH),
    "US_ITIN": (DataCategory.PII, Severity.HIGH, Confidence.HIGH),
    "UK_NHS": (DataCategory.MEDICAL, Severity.HIGH, Confidence.HIGH),
    "UK_NINO": (DataCategory.PII, Severity.HIGH, Confidence.HIGH),
    "IP_ADDRESS": (DataCategory.LOCATION, Severity.LOW, Confidence.MEDIUM),
    "LOCATION": (DataCategory.LOCATION, Severity.LOW, Confidence.MEDIUM),
    "DATE_TIME": (DataCategory.PERSONAL, Severity.LOW, Confidence.MEDIUM),
    "NRP": (DataCategory.PERSONAL, Severity.MEDIUM, Confidence.MEDIUM),
    "URL": (DataCategory.OTHER, Severity.LOW, Confidence.HIGH),
    "IBAN_CODE": (DataCategory.FINANCIAL, Severity.HIGH, Confidence.HIGH),
    "CRYPTO": (DataCategory.FINANCIAL, Severity.MEDIUM, Confidence.MEDIUM),
    "MAC_ADDRESS": (DataCategory.LOCATION, Severity.LOW, Confidence.MEDIUM),
    "MEDICAL_LICENSE": (DataCategory.MEDICAL, Severity.HIGH, Confidence.HIGH),
}


class PresidioDetector(BaseDetector):
    name = "presidio_detector"
    detector_type = DetectorType.PII

    def __init__(self) -> None:
        self._engine: Any = None

    def _get_engine(self) -> Any:
        if self._engine is None:
            try:
                from presidio_analyzer import AnalyzerEngine

                self._engine = AnalyzerEngine()
            except ImportError:
                msg = (
                    "presidio-analyzer is not installed. "
                    "Install with: pip install datashield-ai[presidio]"
                )
                raise ImportError(msg) from None
        return self._engine

    async def detect(self, records: list[dict[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        engine = self._get_engine()
        for record in records:
            findings.extend(self._scan_record(record, engine))
        return findings

    def _scan_record(self, record: dict[str, Any], engine: Any, path: str = "") -> list[Finding]:
        findings: list[Finding] = []
        for key, value in record.items():
            field_path = f"{path}.{key}" if path else key
            if isinstance(value, dict):
                findings.extend(self._scan_record(value, engine, field_path))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        findings.extend(self._scan_record(item, engine, f"{field_path}[{i}]"))
                    elif isinstance(item, str):
                        results = engine.analyze(text=item, language="en")
                        findings.extend(
                            self._presidio_results_to_findings(results, field_path, item)
                        )
            elif isinstance(value, str):
                results = engine.analyze(text=value, language="en")
                findings.extend(self._presidio_results_to_findings(results, field_path, value))
        return findings

    def _presidio_results_to_findings(
        self,
        results: list[Any],
        field_path: str,
        value: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for result in results:
            entity = result.entity_type
            mapping = _PRESIDIO_ENTITY_MAP.get(
                entity, (DataCategory.OTHER, Severity.MEDIUM, Confidence.MEDIUM)
            )
            category, severity, default_conf = mapping
            score = getattr(result, "score", 0.5)
            if score >= 0.85:
                confidence = Confidence.HIGH
            elif score >= 0.6:
                confidence = Confidence.MEDIUM
            else:
                confidence = Confidence.LOW
            snippet_start = max(0, result.start - 20)
            snippet_end = min(len(value), result.end + 20)
            snippet = value[snippet_start:snippet_end]

            findings.append(
                Finding(
                    detector=self.name,
                    detector_type=self.detector_type,
                    severity=severity,
                    confidence=confidence,
                    title=f"Presidio detected: {entity}",
                    description=(
                        f"Presidio identified '{entity}' in field '{field_path}' "
                        f"with confidence {score:.2f}"
                    ),
                    field_path=field_path,
                    value=value[result.start : result.end],
                    category=category,
                    snippet=snippet,
                    recommendation=(f"Review and sanitize '{entity}' data in '{field_path}'"),
                    metadata={
                        "presidio_entity": entity,
                        "presidio_score": score,
                        "start": result.start,
                        "end": result.end,
                    },
                )
            )
        return findings
