from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

_CONF_WEIGHTS = {"high": 0.8, "medium": 0.5, "low": 0.2}


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DataCategory(StrEnum):
    PII = "pii"
    SECRET = "secret"
    MEDICAL = "medical"
    FINANCIAL = "financial"
    LEGAL = "legal"
    PERSONAL = "personal"
    CREDENTIAL = "credential"
    LOCATION = "location"
    CONTACT = "contact"
    OTHER = "other"


class DetectorType(StrEnum):
    PII = "pii_detector"
    SECRET = "secret_scanner"
    CLASSIFIER = "sensitive_classifier"
    PATTERN = "pattern_matcher"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    detector: str
    detector_type: DetectorType
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    field_path: str | None = None
    value: str | None = None
    category: DataCategory
    snippet: str | None = None
    recommendation: str | None = None
    source: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanReport(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str | None = None
    total_records: int | None = None
    total_findings: int = 0
    findings: list[Finding] = Field(default_factory=list)
    risk_score: float = 0.0
    risk_category: str = "unknown"
    summary: dict[str, int] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SanitizedRecord(BaseModel):
    index: int = 0
    original: dict[str, Any] = Field(default_factory=dict)
    sanitized: dict[str, Any] = Field(default_factory=dict)
    removed_fields: list[str] = Field(default_factory=list)
    modified_fields: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


class SanitizeReport(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    records: list[SanitizedRecord] = Field(default_factory=list)
    total_original: int = 0
    total_removed: int = 0
    total_modified: int = 0
    total_findings: int = 0
    techniques_applied: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ComplianceResult(BaseModel):
    regulation: str
    compliant: bool
    checks: list[dict[str, Any]] = Field(default_factory=list)
    violations: list[str] = Field(default_factory=list)
    score: float = 0.0


class Scanner:
    def __init__(
        self,
        detectors: list[BaseDetector] | None = None,
        sanitizers: list[BaseSanitizer] | None = None,
    ):
        self.detectors = detectors or []
        self.sanitizers = sanitizers or []

    async def scan(
        self,
        data: list[dict[str, Any]] | dict[str, Any],
        threshold: float = 0.0,
        exclude: list[str] | None = None,
    ) -> ScanReport:
        records = data if isinstance(data, list) else [data]
        all_findings: list[Finding] = []
        seen: set[tuple[str | None, str | None]] = set()
        for detector in self.detectors:
            results = await detector.detect(records)
            for f in results:
                key = (f.field_path, f.value)
                if key not in seen:
                    seen.add(key)
                    all_findings.append(f)

        filtered = self._filter_findings(all_findings, threshold, exclude or [])
        severity_counts: dict[str, int] = {}
        for f in filtered:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
        risk_score = self.compute_risk_score(filtered)
        return ScanReport(
            source="scan",
            total_records=len(records),
            total_findings=len(filtered),
            findings=filtered,
            risk_score=risk_score,
            risk_category=self._risk_category(risk_score),
            summary=severity_counts,
        )

    @staticmethod
    def _filter_findings(
        findings: list[Finding], threshold: float, exclude: list[str]
    ) -> list[Finding]:
        filtered: list[Finding] = []
        for f in findings:
            if threshold > 0 and f.confidence.value in _CONF_WEIGHTS:
                if _CONF_WEIGHTS[f.confidence.value] < threshold:
                    continue
            if exclude and f.field_path:
                if any(f.field_path.startswith(e) for e in exclude):
                    continue
            filtered.append(f)
        return filtered

    def compute_risk_score(self, findings: list[Finding]) -> float:
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }
        total = sum(weights.get(f.severity, 0) for f in findings)
        return min(100.0, total)

    def _risk_category(self, score: float) -> str:
        if score >= 70:
            return "critical"
        if score >= 40:
            return "high"
        if score >= 20:
            return "medium"
        if score >= 5:
            return "low"
        return "safe"


class BaseDetector:
    name: str = "base"
    detector_type: DetectorType = DetectorType.PATTERN

    async def detect(self, records: list[dict[str, Any]]) -> list[Finding]:
        raise NotImplementedError


class BaseSanitizer:
    name: str = "base"

    async def sanitize(
        self, records: list[dict[str, Any]], findings: list[Finding] | None = None
    ) -> list[SanitizedRecord]:
        raise NotImplementedError
