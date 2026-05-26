from __future__ import annotations

from mcp_taxonomy.core import (
    AttackCategory,
    Confidence,
    DetectionMethod,
    TaxonomyEvent,
    severity_weight,
)

from datashield.scanner import DataCategory, DetectorType, Finding, Severity

_DATASHIELD_CATEGORY_MAP: dict[DataCategory, AttackCategory] = {
    DataCategory.PII: AttackCategory.INJECTION,
    DataCategory.SECRET: AttackCategory.POLICY_VIOLATION,
    DataCategory.MEDICAL: AttackCategory.POLICY_VIOLATION,
    DataCategory.LEGAL: AttackCategory.POLICY_VIOLATION,
    DataCategory.CREDENTIAL: AttackCategory.TOOL_POISONING,
    DataCategory.FINANCIAL: AttackCategory.POLICY_VIOLATION,
    DataCategory.LOCATION: AttackCategory.ANOMALY,
    DataCategory.PERSONAL: AttackCategory.POLICY_VIOLATION,
    DataCategory.CONTACT: AttackCategory.ANOMALY,
    DataCategory.OTHER: AttackCategory.ANOMALY,
}

_DATASHIELD_DETECTOR_MAP: dict[DetectorType, DetectionMethod] = {
    DetectorType.PII: DetectionMethod.HIDDEN_TEXT,
    DetectorType.SECRET: DetectionMethod.INJECTION_PATTERNS,
    DetectorType.CLASSIFIER: DetectionMethod.INSTRUCTION_CLASSIFIER,
    DetectorType.PATTERN: DetectionMethod.INJECTION_PATTERNS,
}

_DATASHIELD_CONFIDENCE_MAP: dict[str, Confidence] = {
    "high": Confidence.HIGH,
    "medium": Confidence.MEDIUM,
    "low": Confidence.LOW,
}


def datashield_finding_to_taxonomy(finding: Finding | dict) -> TaxonomyEvent:
    if isinstance(finding, dict):
        finding_obj = Finding(**finding)
    else:
        finding_obj = finding

    category = _DATASHIELD_CATEGORY_MAP.get(finding_obj.category, AttackCategory.ANOMALY)
    detector = _DATASHIELD_DETECTOR_MAP.get(
        finding_obj.detector_type, DetectionMethod.INJECTION_PATTERNS
    )
    ds_sev = (
        finding_obj.severity.value
        if isinstance(finding_obj.severity, Severity)
        else str(finding_obj.severity)
    )
    severity = Severity(ds_sev) if ds_sev in {s.value for s in Severity} else Severity.MEDIUM
    confidence = _DATASHIELD_CONFIDENCE_MAP.get(
        finding_obj.confidence.value
        if hasattr(finding_obj.confidence, "value")
        else str(finding_obj.confidence),
        Confidence.MEDIUM,
    )

    return TaxonomyEvent(
        source="datashield",
        attack_category=category,
        severity=severity,
        confidence=confidence,
        detection_method=detector,
        title=finding_obj.title,
        description=finding_obj.description,
        recommendation=finding_obj.recommendation or "",
        snippet=finding_obj.snippet or "",
        target=finding_obj.field_path or "",
        raw=finding_obj.model_dump() if hasattr(finding_obj, "model_dump") else {},
        risk_score=severity_weight(severity)
        * sum(s["weight"] for s in _score_weights(finding_obj))
        // 25,
    )


def _score_weights(finding: Finding) -> list[dict]:
    severity_weights = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 10,
        Severity.MEDIUM: 3,
        Severity.LOW: 1,
    }
    w = severity_weights.get(
        finding.severity if isinstance(finding.severity, Severity) else Severity.MEDIUM,
        0,
    )
    return [{"weight": w}]
