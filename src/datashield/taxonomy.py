from __future__ import annotations

from datashield.scanner import DataCategory, DetectorType, Finding, Severity

try:  # noqa: I001
    from mcp_taxonomy.core import (
        AttackCategory,
        DetectionMethod,
        TaxonomyEvent,
        severity_weight,
    )
    from mcp_taxonomy.core import (
        Confidence as TaxonomyConfidence,
    )

    _HAS_MCP_TAXONOMY = True
except ImportError:
    _HAS_MCP_TAXONOMY = False
    AttackCategory = None
    TaxonomyConfidence = None
    DetectionMethod = None
    TaxonomyEvent = None

    def severity_weight(s: Severity) -> int:
        return 0


_CATEGORY_MAP: dict[DataCategory, str] = {
    DataCategory.PII: "injection",
    DataCategory.SECRET: "policy_violation",
    DataCategory.MEDICAL: "policy_violation",
    DataCategory.LEGAL: "policy_violation",
    DataCategory.CREDENTIAL: "tool_poisoning",
    DataCategory.FINANCIAL: "policy_violation",
    DataCategory.LOCATION: "anomaly",
    DataCategory.PERSONAL: "policy_violation",
    DataCategory.CONTACT: "anomaly",
    DataCategory.OTHER: "anomaly",
}

_DETECTOR_MAP: dict[DetectorType, str] = {
    DetectorType.PII: "hidden_text",
    DetectorType.SECRET: "injection_patterns",
    DetectorType.CLASSIFIER: "instruction_classifier",
    DetectorType.PATTERN: "injection_patterns",
}

_CONFIDENCE_MAP: dict[str, str] = {
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def datashield_finding_to_taxonomy(finding: Finding | dict) -> TaxonomyEvent:
    if not _HAS_MCP_TAXONOMY:
        raise ImportError(
            "mcp_taxonomy is required for taxonomy conversion. "
            "Install it with: pip install datashield-ai[taxonomy]"
        )
    if isinstance(finding, dict):
        finding_obj = Finding(**finding)
    else:
        finding_obj = finding

    category_str = _CATEGORY_MAP.get(finding_obj.category, "anomaly")
    category = AttackCategory(category_str)
    detector_str = _DETECTOR_MAP.get(finding_obj.detector_type, "injection_patterns")
    detector = DetectionMethod(detector_str)
    ds_sev = (
        finding_obj.severity.value
        if isinstance(finding_obj.severity, Severity)
        else str(finding_obj.severity)
    )
    severity = Severity(ds_sev) if ds_sev in {s.value for s in Severity} else Severity.MEDIUM
    confidence_str = _CONFIDENCE_MAP.get(
        finding_obj.confidence.value
        if hasattr(finding_obj.confidence, "value")
        else str(finding_obj.confidence),
        "medium",
    )
    confidence = TaxonomyConfidence(confidence_str)

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
