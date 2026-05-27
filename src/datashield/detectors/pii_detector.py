from __future__ import annotations

from typing import Any

from datashield.detectors.pattern_matcher import PatternMatcher
from datashield.scanner import (
    BaseDetector,
    Confidence,
    DataCategory,
    DetectorType,
    Finding,
    Severity,
)

_PII_PATTERNS: list[tuple[str, str, Severity, Confidence, DataCategory, str]] = [
    (
        "email",
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        Severity.MEDIUM,
        Confidence.HIGH,
        DataCategory.PII,
        "Email address",
    ),
    (
        "phone",
        r"(?:\+\d{1,3}[-\s]?)?\(?\d{2,4}\)?[-\s]?\d{2,4}[-\s]?\d{2,4}",
        Severity.MEDIUM,
        Confidence.HIGH,
        DataCategory.PII,
        "Phone number",
    ),
    (
        "ssn",
        r"\b\d{3}-\d{2}-\d{4}\b",
        Severity.CRITICAL,
        Confidence.HIGH,
        DataCategory.PII,
        "Social Security Number",
    ),
    (
        "passport",
        r"(?i)\b[A-Z]{1,2}\d{6,9}\b",
        Severity.HIGH,
        Confidence.MEDIUM,
        DataCategory.PII,
        "Passport number",
    ),
    (
        "driver_license",
        r"(?i)\b[A-Z]{1,3}[-]\d{4,8}\b",
        Severity.HIGH,
        Confidence.MEDIUM,
        DataCategory.PII,
        "Driver license number",
    ),
    (
        "national_id",
        r"\b\d{3}[-.]?\d{3}[-.]?\d{3}[-.]?\d{2}\b",
        Severity.HIGH,
        Confidence.MEDIUM,
        DataCategory.PII,
        "National ID number",
    ),
    (
        "tax_id",
        r"(?i)\b\d{2}-\d{7}\b",
        Severity.HIGH,
        Confidence.MEDIUM,
        DataCategory.PII,
        "Tax ID number",
    ),
    (
        "full_name",
        r"(?i)\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b",
        Severity.LOW,
        Confidence.LOW,
        DataCategory.PERSONAL,
        "Personal name with title",
    ),
    (
        "age",
        r"\b(?:age|edad)\s*[=:]\s*(\d{1,3})\b",
        Severity.LOW,
        Confidence.MEDIUM,
        DataCategory.PERSONAL,
        "Age information",
    ),
    (
        "biometric",
        r"(?i)\b(?:fingerprint|dna|retina|iris|face\s*scan|biometric)\b",
        Severity.HIGH,
        Confidence.LOW,
        DataCategory.PERSONAL,
        "Biometric data reference",
    ),
    (
        "ethnicity",
        r"(?i)\b(?:race|ethnicity|ethnic)\s*[=:]\s*[A-Za-z]+\b",
        Severity.MEDIUM,
        Confidence.LOW,
        DataCategory.PERSONAL,
        "Ethnicity information",
    ),
    (
        "religion",
        r"(?i)\b(?:religion|religious)\s*[=:]\s*[A-Za-z]+\b",
        Severity.MEDIUM,
        Confidence.LOW,
        DataCategory.PERSONAL,
        "Religious information",
    ),
    (
        "political_opinion",
        r"(?i)\b(?:political|party|affiliation)\s*[=:]\s*[A-Za-z]+\b",
        Severity.MEDIUM,
        Confidence.LOW,
        DataCategory.PERSONAL,
        "Political opinion",
    ),
    (
        "gender",
        r"(?i)\b(?:gender|sex)\s*[=:]\s*[A-Za-z]+\b",
        Severity.LOW,
        Confidence.MEDIUM,
        DataCategory.PERSONAL,
        "Gender information",
    ),
    (
        "sexual_orientation",
        r"(?i)\b(?:sexual\s*orientation|lgbtq?)\s*[=:]\s*[A-Za-z]+\b",
        Severity.HIGH,
        Confidence.LOW,
        DataCategory.PERSONAL,
        "Sexual orientation",
    ),
    (
        "health_condition",
        r"(?i)\b(?:diagnosis|condition|disease|illness|disorder|symptom)\s*[=:]\s*[A-Za-z\s]+\b",
        Severity.HIGH,
        Confidence.LOW,
        DataCategory.MEDICAL,
        "Health condition",
    ),
    (
        "union_membership",
        r"(?i)\b(?:union\s*member|union\s*membership)\s*[=:]\s*[A-Za-z]+\b",
        Severity.MEDIUM,
        Confidence.LOW,
        DataCategory.PERSONAL,
        "Union membership",
    ),
]


class PIIDetector(BaseDetector):
    """Detects PII fields (email, phone, SSN, passport, driver license, national ID, etc.) via pattern matching."""

    name = "pii_detector"
    detector_type = DetectorType.PII

    def __init__(self) -> None:
        self._matcher = PatternMatcher(_PII_PATTERNS)

    async def detect(self, records: list[dict[str, Any]]) -> list[Finding]:
        return await self._matcher.detect(records)
