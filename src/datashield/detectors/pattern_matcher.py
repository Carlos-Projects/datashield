from __future__ import annotations

import logging
from typing import Any

import regex

from datashield.scanner import (
    BaseDetector,
    Confidence,
    DataCategory,
    DetectorType,
    Finding,
    Severity,
)

_RE_TIMEOUT = 5.0

logger = logging.getLogger(__name__)

_PATTERNS: list[tuple[str, str, Severity, Confidence, DataCategory, str]] = [
    (
        "email",
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        Severity.MEDIUM,
        Confidence.HIGH,
        DataCategory.PII,
        "Email address detected",
    ),
    (
        "phone_us",
        r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
        Severity.MEDIUM,
        Confidence.HIGH,
        DataCategory.PII,
        "US phone number detected",
    ),
    (
        "ssn_us",
        r"\b\d{3}-\d{2}-\d{4}\b",
        Severity.CRITICAL,
        Confidence.HIGH,
        DataCategory.PII,
        "US SSN detected",
    ),
    (
        "ipv4",
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        Severity.LOW,
        Confidence.MEDIUM,
        DataCategory.LOCATION,
        "IPv4 address detected",
    ),
    (
        "credit_card",
        r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        Severity.CRITICAL,
        Confidence.HIGH,
        DataCategory.FINANCIAL,
        "Credit card number detected",
    ),
    (
        "api_key_generic",
        r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?",
        Severity.HIGH,
        Confidence.MEDIUM,
        DataCategory.SECRET,
        "API key detected",
    ),
    (
        "aws_key",
        r"(?i)AKIA[0-9A-Z]{16}",
        Severity.CRITICAL,
        Confidence.HIGH,
        DataCategory.CREDENTIAL,
        "AWS access key detected",
    ),
    (
        "aws_secret",
        r"(?i)(?<![a-zA-Z0-9])[\w\/+=]{40}(?![a-zA-Z0-9])",
        Severity.CRITICAL,
        Confidence.MEDIUM,
        DataCategory.CREDENTIAL,
        "Potential AWS secret key detected",
    ),
    (
        "github_token",
        r"(?i)gh[ps]_[a-zA-Z0-9]{36,}",
        Severity.CRITICAL,
        Confidence.HIGH,
        DataCategory.CREDENTIAL,
        "GitHub token detected",
    ),
    (
        "jwt",
        r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        Severity.HIGH,
        Confidence.MEDIUM,
        DataCategory.SECRET,
        "JWT token detected",
    ),
    (
        "private_key",
        r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
        Severity.CRITICAL,
        Confidence.HIGH,
        DataCategory.CREDENTIAL,
        "Private key detected",
    ),
    (
        "password_field",
        r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^'\"\s]{4,})['\"]?",
        Severity.CRITICAL,
        Confidence.HIGH,
        DataCategory.CREDENTIAL,
        "Password detected",
    ),
    (
        "bearer_token",
        r"(?i)Bearer\s+[a-zA-Z0-9_\-\.]{20,}",
        Severity.HIGH,
        Confidence.HIGH,
        DataCategory.CREDENTIAL,
        "Bearer token detected",
    ),
    (
        "basic_auth",
        r"(?i)Basic\s+[a-zA-Z0-9+/=]{10,}",
        Severity.HIGH,
        Confidence.MEDIUM,
        DataCategory.CREDENTIAL,
        "Basic auth credentials detected",
    ),
    (
        "date_of_birth",
        r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
        Severity.LOW,
        Confidence.LOW,
        DataCategory.PERSONAL,
        "Potential date detected",
    ),
    (
        "street_address",
        r"\b\d{1,5}\s+(?>[A-Za-z0-9\s,]+)(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct)\b",
        Severity.MEDIUM,
        Confidence.LOW,
        DataCategory.LOCATION,
        "Street address detected",
    ),
    (
        "zip_code_us",
        r"\b\d{5}(?:-\d{4})?\b",
        Severity.LOW,
        Confidence.MEDIUM,
        DataCategory.LOCATION,
        "US zip code detected",
    ),
    (
        "medical_record",
        r"(?i)\b(?:MRN|patient\s*id|medical\s*record\s*number)[:\s]*[a-zA-Z0-9\-]{4,20}\b",
        Severity.HIGH,
        Confidence.MEDIUM,
        DataCategory.MEDICAL,
        "Medical record number detected",
    ),
    (
        "credit_card_cvv",
        r"(?i)(?:cvv|cvc|cvv2|cvc2|card_code|security_code)\s*[=:]\s*['\"]?\d{3,4}['\"]?",
        Severity.LOW,
        Confidence.MEDIUM,
        DataCategory.FINANCIAL,
        "Potential CVV detected",
    ),
]


class PatternMatcher(BaseDetector):
    """Detects sensitive data using regex patterns with ReDoS protection (atomic groups + timeout)."""

    name = "pattern_matcher"
    detector_type = DetectorType.PATTERN

    def __init__(
        self,
        custom_patterns: list[tuple[str, str, Severity, Confidence, DataCategory, str]]
        | None = None,
    ):
        self.patterns = custom_patterns or _PATTERNS

    async def detect(self, records: list[dict[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        for record in records:
            findings.extend(self._scan_record(record))
        return findings

    def _scan_record(self, record: dict[str, Any], path: str = "") -> list[Finding]:
        findings: list[Finding] = []
        for key, value in record.items():
            field_path = f"{path}.{key}" if path else key
            if isinstance(value, dict):
                findings.extend(self._scan_record(value, field_path))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        findings.extend(self._scan_record(item, f"{field_path}[{i}]"))
                    elif isinstance(item, str):
                        findings.extend(self._check_value(item, f"{field_path}[{i}]"))
            elif isinstance(value, str):
                findings.extend(self._check_value(value, field_path))
        return findings

    def _check_value(self, value: str, field_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for name, pattern, severity, confidence, category, title in self.patterns:
            try:
                for match in regex.finditer(pattern, value, overlapped=True, timeout=_RE_TIMEOUT):
                    findings.append(
                        Finding(
                            detector=self.name,
                            detector_type=self.detector_type,
                            severity=severity,
                            confidence=confidence,
                            title=title,
                            description=f"Pattern '{name}' matched in field '{field_path}'",
                            field_path=field_path,
                            value=match.group(),
                            category=category,
                            snippet=value[:200] if len(value) > 200 else value,
                            recommendation=f"Review and remove/obfuscate the {name} value in '{field_path}'",
                            metadata={"pattern_name": name, "pattern": pattern},
                        )
                    )
            except regex.error as e:
                logger.warning("Regex pattern '%s' failed: %s", name, e)
                continue
            except regex.TimeoutError:
                logger.warning("Regex pattern '%s' timed out on field '%s'", name, field_path)
                continue
        return findings
