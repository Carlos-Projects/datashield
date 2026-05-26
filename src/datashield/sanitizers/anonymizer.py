from __future__ import annotations

import hashlib
from typing import Any

from datashield.scanner import BaseSanitizer, Finding, SanitizedRecord

_ANONYMIZATION_MAP: dict[str, str] = {}


def _anonymize_value(value: str) -> str:
    if value in _ANONYMIZATION_MAP:
        return _ANONYMIZATION_MAP[value]
    if value.startswith("ANON_"):
        return value
    prefix = value[:3] if len(value) >= 3 else value
    suffix = hashlib.sha256(value.encode()).hexdigest()[:8]
    anon = f"ANON_{prefix}_{suffix}"
    _ANONYMIZATION_MAP[value] = anon
    return anon


class Anonymizer(BaseSanitizer):
    name = "anonymizer"

    async def sanitize(
        self, records: list[dict[str, Any]], findings: list[Finding] | None = None
    ) -> list[SanitizedRecord]:
        results: list[SanitizedRecord] = []
        for i, record in enumerate(records):
            sanitized = dict(record)
            modified: list[str] = []
            removed: list[str] = []
            record_findings = [f for f in findings if f.field_path in record] if findings else []
            for finding in record_findings:
                if finding.field_path and finding.field_path in sanitized:
                    val = sanitized[finding.field_path]
                    if isinstance(val, str):
                        sanitized[finding.field_path] = _anonymize_value(val)
                        modified.append(finding.field_path)
            results.append(
                SanitizedRecord(
                    index=i,
                    original=record,
                    sanitized=sanitized,
                    removed_fields=removed,
                    modified_fields=modified,
                    findings=record_findings,
                )
            )
        return results
