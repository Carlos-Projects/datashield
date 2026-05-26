from __future__ import annotations

from typing import Any

from datashield.scanner import BaseSanitizer, Finding, SanitizedRecord


class Redactor(BaseSanitizer):
    name = "redactor"

    def __init__(self, redaction_token: str = "[REDACTED]"):
        self.redaction_token = redaction_token

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
                    sanitized[finding.field_path] = self.redaction_token
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
