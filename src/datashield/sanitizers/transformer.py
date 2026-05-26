from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

from datashield.scanner import BaseSanitizer, DataCategory, Finding, SanitizedRecord

_TRANSFORM_FUNCTIONS: dict[DataCategory, Callable[[str], str]] = {
    DataCategory.PII: lambda v: hashlib.sha256(v.encode()).hexdigest()[:16],
    DataCategory.CREDENTIAL: lambda _: "[REDACTED]",
    DataCategory.SECRET: lambda _: "[REDACTED]",
    DataCategory.MEDICAL: lambda v: f"MED_{hashlib.md5(v.encode()).hexdigest()[:8]}",
    DataCategory.FINANCIAL: lambda v: v[:4] + "XXXX" if len(v) >= 4 else "XXXX",
    DataCategory.LOCATION: lambda v: v[:3] + "***" if len(v) >= 3 else "***",
    DataCategory.PERSONAL: lambda v: hashlib.sha256(v.encode()).hexdigest()[:12],
}


class Transformer(BaseSanitizer):
    name = "transformer"

    def __init__(
        self,
        transform_functions: dict[DataCategory, Callable[[str], str]] | None = None,
    ):
        self.transform_functions = transform_functions or _TRANSFORM_FUNCTIONS

    async def sanitize(
        self, records: list[dict[str, Any]], findings: list[Finding] | None = None
    ) -> list[SanitizedRecord]:
        results: list[SanitizedRecord] = []
        for i, record in enumerate(records):
            sanitized = dict(record)
            modified: list[str] = []
            removed: list[str] = []
            record_findings = findings or []

            for finding in record_findings:
                if (
                    finding.field_path
                    and finding.field_path in sanitized
                    and finding.category in self.transform_functions
                ):
                    val = sanitized[finding.field_path]
                    if isinstance(val, str):
                        fn = self.transform_functions[finding.category]
                        sanitized[finding.field_path] = fn(val)
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
