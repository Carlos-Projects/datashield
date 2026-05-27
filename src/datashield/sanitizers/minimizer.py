from __future__ import annotations

from typing import Any

from datashield.scanner import BaseSanitizer, DataCategory, Finding, SanitizedRecord

_MINIMIZE_CATEGORIES: set[DataCategory] = {
    DataCategory.PII,
    DataCategory.CREDENTIAL,
    DataCategory.SECRET,
    DataCategory.MEDICAL,
    DataCategory.FINANCIAL,
    DataCategory.LOCATION,
}

_KEEP_FIELDS = {"id", "uuid", "user_id", "timestamp", "created_at", "updated_at"}


class Minimizer(BaseSanitizer):
    """Removes sensitive fields from records, keeping only necessary identifiers."""

    name = "minimizer"

    def __init__(
        self,
        minimize_categories: set[DataCategory] | None = None,
        keep_fields: set[str] | None = None,
    ):
        self.minimize_categories = minimize_categories or _MINIMIZE_CATEGORIES
        self.keep_fields = keep_fields or _KEEP_FIELDS

    async def sanitize(
        self, records: list[dict[str, Any]], findings: list[Finding] | None = None
    ) -> list[SanitizedRecord]:
        results: list[SanitizedRecord] = []
        for i, record in enumerate(records):
            sanitized = dict(record)
            removed: list[str] = []
            modified: list[str] = []
            record_findings = findings or []

            min_fields = self._find_minimizable_fields(record, record_findings)
            for field in min_fields:
                if field not in self.keep_fields and field in sanitized:
                    del sanitized[field]
                    removed.append(field)

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

    def _find_minimizable_fields(
        self, record: dict[str, Any], findings: list[Finding]
    ) -> list[str]:
        min_fields: list[str] = []
        for finding in findings:
            if finding.category in self.minimize_categories and finding.field_path:
                if finding.field_path in record:
                    min_fields.append(finding.field_path)
        return list(set(min_fields))
