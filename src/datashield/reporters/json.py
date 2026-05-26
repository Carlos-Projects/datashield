from __future__ import annotations

import json
from typing import Any

from datashield.scanner import ScanReport


class JSONReporter:
    def render(self, report: ScanReport) -> str:
        return json.dumps(self._serialize(report), indent=2, default=str)

    def _serialize(self, report: ScanReport) -> dict[str, Any]:
        return {
            "metadata": {
                "id": report.id,
                "timestamp": report.timestamp.isoformat(),
                "source": report.source,
                "total_records": report.total_records,
                "total_findings": report.total_findings,
                "risk_score": report.risk_score,
                "risk_category": report.risk_category,
            },
            "summary": report.summary,
            "findings": [
                {
                    "id": f.id,
                    "detector": f.detector,
                    "detector_type": f.detector_type.value,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "title": f.title,
                    "description": f.description,
                    "category": f.category.value,
                    "field_path": f.field_path,
                    "value": f.value,
                    "snippet": f.snippet,
                    "recommendation": f.recommendation,
                    "timestamp": f.timestamp.isoformat(),
                }
                for f in report.findings
            ],
        }
