from __future__ import annotations

from typing import Any

import httpx

from datashield.scanner import ScanReport


class MCPscopClient:
    def __init__(self, base_url: str, api_key: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._client = httpx.AsyncClient(timeout=30.0)

    async def send_report(self, report: ScanReport) -> dict[str, Any]:
        from datashield.taxonomy import datashield_finding_to_taxonomy

        events = []
        for finding in report.findings:
            event = datashield_finding_to_taxonomy(finding)
            events.append(
                {
                    "source": event.source,
                    "attack_category": event.attack_category.value,
                    "severity": event.severity.value,
                    "confidence": event.confidence.value,
                    "title": event.title,
                    "description": event.description,
                    "recommendation": event.recommendation,
                    "detection_method": event.detection_method.value
                    if event.detection_method
                    else "",
                    "target": event.target,
                    "snippet": event.snippet,
                    "risk_score": event.risk_score,
                    "timestamp": event.timestamp,
                }
            )

        payload = {
            "source": "datashield",
            "report_id": report.id,
            "risk_score": report.risk_score,
            "risk_category": report.risk_category,
            "total_findings": report.total_findings,
            "events": events,
            "metadata": report.metadata,
        }

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        response = await self._client.post(
            f"{self.base_url}/api/events",
            json=payload,
            headers=headers,
        )
        response.raise_for_status()
        return response.json()

    async def close(self) -> None:
        await self._client.aclose()
