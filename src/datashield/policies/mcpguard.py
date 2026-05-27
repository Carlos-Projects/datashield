from __future__ import annotations

from typing import Any

import yaml
from pydantic import BaseModel, Field

from datashield.scanner import Finding, ScanReport, Severity


class MCPGuardPolicy(BaseModel):
    """MCPGuard-compatible security policy specifying allow/deny rules, rate limits, and blocking behavior."""

    mode: str = "http"
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    target_url: str = "http://localhost:8000"
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)
    rate_limit: int = 100
    rate_window: int = 60
    block_on_injection: bool = True
    block_on_poisoning: bool = True
    block_on_resource_scan: bool = True
    block_on_prompt_scan: bool = False
    log_dir: str = "./mcpguard_logs"
    metadata: dict[str, Any] = Field(default_factory=dict)


class MCPGuardPolicyGenerator:
    """Generates MCPGuard YAML policies from scan findings and reports."""

    def __init__(self) -> None:
        self.policy = MCPGuardPolicy()

    def from_findings(
        self,
        findings: list[Finding],
        target_url: str = "http://localhost:8000",
    ) -> MCPGuardPolicy:
        deny_tools: set[str] = set()
        allow_tools: set[str] = set()
        block_injection = False
        block_poisoning = False

        severity_map: dict[Severity, int] = {}
        for f in findings:
            severity_label = f.severity if isinstance(f.severity, Severity) else Severity.MEDIUM
            severity_map[severity_label] = severity_map.get(severity_label, 0) + 1

            if f.field_path:
                deny_tools.add(f.field_path)

            if (
                "credential" in str(f.category.value).lower()
                or "secret" in str(f.category.value).lower()
            ):
                block_poisoning = True
            if "pii" in str(f.category.value).lower() or "medical" in str(f.category.value).lower():
                block_injection = True

        has_critical = any(
            (s if isinstance(s, Severity) else Severity.MEDIUM) == Severity.CRITICAL
            for s in severity_map
        )
        has_high = any(
            (s if isinstance(s, Severity) else Severity.MEDIUM) == Severity.HIGH
            for s in severity_map
        )

        if has_critical:
            rate_limit_val = 30
        elif has_high:
            rate_limit_val = 60
        else:
            rate_limit_val = 100

        self.policy = MCPGuardPolicy(
            target_url=target_url,
            deny=sorted(deny_tools),
            allow=sorted(allow_tools),
            rate_limit=rate_limit_val,
            block_on_injection=block_injection or has_critical,
            block_on_poisoning=block_poisoning or has_high,
            block_on_resource_scan=True,
            metadata={
                "generated_by": "datashield",
                "findings_count": len(findings),
                "severity_summary": {str(k): v for k, v in severity_map.items()},
            },
        )
        return self.policy

    def from_scan_report(
        self, report: ScanReport, target_url: str = "http://localhost:8000"
    ) -> MCPGuardPolicy:
        return self.from_findings(report.findings, target_url)

    def to_yaml(self, policy: MCPGuardPolicy | None = None) -> str:
        p = policy or self.policy
        data = p.model_dump(exclude={"metadata"})
        data["metadata"] = p.metadata
        return yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True)

    def save(self, path: str, policy: MCPGuardPolicy | None = None) -> None:
        content = self.to_yaml(policy)
        with open(path, "w") as f:
            f.write(content)
