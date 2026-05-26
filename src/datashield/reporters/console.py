from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from datashield.scanner import ComplianceResult, ScanReport

console = Console()


class ConsoleReporter:
    def render(self, report: ScanReport) -> None:
        self._render_summary(report)
        self._render_findings(report)
        self._render_stats(report)

    def _render_summary(self, report: ScanReport) -> None:
        color = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "safe": "green",
        }.get(report.risk_category, "white")

        panel = Panel(
            f"[bold]Risk Score:[/bold] [{color}]{report.risk_score:.1f}[/{color}]  |  "
            f"[bold]Category:[/bold] [{color}]{report.risk_category.upper()}[/{color}]  |  "
            f"[bold]Findings:[/bold] {report.total_findings}  |  "
            f"[bold]Records:[/bold] {report.total_records}",
            title="DataShield Scan Report",
            border_style=color,
        )
        console.print(panel)

    def _render_findings(self, report: ScanReport) -> None:
        if not report.findings:
            console.print("[green]No findings detected.[/green]")
            return
        table = Table(title=f"Findings ({len(report.findings)})")
        table.add_column("Severity", style="bold")
        table.add_column("Confidence")
        table.add_column("Category")
        table.add_column("Title")
        table.add_column("Field")
        for f in report.findings:
            severity_style = {
                "critical": "red",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
                "info": "white",
            }.get(f.severity.value, "white")
            table.add_row(
                f"[{severity_style}]{f.severity.value.upper()}[/{severity_style}]",
                f.confidence.value,
                f.category.value,
                f.title[:50],
                f.field_path or "-",
            )
        console.print(table)

    def _render_stats(self, report: ScanReport) -> None:
        if not report.summary:
            return
        tree = Tree("Severity Distribution")
        for severity, count in sorted(report.summary.items()):
            color = {
                "critical": "red",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
                "info": "white",
            }.get(severity, "white")
            tree.add(f"[{color}]{severity}: {count}[/{color}]")
        console.print(tree)

    def report_anonymization(
        self,
        epsilon: float,
        k: int,
        epsilon_estimate: float,
        dp_modified: int,
        k_satisfied: bool,
    ) -> None:
        table = Table(title="Anonymization Report")
        table.add_column("Parameter", style="bold")
        table.add_column("Value")
        table.add_row("Privacy Budget (ε)", str(epsilon))
        table.add_row("Estimated ε", str(epsilon_estimate))
        table.add_row("k-Anonymity", str(k))
        table.add_row("Records Modified (DP)", str(dp_modified))
        table.add_row(
            "k-Anonymity Satisfied", "[green]Yes[/green]" if k_satisfied else "[red]No[/red]"
        )
        console.print(table)

    def report_compliance(self, results: list[ComplianceResult]) -> None:
        for result in results:
            color = "green" if result.compliant else "red"
            panel = Panel(
                f"[bold]Regulation:[/bold] {result.regulation}\n"
                f"[bold]Status:[/bold] [{color}]{'COMPLIANT' if result.compliant else 'NON-COMPLIANT'}[/{color}]\n"
                f"[bold]Score:[/bold] {result.score:.1f}%\n"
                f"[bold]Violations:[/bold] {len(result.violations)}",
                title=f"Compliance - {result.regulation}",
                border_style=color,
            )
            console.print(panel)
            if result.violations:
                console.print("[red]Violations:[/red]")
                for v in result.violations:
                    console.print(f"  • {v}")
