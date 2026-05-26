from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from datashield.detectors import PatternMatcher, PIIDetector, SecretScanner, SensitiveClassifier
from datashield.reporters import ConsoleReporter, HTMLReporter, JSONReporter
from datashield.sanitizers import Anonymizer, Minimizer, Redactor, Transformer
from datashield.scanner import Scanner

app = typer.Typer(
    name="datashield",
    help="DataShield — Data sanitization with privacy preservation for AI training",
    no_args_is_help=True,
)
console = Console()


def _load_data(path: str) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        console.print(f"[red]File not found:[/red] {path}")
        raise typer.Exit(1)
    raw = p.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON:[/red] {e}")
        raise typer.Exit(1) from e
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    console.print("[red]Unsupported data format. Expected JSON object or array.[/red]")
    raise typer.Exit(1)


def _build_scanner(
    enable_pii: bool = True,
    enable_secrets: bool = True,
    enable_classifier: bool = True,
    enable_patterns: bool = True,
    enable_anonymizer: bool = False,
    enable_redactor: bool = False,
    enable_minimizer: bool = False,
    enable_transformer: bool = False,
) -> Scanner:
    detectors = []
    sanitizers = []
    if enable_pii:
        detectors.append(PIIDetector())
    if enable_secrets:
        detectors.append(SecretScanner())
    if enable_classifier:
        detectors.append(SensitiveClassifier())
    if enable_patterns:
        detectors.append(PatternMatcher())
    if enable_anonymizer:
        sanitizers.append(Anonymizer())
    if enable_redactor:
        sanitizers.append(Redactor())
    if enable_minimizer:
        sanitizers.append(Minimizer())
    if enable_transformer:
        sanitizers.append(Transformer())
    return Scanner(detectors=detectors, sanitizers=sanitizers)


@app.command()
def scan(
    file: str = typer.Argument(..., help="Path to JSON dataset file"),
    pii: bool = typer.Option(True, "--pii/--no-pii", help="Enable PII detection"),
    secrets: bool = typer.Option(True, "--secrets/--no-secrets", help="Enable secret scanning"),
    classifier: bool = typer.Option(
        True, "--classifier/--no-classifier", help="Enable sensitive data classification"
    ),
    patterns: bool = typer.Option(True, "--patterns/--no-patterns", help="Enable pattern matching"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output report path"),
    format: str = typer.Option(
        "console", "--format", "-f", help="Output format: console, json, html"
    ),
):
    """Scan a dataset for sensitive data and privacy risks."""
    data = _load_data(file)
    scanner = _build_scanner(
        enable_pii=pii,
        enable_secrets=secrets,
        enable_classifier=classifier,
        enable_patterns=patterns,
    )
    report = asyncio.run(scanner.scan(data))
    _render_report(report, format, output)
    if report.risk_score >= 40:
        raise typer.Exit(1)


@app.command()
def sanitize(
    file: str = typer.Argument(..., help="Path to JSON dataset file"),
    output: str = typer.Argument(..., help="Output path for sanitized data"),
    pii: bool = typer.Option(True, "--pii/--no-pii", help="Enable PII detection"),
    secrets: bool = typer.Option(True, "--secrets/--no-secrets", help="Enable secret scanning"),
    classifier: bool = typer.Option(
        True, "--classifier/--no-classifier", help="Enable sensitive data classification"
    ),
    patterns: bool = typer.Option(True, "--patterns/--no-patterns", help="Enable pattern matching"),
    anonymize: bool = typer.Option(True, "--anonymize", help="Apply anonymization"),
    redact: bool = typer.Option(True, "--redact", help="Apply redaction"),
    minimize: bool = typer.Option(False, "--minimize", help="Apply data minimization"),
    transform: bool = typer.Option(False, "--transform", help="Apply data transformation"),
    report_output: str | None = typer.Option(
        None, "--report", "-r", help="Output path for scan report"
    ),
    format: str = typer.Option(
        "console", "--format", "-f", help="Report format: console, json, html"
    ),
):
    """Sanitize a dataset by detecting and removing/obfuscating sensitive data."""
    data = _load_data(file)
    scanner = _build_scanner(
        enable_pii=pii,
        enable_secrets=secrets,
        enable_classifier=classifier,
        enable_patterns=patterns,
        enable_anonymizer=anonymize,
        enable_redactor=redact,
        enable_minimizer=minimize,
        enable_transformer=transform,
    )
    scan_report = asyncio.run(scanner.scan(data))
    sanitized_records = []
    for i, record in enumerate(data):
        sanitized = dict(record)
        modified_fields = []
        removed_fields = []
        record_findings = [
            f for f in scan_report.findings if f.field_path in record or f.field_path is None
        ]
        for sanitizer in scanner.sanitizers:
            result = asyncio.run(sanitizer.sanitize([sanitized], record_findings))
            if result:
                sanitized = result[0].sanitized
                modified_fields.extend(result[0].modified_fields)
                removed_fields.extend(result[0].removed_fields)
        from datashield.scanner import SanitizedRecord

        sanitized_records.append(
            SanitizedRecord(
                index=i,
                original=record,
                sanitized=sanitized,
                removed_fields=list(set(removed_fields)),
                modified_fields=list(set(modified_fields)),
                findings=record_findings,
            )
        )
    from datashield.scanner import SanitizeReport

    sreport = SanitizeReport(
        records=sanitized_records,
        total_original=len(data),
        total_removed=sum(len(r.removed_fields) for r in sanitized_records),
        total_modified=sum(len(r.modified_fields) for r in sanitized_records),
        total_findings=len(scan_report.findings),
        techniques_applied=[s.name for s in scanner.sanitizers],
    )
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            {
                "metadata": {
                    "timestamp": sreport.timestamp.isoformat(),
                    "total_original": sreport.total_original,
                    "total_removed": sreport.total_removed,
                    "total_modified": sreport.total_modified,
                    "techniques_applied": sreport.techniques_applied,
                },
                "records": [
                    {
                        "index": r.index,
                        "sanitized": r.sanitized,
                        "removed_fields": r.removed_fields,
                        "modified_fields": r.modified_fields,
                    }
                    for r in sreport.records
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    console.print(f"[green]Sanitized data written to:[/green] {output}")
    if report_output:
        _render_report(scan_report, format, report_output)


@app.command()
def anonymize(
    file: str = typer.Argument(..., help="Path to JSON dataset file"),
    output: str = typer.Argument(..., help="Output path for anonymized data"),
    epsilon: float = typer.Option(1.0, "--epsilon", help="Privacy budget epsilon"),
    k: int = typer.Option(5, "--k", help="k-anonymity parameter"),
    report_output: str | None = typer.Option(None, "--report", "-r", help="Output path for report"),
):
    """Anonymize a dataset using differential privacy and k-anonymity."""
    from datashield.privacy import DifferentialPrivacy, EpsilonCalculator, KAnonymity

    data = _load_data(file)
    dp = DifferentialPrivacy(epsilon=epsilon)
    ka = KAnonymity(k=k)
    calc = EpsilonCalculator()

    epsilon_estimate = calc.estimate(data)
    dp_report = dp.apply(data)
    k_report = ka.apply(data)

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            {
                "metadata": {
                    "epsilon": epsilon,
                    "k": k,
                    "epsilon_estimate": epsilon_estimate,
                    "dp_records_modified": dp_report.get("records_modified", 0),
                    "k_anonymity_satisfied": k_report.get("satisfied", False),
                },
                "data": dp_report.get("data", data),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    console.print(f"[green]Anonymized data written to:[/green] {output}")
    if report_output:
        from datashield.reporters import ConsoleReporter

        reporter = ConsoleReporter()
        reporter.report_anonymization(
            epsilon=epsilon,
            k=k,
            epsilon_estimate=epsilon_estimate,
            dp_modified=dp_report.get("records_modified", 0),
            k_satisfied=k_report.get("satisfied", False),
        )


@app.command()
def verify(
    file: str = typer.Argument(..., help="Path to sanitized JSON dataset file"),
    original: str = typer.Option("", "--original", help="Path to original dataset for comparison"),
    gdpr: bool = typer.Option(True, "--gdpr", help="Check GDPR compliance"),
    hipaa: bool = typer.Option(True, "--hipaa", help="Check HIPAA compliance"),
):
    """Verify compliance of a sanitized dataset with regulations."""
    from datashield.compliance import ComplianceVerifier, GDPRCompliance, HIPAACompliance

    data = _load_data(file)
    original_data = _load_data(original) if original else None
    verifier = ComplianceVerifier()
    results = []
    if gdpr:
        gdpr_check = GDPRCompliance()
        results.append(gdpr_check.verify(data))
    if hipaa:
        hipaa_check = HIPAACompliance()
        results.append(hipaa_check.verify(data))
    if original_data:
        verifier.compare(original_data, data)
    reporter = ConsoleReporter()
    reporter.report_compliance(results)


@app.command()
def report(
    file: str = typer.Argument(..., help="Path to JSON dataset file"),
    output: str = typer.Option("report.html", "--output", "-o", help="Output path"),
    format: str = typer.Option("html", "--format", "-f", help="Report format: html, json, console"),
    pii: bool = typer.Option(True, "--pii/--no-pii", help="Enable PII detection"),
    secrets: bool = typer.Option(True, "--secrets/--no-secrets", help="Enable secret scanning"),
):
    """Generate a comprehensive privacy report for a dataset."""
    data = _load_data(file)
    scanner = _build_scanner(enable_pii=pii, enable_secrets=secrets)
    scan_report = asyncio.run(scanner.scan(data))
    _render_report(scan_report, format, output)


def _render_report(report, format: str, output: str | None = None) -> None:
    if format == "json":
        reporter = JSONReporter()
        result = reporter.render(report)
    elif format == "html":
        reporter = HTMLReporter()
        result = reporter.render(report)
    else:
        reporter = ConsoleReporter()
        reporter.render(report)
        return
    if output:
        Path(output).write_text(result, encoding="utf-8")
        console.print(f"[green]Report written to:[/green] {output}")
    else:
        console.print(result)


def main() -> None:
    app()
