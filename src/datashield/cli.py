from __future__ import annotations

import asyncio
import csv
import json
from io import StringIO
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from datashield.config import settings
from datashield.detectors import PatternMatcher, PIIDetector, SecretScanner, SensitiveClassifier
from datashield.reporters import ConsoleReporter, HTMLReporter, JSONReporter
from datashield.sanitizers import Anonymizer, Minimizer, Redactor, Transformer
from datashield.scanner import (
    BaseDetector,
    BaseSanitizer,
    SanitizeReport,
    Scanner,
    ScanReport,
)

_CONF_WEIGHTS = {"high": 0.8, "medium": 0.5, "low": 0.2}
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@")
_QUIET = False


def _version_callback(value: bool) -> None:
    if value:
        from datashield import __version__ as ver

        _print(f"DataShield v{ver}")
        raise typer.Exit()


def _quiet_callback(value: bool) -> None:
    global _QUIET  # noqa: PLW0603
    _QUIET = value


def _print(*args: Any, **kwargs: Any) -> None:
    if not _QUIET:
        Console().print(*args, **kwargs)


def _main_callback(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show version and exit",
        callback=_version_callback,
        is_eager=True,
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress all non-error output",
        callback=_quiet_callback,
        is_eager=True,
    ),
) -> None:
    pass


app = typer.Typer(
    name="datashield",
    help="DataShield — Data sanitization with privacy preservation for AI training",
    no_args_is_help=True,
    callback=_main_callback,
)
console = Console()


def _check_file_size(path: str, max_mb: int) -> None:
    size = Path(path).stat().st_size
    max_bytes = max_mb * 1024 * 1024
    if size > max_bytes:
        _print(
            f"[red]File too large:[/red] {size / 1024 / 1024:.1f} MB "
            f"(max {max_mb} MB). Use --max-size to increase."
        )
        raise typer.Exit(1)


def _sanitize_csv_value(val: str) -> str:
    if val and val[0] in _CSV_FORMULA_PREFIXES:
        return "'" + val
    return val


def _load_data(
    path: str, fmt: str | None = None, max_size_mb: int | None = None
) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        _print(f"[red]File not found:[/red] {path}")
        raise typer.Exit(1)

    ext = (fmt or p.suffix).lstrip(".").lower()
    _check_file_size(path, max_size_mb or settings.max_size_mb)
    try:
        raw = p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        _print(f"[red]File is not valid UTF-8 text:[/red] {path}")
        raise typer.Exit(1) from None

    if ext in ("csv",):
        data = _load_csv(raw)
        for record in data:
            for k, v in record.items():
                record[k] = _sanitize_csv_value(v) if isinstance(v, str) else v
        return data
    if ext in ("jsonl", "ndjson"):
        return _load_jsonl(raw)
    return _load_json(raw)


def _load_json(raw: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        _print(f"[red]Invalid JSON:[/red] {e}")
        raise typer.Exit(1) from e
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    _print("[red]Unsupported JSON format. Expected object or array.[/red]")
    raise typer.Exit(1)


def _load_jsonl(raw: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for i, line in enumerate(raw.strip().split("\n"), 1):
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as e:
            _print(f"[red]Invalid JSONL line {i}:[/red] {e}")
            raise typer.Exit(1) from e
    return records


def _load_csv(raw: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(StringIO(raw))
    return list(reader)


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
    detectors: list[BaseDetector] = []
    sanitizers: list[BaseSanitizer] = []
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


async def _send_to_mcpscop(report: ScanReport, url: str, api_key: str | None) -> None:
    from datashield.integrations.mcpscop import MCPscopClient

    client = MCPscopClient(url, api_key)
    try:
        await client.send_report(report)
        _print("[blue]Report forwarded to MCPscop[/blue]")
    except Exception as e:
        _print(f"[yellow]Failed to send to MCPscop:[/yellow] {e}")
    finally:
        await client.close()


@app.command()
def scan(
    file: str = typer.Argument(..., help="Path to dataset file (JSON, JSONL, CSV)"),
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
    threshold: float = typer.Option(
        settings.threshold, "--threshold", "-t", help="Minimum confidence threshold (0-1)"
    ),
    exclude_fields: str | None = typer.Option(
        None, "--exclude", "-x", help="Fields to exclude (comma-separated)"
    ),
    input_format: str | None = typer.Option(
        None, "--input-format", help="Input format: json, jsonl, csv (auto-detected from extension)"
    ),
    mcpscop: bool = typer.Option(False, "--mcpscop", help="Forward findings to MCPscop"),
):
    """Scan a dataset for sensitive data and privacy risks."""
    data = _load_data(file, input_format)
    exclude_list = exclude_fields.split(",") if exclude_fields else settings.exclude_fields
    scanner = _build_scanner(
        enable_pii=pii,
        enable_secrets=secrets,
        enable_classifier=classifier,
        enable_patterns=patterns,
    )
    report = asyncio.run(scanner.scan(data, threshold=threshold, exclude=exclude_list))
    _render_report(report, format, output)
    if mcpscop and settings.mcpscop_url:
        asyncio.run(_send_to_mcpscop(report, settings.mcpscop_url, settings.mcpscop_api_key))
    if report.risk_score >= 40:
        raise typer.Exit(1)


@app.command()
def sanitize(
    file: str = typer.Argument(..., help="Path to dataset file (JSON, JSONL, CSV)"),
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
    threshold: float = typer.Option(
        settings.threshold, "--threshold", "-t", help="Minimum confidence threshold (0-1)"
    ),
    exclude_fields: str | None = typer.Option(
        None, "--exclude", "-x", help="Fields to exclude (comma-separated)"
    ),
    input_format: str | None = typer.Option(
        None, "--input-format", help="Input format: json, jsonl, csv"
    ),
    mcpscop: bool = typer.Option(False, "--mcpscop", help="Forward findings to MCPscop"),
):
    """Sanitize a dataset by detecting and removing/obfuscating sensitive data."""
    data = _load_data(file, input_format)
    exclude_list = exclude_fields.split(",") if exclude_fields else settings.exclude_fields
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
    scan_report = asyncio.run(scanner.scan(data, threshold=threshold, exclude=exclude_list))

    all_records = [dict(r) for r in data]
    for sanitizer in scanner.sanitizers:
        records_copy = [dict(r) for r in all_records]
        result = asyncio.run(sanitizer.sanitize(records_copy, scan_report.findings))
        for i, sr in enumerate(result):
            if i < len(all_records):
                all_records[i] = sr.sanitized

    from datashield.scanner import SanitizedRecord

    sanitized_records = []
    for i, (original, sanitized) in enumerate(zip(data, all_records, strict=True)):
        removed = [k for k in original if k not in sanitized]
        modified = [k for k in sanitized if k in original and sanitized[k] != original[k]]
        record_findings = [
            f for f in scan_report.findings if f.field_path in original or f.field_path is None
        ]
        sanitized_records.append(
            SanitizedRecord(
                index=i,
                original=original,
                sanitized=sanitized,
                removed_fields=removed,
                modified_fields=modified,
                findings=record_findings,
            )
        )
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
    _print(f"[green]Sanitized data written to:[/green] {output}")
    if mcpscop and settings.mcpscop_url:
        asyncio.run(_send_to_mcpscop(scan_report, settings.mcpscop_url, settings.mcpscop_api_key))
    if report_output:
        _render_report(scan_report, format, report_output)


@app.command()
def anonymize(
    file: str = typer.Argument(..., help="Path to dataset file (JSON, JSONL, CSV)"),
    output: str = typer.Argument(..., help="Output path for anonymized data"),
    epsilon: float = typer.Option(
        settings.default_epsilon, "--epsilon", help="Privacy budget epsilon"
    ),
    k: int = typer.Option(settings.default_k, "--k", help="k-anonymity parameter"),
    report_output: str | None = typer.Option(None, "--report", "-r", help="Output path for report"),
    input_format: str | None = typer.Option(
        None, "--input-format", help="Input format: json, jsonl, csv"
    ),
):
    """Anonymize a dataset using differential privacy and k-anonymity."""
    from datashield.privacy import DifferentialPrivacy, EpsilonCalculator, KAnonymity

    data = _load_data(file, input_format)
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
    _print(f"[green]Anonymized data written to:[/green] {output}")
    if report_output:
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
    file: str = typer.Argument(..., help="Path to sanitized dataset file"),
    original: str = typer.Option("", "--original", help="Path to original dataset for comparison"),
    gdpr: bool = typer.Option(True, "--gdpr", help="Check GDPR compliance"),
    hipaa: bool = typer.Option(True, "--hipaa", help="Check HIPAA compliance"),
    input_format: str | None = typer.Option(
        None, "--input-format", help="Input format: json, jsonl, csv"
    ),
):
    """Verify compliance of a sanitized dataset with regulations."""
    from datashield.compliance import ComplianceVerifier, GDPRCompliance, HIPAACompliance

    data = _load_data(file, input_format)
    original_data = _load_data(original, input_format) if original else None
    verifier = ComplianceVerifier()
    results: list[Any] = []
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
    file: str = typer.Argument(..., help="Path to dataset file"),
    output: str = typer.Option("report.html", "--output", "-o", help="Output path"),
    format: str = typer.Option("html", "--format", "-f", help="Report format: html, json, console"),
    pii: bool = typer.Option(True, "--pii/--no-pii", help="Enable PII detection"),
    secrets: bool = typer.Option(True, "--secrets/--no-secrets", help="Enable secret scanning"),
    threshold: float = typer.Option(
        settings.threshold, "--threshold", "-t", help="Minimum confidence threshold (0-1)"
    ),
    input_format: str | None = typer.Option(
        None, "--input-format", help="Input format: json, jsonl, csv"
    ),
):
    """Generate a comprehensive privacy report for a dataset."""
    data = _load_data(file, input_format)
    scanner = _build_scanner(enable_pii=pii, enable_secrets=secrets)
    scan_report = asyncio.run(scanner.scan(data, threshold=threshold))
    _render_report(scan_report, format, output)


@app.command()
def policies(
    file: str = typer.Argument(..., help="Path to dataset file"),
    output: str = typer.Option("mcpguard_policy.yaml", "--output", "-o", help="Output YAML path"),
    target_url: str = typer.Option("http://localhost:8000", "--target", help="MCPGuard target URL"),
    input_format: str | None = typer.Option(
        None, "--input-format", help="Input format: json, jsonl, csv"
    ),
):
    """Generate an MCPGuard-compatible YAML policy from dataset findings."""
    from datashield.policies.mcpguard import MCPGuardPolicyGenerator

    data = _load_data(file, input_format)
    scanner = _build_scanner()
    scan_report = asyncio.run(scanner.scan(data))
    gen = MCPGuardPolicyGenerator()
    policy = gen.from_scan_report(scan_report, target_url=target_url)
    gen.save(output, policy)
    _print(f"[green]MCPGuard policy written to:[/green] {output}")


def _render_report(report: ScanReport, format: str, output: str | None = None) -> None:
    result: str | None = None
    if format == "json":
        result = JSONReporter().render(report)
    elif format == "html":
        result = HTMLReporter().render(report)
    else:
        ConsoleReporter().render(report)
        return
    if output and result is not None:
        Path(output).write_text(result, encoding="utf-8")
        _print(f"[green]Report written to:[/green] {output}")
    elif result is not None:
        _print(result)


def main() -> None:
    """Entry point for `python -m datashield`."""
    app()
