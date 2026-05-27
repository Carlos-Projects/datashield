# DataShield 🔒

**Privacy-preserving data sanitization for AI training.**

[![CI](https://github.com/Carlos-Projects/datashield/actions/workflows/ci.yml/badge.svg)](https://github.com/Carlos-Projects/datashield/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/datashield-ai.svg?label=PyPI)](https://pypi.org/project/datashield-ai/)
[![Python versions](https://img.shields.io/pypi/pyversions/datashield-ai.svg)](https://pypi.org/project/datashield-ai/)
[![License](https://img.shields.io/github/license/Carlos-Projects/datashield.svg)](https://github.com/Carlos-Projects/datashield/blob/main/LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Coverage](https://img.shields.io/badge/coverage-92%25-brightgreen.svg)](tests/)

DataShield detects and removes sensitive information (PII, secrets, medical, financial data) from datasets before fine-tuning or RAG. It implements anonymization, differential privacy, and data minimization techniques.

---

## Features

| Feature | Description |
|---------|-------------|
| **PII Detection** | Detects emails, phones, SSNs, passports, national IDs, and more |
| **Secret Scanning** | Finds API keys, tokens, passwords, certificates, and credentials |
| **Sensitive Classification** | Classifies medical, financial, legal, and personal data by keywords |
| **Presidio Detection** | Optional ML-powered PII detection via Microsoft Presidio |
| **Anonymization** | Replaces sensitive values with anonymized tokens (deterministic) |
| **Redaction** | Replaces sensitive content with `[REDACTED]` |
| **Data Minimization** | Removes unnecessary fields while preserving required ones |
| **Transformation** | Applies category-specific transforms (hashing, masking, etc.) |
| **Differential Privacy** | Adds calibrated Laplace/Gaussian noise with configurable epsilon |
| **k-Anonymity** | Ensures each record is indistinguishable from k-1 others |
| **Epsilon Calculator** | Estimates optimal privacy budget based on dataset characteristics |
| **GDPR Compliance** | Checks Art. 5, 9, 17, 25, 32, 35 compliance |
| **HIPAA Compliance** | Checks Privacy Rule, Security Rule, Minimum Necessary |
| **MCPGuard Policies** | Generates MCPGuard-compatible YAML security policies |
| **mcp-taxonomy Adapter** | Normalizes findings to the canonical MCP security taxonomy |
| **MCPscop Integration** | Forwards findings to MCPscop dashboard via webhook |
| **HTML/JSON/Console Reports** | Rich reports for auditing and sharing |
| **Multi-format Input** | Supports JSON, JSONL, and CSV datasets |

## Installation

```bash
pip install datashield-ai
```

With Presidio support (enhanced ML-based PII detection):
```bash
pip install datashield-ai[presidio]
```

With taxonomy integration:
```bash
pip install datashield-ai[taxonomy]
```

## Quick Start

```bash
# Scan a dataset for sensitive data
datashield scan dataset.json

# Sanitize a dataset (detect + anonymize)
datashield sanitize dataset.json sanitized.json

# Anonymize with differential privacy
datashield anonymize dataset.json anonymized.json --epsilon 0.5 --k 5

# Verify compliance
datashield verify sanitized.json

# Generate MCPGuard policy
datashield policies dataset.json -o mcpguard_policy.yaml

# Generate HTML report
datashield report dataset.json -o report.html
```

## Usage

### Scan a dataset

```bash
# Basic scan (auto-detects format from extension)
datashield scan data.json
datashield scan data.jsonl
datashield scan data.csv

# Scan with confidence threshold
datashield scan data.json --threshold 0.6

# Exclude certain fields
datashield scan data.json --exclude metadata,internal_id

# Forward findings to MCPscop dashboard
datashield scan data.json --mcpscop

# Output as JSON
datashield scan data.json --format json -o scan_report.json
```

### Sanitize a dataset

```bash
# Detect and anonymize sensitive data
datashield sanitize data.json sanitized.json

# Full pipeline with all techniques
datashield sanitize data.json sanitized.json \
  --anonymize true --redact true --minimize true --transform true

# Generate scan report alongside sanitized data
datashield sanitize data.json sanitized.json -r report.html
```

### Anonymize with privacy guarantees

```bash
# Differential privacy + k-anonymity
datashield anonymize data.json anonymized.json --epsilon 1.0 --k 5
```

### Verify compliance

```bash
# Check GDPR and HIPAA compliance
datashield verify sanitized.json

# Compare with original
datashield verify sanitized.json --original original.json
```

### Generate MCPGuard policies

```bash
# Generate YAML security policy from dataset findings
datashield policies dataset.json -o mcpguard_policy.yaml

# Specify custom MCPGuard target
datashield policies dataset.json --target http://my-mcp-server:8000
```

### Generate reports

```bash
# HTML report with visualizations
datashield report data.json -o report.html

# JSON report for programmatic use
datashield report data.json -o report.json --format json
```

## Configuration

DataShield supports configuration via environment variables (prefix `DATASHIELD_`) or a `.env` file:

```bash
# .env
DATASHIELD_THRESHOLD=0.5
DATASHIELD_EXCLUDE_FIELDS=metadata,debug
DATASHIELD_DEFAULT_EPSILON=0.5
DATASHIELD_DEFAULT_K=10
DATASHIELD_MCPSCOP_URL=http://mcpscop:8080
DATASHIELD_MCPSCOP_API_KEY=your-key
```

## Integration with Ecosystem

| Project | Integration |
|---------|-------------|
| [MCPGuard](https://github.com/Carlos-Projects/mcpguard) | Generates MCPGuard-compatible YAML data policies via `datashield policies` |
| [MCPscop](https://github.com/Carlos-Projects/mcpscope) | Forwards normalized findings via `--mcpscop` flag or `MCPscopClient` API |
| [mcp-taxonomy](https://github.com/Carlos-Projects/mcp-taxonomy) | Normalizes findings to canonical taxonomy via `datashield_finding_to_taxonomy()` |
| [palisade-scanner](https://github.com/Carlos-Projects/palisade-scanner) | Same detector pattern and architecture |

## API

```python
import asyncio
from datashield.scanner import Scanner
from datashield.detectors import PIIDetector, SecretScanner, PresidioDetector
from datashield.taxonomy import datashield_finding_to_taxonomy
from datashield.policies.mcpguard import MCPGuardPolicyGenerator

# Create scanner with detectors
scanner = Scanner(detectors=[PIIDetector(), SecretScanner()])

# Scan dataset
data = [{"email": "user@example.com", "api_key": "sk-1234"}]
report = asyncio.run(scanner.scan(data))

print(f"Risk score: {report.risk_score}")
print(f"Findings: {report.total_findings}")

# Normalize to mcp-taxonomy
for finding in report.findings:
    event = datashield_finding_to_taxonomy(finding)
    print(f"  → {event.attack_category.value}: {event.title}")

# Generate MCPGuard policy
gen = MCPGuardPolicyGenerator()
policy = gen.from_findings(report.findings)
print(gen.to_yaml(policy))
```

## Project Structure

```
datashield/
├── src/datashield/
│   ├── cli.py              # Typer CLI interface (6 commands)
│   ├── scanner.py           # Core scanning engine + Pydantic models
│   ├── config.py            # pydantic-settings configuration
│   ├── taxonomy.py          # mcp-taxonomy adapter
│   ├── detectors/           # Detection modules
│   │   ├── pii_detector.py
│   │   ├── secret_scanner.py
│   │   ├── sensitive_classifier.py
│   │   ├── pattern_matcher.py
│   │   └── presidio_detector.py   # Optional ML-based PII detection
│   ├── sanitizers/          # Sanitization modules
│   │   ├── anonymizer.py
│   │   ├── redactor.py
│   │   ├── minimizer.py
│   │   └── transformer.py
│   ├── privacy/             # Privacy preservation
│   │   ├── differential.py
│   │   ├── k_anonymity.py
│   │   └── epsilon_calculator.py
│   ├── compliance/          # Compliance verification
│   │   ├── gdpr.py
│   │   ├── hipaa.py
│   │   └── verifier.py
│   ├── reporters/           # Output formats
│   │   ├── console.py       # Rich console output
│   │   ├── json.py
│   │   └── html.py          # Jinja2 HTML reports
│   ├── policies/            # Policy generation
│   │   └── mcpguard.py      # MCPGuard YAML policy generator
│   ├── integrations/        # Ecosystem integrations
│   │   └── mcpscop.py       # MCPscop webhook client
│   └── utils/
│       └── crypto.py        # Cryptographic utilities
└── tests/                   # 202+ tests (92% coverage)
```

## Compliance

DataShield helps verify compliance with:

- **GDPR** (Art. 5, 9, 17, 25, 32, 35) — Data minimization, right to erasure, DPIA
- **HIPAA** (Privacy Rule, Security Rule, Breach Rule) — PHI de-identification, minimum necessary

## Academic References

- [arXiv:2605.25716](https://arxiv.org/abs/2605.25716) — Efficient and Privacy-Preserving Architecture for Cross-Institutional Collaborative RAG
- [arXiv:2605.25791](https://arxiv.org/abs/2605.25791) — Efficient and Privacy-Preserving Distribution Statistics Analytics on Mobile Spatial Data
- [arXiv:2605.25002](https://arxiv.org/abs/2605.25002) — Verifiable Secure Aggregation via Dual Servers with Linear Tags
- [arXiv:2605.26019](https://arxiv.org/abs/2605.26019) — Retrieval-Augmented Detection of Potentially Abusive Clauses

## Troubleshooting

### "mcp_taxonomy is required" error

The taxonomy adapter requires `mcp-taxonomy`. Install it with:

```bash
pip install datashield-ai[taxonomy]
```

If you don't need taxonomy integration, this error means you're calling
`datashield_finding_to_taxonomy()` directly — the CLI commands work without it.

### Presidio not found

Presidio-based PII detection requires:

```bash
pip install datashield-ai[presidio]
```

This downloads models (~500 MB) on first use.

### Large files causing memory errors

DataShield loads the entire file into memory. For files >500 MB, set:

```bash
export DATASHIELD_MAX_SIZE_MB=1000
```

Or pass `--max-size` if available. Streaming support is planned for a future release.

### How to interpret risk scores

| Score | Category | Meaning |
|-------|----------|---------|
| 70+ | Critical | High-risk data (credentials, keys) present |
| 40-69 | High | PII/secrets detected, immediate action needed |
| 20-39 | Medium | Some sensitive fields found |
| 5-19 | Low | Minor privacy concerns |
| <5 | Safe | No significant risks detected |

### Getting help

```bash
datashield --help          # Top-level help
datashield scan --help     # Help for a specific command
datashield --version       # Show version
```

## License

MIT — see [LICENSE](LICENSE)

## Author

**Carlos Rocha** — [carlos@carlosrocha.dev](mailto:carlos@carlosrocha.dev)
