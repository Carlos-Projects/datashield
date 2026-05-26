# DataShield 🔒

**Privacy-preserving data sanitization for AI training.**

[![CI](https://github.com/Carlos-Projects/datashield/actions/workflows/ci.yml/badge.svg)](https://github.com/Carlos-Projects/datashield/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/datashield-ai.svg)](https://pypi.org/project/datashield-ai/)
[![Python versions](https://img.shields.io/pypi/pyversions/datashield-ai.svg)](https://pypi.org/project/datashield-ai/)
[![License](https://img.shields.io/github/license/Carlos-Projects/datashield.svg)](https://github.com/Carlos-Projects/datashield/blob/main/LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

DataShield detects and removes sensitive information (PII, secrets, medical, financial data) from datasets before fine-tuning or RAG. It implements anonymization, differential privacy, and data minimization techniques.

---

## Features

| Feature | Description |
|---------|-------------|
| **PII Detection** | Detects emails, phones, SSNs, passports, national IDs, and more |
| **Secret Scanning** | Finds API keys, tokens, passwords, certificates, and credentials |
| **Sensitive Classification** | Classifies medical, financial, legal, and personal data |
| **Anonymization** | Replaces sensitive values with anonymized tokens |
| **Redaction** | Replaces sensitive content with `[REDACTED]` |
| **Data Minimization** | Removes unnecessary fields while preserving required ones |
| **Transformation** | Applies category-specific transforms (hashing, masking, etc.) |
| **Differential Privacy** | Adds calibrated noise with configurable epsilon |
| **k-Anonymity** | Ensures each record is indistinguishable from k-1 others |
| **Compliance Verification** | Checks GDPR and HIPAA compliance |
| **HTML/JSON/Console Reports** | Rich reports for auditing and sharing |

## Installation

```bash
pip install datashield-ai
```

With Presidio support (enhanced PII detection):
```bash
pip install datashield-ai[presidio]
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

# Generate HTML report
datashield report dataset.json -o report.html
```

## Usage

### Scan a dataset

```bash
# Basic scan
datashield scan data.json

# Scan with specific detectors
datashield scan data.json --pii true --secrets true --classifier false

# Output JSON report
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

### Generate reports

```bash
# HTML report with visualizations
datashield report data.json -o report.html

# JSON report for programmatic use
datashield report data.json -o report.json --format json
```

## Integration with Ecosystem

| Project | Integration |
|---------|-------------|
| [MCPGuard](https://github.com/Carlos-Projects/mcpguard) | Generates MCPGuard-compatible data policies |
| [MCPscop](https://github.com/Carlos-Projects/mcpscope) | Reports consumable by MCPscop dashboard |
| [mcp-taxonomy](https://github.com/Carlos-Projects/mcp-taxonomy) | Uses shared taxonomy for cross-project normalization |
| [palisade-scanner](https://github.com/Carlos-Projects/palisade-scanner) | Same detector pattern and architecture |

## API

```python
import asyncio
from datashield.scanner import Scanner
from datashield.detectors import PIIDetector, SecretScanner

# Create scanner with detectors
scanner = Scanner(detectors=[PIIDetector(), SecretScanner()])

# Scan dataset
data = [{"email": "user@example.com", "api_key": "sk-1234"}]
report = asyncio.run(scanner.scan(data))

print(f"Risk score: {report.risk_score}")
print(f"Findings: {report.total_findings}")
```

## Project Structure

```
datashield/
├── src/datashield/
│   ├── cli.py              # Typer CLI interface
│   ├── scanner.py           # Core scanning engine + models
│   ├── detectors/           # Detection modules
│   │   ├── pii_detector.py
│   │   ├── secret_scanner.py
│   │   ├── sensitive_classifier.py
│   │   └── pattern_matcher.py
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
│   └── utils/
│       └── crypto.py        # Cryptographic utilities
└── tests/                   # 60+ tests
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

## License

MIT — see [LICENSE](LICENSE)

## Author

**Carlos Rocha** — [carlos@carlosrocha.dev](mailto:carlos@carlosrocha.dev)
