# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-26

### Added

- PII Detection (emails, phones, SSNs, passports, national IDs, etc.)
- Secret Scanning (API keys, tokens, passwords, certificates, credentials)
- Sensitive Data Classification (medical, financial, legal, personal)
- Pattern Matching (32 regex patterns with ReDoS protection)
- Optional Presidio integration (ML-based PII detection)
- Anonymization with deterministic per-instance mapping
- Redaction (`[REDACTED]` replacement)
- Data Minimization (field removal while preserving required fields)
- Transformation (category-specific hashing, masking)
- Differential Privacy (Laplace/Gaussian noise, configurable epsilon)
- k-Anonymity (automatic quasi-identifier inference, generalization)
- Epsilon Calculator (optimal privacy budget estimation)
- GDPR Compliance (Art. 5, 9, 17, 25, 32, 35)
- HIPAA Compliance (18 PHI identifiers, Privacy/Security Rule)
- Compliance Verifier (verify_all, compare)
- Console/JSON/HTML Reporters
- CLI with 6 commands (scan, sanitize, anonymize, verify, report, policies)
- Multi-format Input (JSON, JSONL, CSV)
- Configuration via pydantic-settings (env vars, .env file)
- MCPGuard YAML Policy Generation
- mcp-taxonomy Adapter
- MCPscop Integration (async webhook client)
- Cryptographic Utilities (PBKDF2, HMAC, SHA-256, anonymization helpers)
- CI/CD (GitHub Actions: lint, test, typecheck matrix on 3.11, 3.12, 3.13)
- 202 tests with 92% coverage
