# Security Policy

## Reporting a Vulnerability

DataShield is a security tool that handles sensitive data. If you discover a security vulnerability, please report it privately.

**Do not report security vulnerabilities through public GitHub issues.**

Instead, email **carlos@carlosrocha.dev** with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

You should receive a response within 48 hours. If you don't, please follow up.

## Supported Versions

| Version | Supported          |
|---------|-------------------|
| 0.1.x   | :white_check_mark: |

## Security Considerations

- DataShield processes data locally — no data is sent to external services
- All detection is done via regex patterns and local classification
- Differential privacy noise is added server-side before any data sharing
- Reports are generated locally and stored at user-specified paths
- The `presidio` integration is optional and runs locally
