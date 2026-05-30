# Contributing to DataShield

👋 **Welcome to DataShield!**

We're building privacy-preserving data sanitization tools for AI training — and we'd love your help. Whether you're adding a new detector, improving privacy algorithms, or fixing a bug, you're helping make AI safer and more responsible.

## First Time Contributor?

Here's how to get started:

- Search for issues labeled `good first issue`
- Add a new detector — the interface is simple and async
- Improve test coverage or documentation
- Report edge cases or suggest new detection patterns

We welcome contributions from everyone, regardless of experience level.

## Need Help?

Questions or feedback?

- Open a [GitHub Issue](https://github.com/Carlos-Projects/datashield/issues)
- Search existing issues first
- Be specific: share what you're trying to do and what's not working

## Development Setup

```bash
# Clone the repo
git clone https://github.com/Carlos-Projects/datashield.git
cd datashield

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in dev mode
pip install -e ".[dev]"
```

## Code Quality

```bash
# Lint
ruff check src/datashield/ tests/

# Type check
mypy src/datashield/

# Test
python -m pytest tests/ -v

# Test with coverage
python -m pytest tests/ -v --cov=datashield
```

## Pull Request Process

1. Fork the repo and create a feature branch
2. Add tests for new functionality
3. Ensure all tests pass and lint is clean
4. Update documentation if needed
5. Open a PR against `main`

## Coding Conventions

- Python 3.11+ with type hints
- Follow existing patterns in the codebase
- Add docstrings to public functions
- Use Pydantic v2 for data models
- Keep detectors stateless and async
- Test coverage > 80%

## Project Structure

- `src/datashield/detectors/` — Add new detection modules
- `src/datashield/sanitizers/` — Add new sanitization techniques
- `src/datashield/privacy/` — Add new privacy preservation methods
- `src/datashield/compliance/` — Add new regulation compliance checks
- `src/datashield/reporters/` — Add new output formats

---

💡 This project is governed by a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold its principles.
