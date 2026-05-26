.PHONY: install test lint typecheck build clean

install:
	pip install -e ".[dev,taxonomy,presidio]"

test:
	python -m pytest tests/ -v --cov=datashield --tb=short

lint:
	ruff check src/datashield/ tests/

typecheck:
	mypy src/datashield/

build:
	hatch build

clean:
	rm -rf dist/ build/ *.egg-info .pytest_cache .ruff_cache .mypy_cache htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

fullcheck: lint typecheck test
