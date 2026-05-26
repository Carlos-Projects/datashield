from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
import typer

from datashield.cli import _load_data


@pytest.fixture
def json_file():
    data = [{"a": 1}, {"b": 2}]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = f.name
    yield path
    Path(path).unlink(missing_ok=True)


@pytest.fixture
def jsonl_file():
    lines = ['{"a": 1}', '{"b": 2}']
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write("\n".join(lines))
        path = f.name
    yield path
    Path(path).unlink(missing_ok=True)


@pytest.fixture
def csv_file():
    content = "name,age\nAlice,30\nBob,25\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write(content)
        path = f.name
    yield path
    Path(path).unlink(missing_ok=True)


class TestLoadData:
    def test_json(self, json_file):
        data = _load_data(json_file)
        assert len(data) == 2
        assert data[0] == {"a": 1}

    def test_jsonl(self, jsonl_file):
        data = _load_data(jsonl_file)
        assert len(data) == 2
        assert data[0] == {"a": 1}

    def test_csv(self, csv_file):
        data = _load_data(csv_file)
        assert len(data) == 2
        assert data[0]["name"] == "Alice"
        assert data[0]["age"] == "30"

    def test_json_with_format_override(self, csv_file):
        with pytest.raises(typer.Exit):
            _load_data(csv_file, fmt="jsonl")

    def test_missing_file(self):
        with pytest.raises(typer.Exit):
            _load_data("/nonexistent/path.json")
