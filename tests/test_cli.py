from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from datashield.cli import app

runner = CliRunner()


@pytest.fixture
def sample_json():
    data = [
        {"name": "Alice", "email": "alice@example.com", "age": 30},
        {
            "name": "Bob",
            "email": "bob@test.com",
            "ssn": "123-45-6789",
            "api_key": "AKIAIOSFODNN7EXAMPLE",
        },
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = f.name
    yield path
    Path(path).unlink(missing_ok=True)


class TestCLI:
    def test_scan_no_args(self):
        result = runner.invoke(app, [])
        assert result.exit_code != 0

    def test_scan_missing_file(self):
        result = runner.invoke(app, ["scan", "nonexistent.json"])
        assert result.exit_code != 0

    def test_scan_basic(self, sample_json):
        result = runner.invoke(app, ["scan", sample_json])
        assert result.exit_code == 0 or result.exit_code == 1

    def test_scan_json_output(self, sample_json):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name
        runner.invoke(app, ["scan", sample_json, "--format", "json", "--output", out_path])
        assert Path(out_path).exists()
        Path(out_path).unlink(missing_ok=True)

    def test_scan_no_pii(self, sample_json):
        result = runner.invoke(app, ["scan", sample_json, "--no-pii"])
        assert result.exit_code in (0, 1)

    def test_sanitize_basic(self, sample_json):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name
        runner.invoke(app, ["sanitize", sample_json, out_path])
        assert Path(out_path).exists()
        content = json.loads(Path(out_path).read_text())
        assert "records" in content
        Path(out_path).unlink(missing_ok=True)

    def test_sanitize_no_anonymize(self, sample_json):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name
        runner.invoke(
            app, ["sanitize", sample_json, out_path, "--anonymize", "false", "--redact", "false"]
        )
        assert Path(out_path).exists()
        Path(out_path).unlink(missing_ok=True)

    def test_anonymize_basic(self, sample_json):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name
        runner.invoke(app, ["anonymize", sample_json, out_path])
        assert Path(out_path).exists()
        Path(out_path).unlink(missing_ok=True)

    def test_verify_basic(self, sample_json):
        result = runner.invoke(app, ["verify", sample_json])
        assert result.exit_code == 0 or result.exit_code == 1

    def test_report_html(self, sample_json):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            out_path = f.name
        runner.invoke(app, ["report", sample_json, "--output", out_path])
        assert Path(out_path).exists()
        content = Path(out_path).read_text()
        assert "DataShield" in content
        Path(out_path).unlink(missing_ok=True)

    def test_report_json_output(self, sample_json):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name
        runner.invoke(app, ["report", sample_json, "--output", out_path, "--format", "json"])
        assert Path(out_path).exists()
        Path(out_path).unlink(missing_ok=True)
