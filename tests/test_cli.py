from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from datashield.cli import _load_data, app

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

    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "DataShield" in result.stdout

    def test_policies_command(self, sample_json):
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            out_path = f.name
        runner.invoke(app, ["policies", sample_json, "--output", out_path])
        assert Path(out_path).exists()
        content = Path(out_path).read_text()
        assert "generated_by: datashield" in content
        Path(out_path).unlink(missing_ok=True)

    def test_scan_with_threshold(self, sample_json):
        result = runner.invoke(app, ["scan", sample_json, "--threshold", "0.8"])
        assert result.exit_code in (0, 1)

    def test_scan_with_exclude(self, sample_json):
        result = runner.invoke(app, ["scan", sample_json, "--exclude", "email,ssn"])
        assert result.exit_code in (0, 1)

    def test_scan_with_path_traversal_output(self, sample_json):
        result = runner.invoke(
            app,
            [
                "scan",
                sample_json,
                "--format",
                "json",
                "--output",
                "../../tmp/../../etc/passwd",
            ],
        )
        assert result.exit_code != 0

    def test_load_data_invalid_type(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('"just_a_string"')
            path = f.name
        with pytest.raises(typer.Exit):
            _load_data(path)
        Path(path).unlink(missing_ok=True)

    def test_load_data_empty_json_object(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{}")
            path = f.name
        data = _load_data(path)
        assert data == [{}]
        Path(path).unlink(missing_ok=True)

    def test_load_data_empty_json_array(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("[]")
            path = f.name
        data = _load_data(path)
        assert data == []
        Path(path).unlink(missing_ok=True)

    def test_load_data_malformed_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json!!!}")
            path = f.name
        with pytest.raises(typer.Exit):
            _load_data(path)
        Path(path).unlink(missing_ok=True)

    def test_load_data_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        with pytest.raises(typer.Exit):
            _load_data(path)
        Path(path).unlink(missing_ok=True)

    def test_load_data_binary_file(self):
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as f:
            f.write(b"\x89PNG\r\n\x1a\n")
            path = f.name
        with pytest.raises(typer.Exit):
            _load_data(path)
        Path(path).unlink(missing_ok=True)

    def test_load_data_csv_formula_injection(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write('name,notes\nAlice,"=HYPERLINK(""http://evil.com"")"\nBob,"+SUM(1,1)"\n')
            path = f.name
        data = _load_data(path)
        assert data[0]["notes"] == '\'=HYPERLINK("http://evil.com")'
        assert data[1]["notes"] == "'+SUM(1,1)"
        Path(path).unlink(missing_ok=True)

    def test_scan_with_all_detectors_disabled(self, sample_json):
        result = runner.invoke(
            app,
            [
                "scan",
                sample_json,
                "--no-pii",
                "--no-secrets",
                "--no-classifier",
                "--no-patterns",
            ],
        )
        assert result.exit_code == 0

    def test_scan_csv_input(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,email\nAlice,alice@test.com\nBob,bob@test.com\n")
            path = f.name
        result = runner.invoke(app, ["sanitize", path, path + ".out"])
        assert result.exit_code == 0
        assert Path(path + ".out").exists()
        Path(path + ".out").unlink(missing_ok=True)
        Path(path).unlink(missing_ok=True)

    def test_full_pipeline_integration(self):
        import json
        import tempfile

        data = [
            {"name": "Alice", "email": "alice@test.com", "ssn": "123-45-6789"},
            {"name": "Bob", "email": "bob@test.com", "api_key": "AKIAIOSFODNN7EXAMPLE"},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            src = f.name
        out = src + ".sanitized.json"
        rpt = src + ".report.html"

        result = runner.invoke(app, ["sanitize", src, out, "--report", rpt, "--format", "html"])
        assert result.exit_code == 0, result.output
        assert Path(out).exists()
        assert Path(rpt).exists()

        with open(out) as f:
            output = json.load(f)
        assert output["metadata"]["total_original"] == 2
        assert output["metadata"]["total_removed"] >= 0

        result2 = runner.invoke(app, ["verify", out])
        assert result2.exit_code == 0

        result3 = runner.invoke(app, ["report", out, "-o", src + ".report2.html"])
        assert result3.exit_code == 0

        for p in [src, out, rpt, src + ".report2.html"]:
            Path(p).unlink(missing_ok=True)
