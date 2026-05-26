from __future__ import annotations

from datashield.compliance.verifier import ComplianceVerifier


class TestComplianceVerifier:
    def test_init(self):
        verifier = ComplianceVerifier()
        assert verifier._results == []

    def test_compare_empty(self):
        verifier = ComplianceVerifier()
        result = verifier.compare([], [])
        assert result["original_pii_fields"] == 0
        assert result["reduction_percentage"] == 0

    def test_compare_with_reduction(self):
        verifier = ComplianceVerifier()
        original = [{"email": "a@b.com", "name": "Alice"}]
        sanitized = [{"name": "Alice"}]
        result = verifier.compare(original, sanitized)
        assert result["fields_removed"] >= 1

    def test_compare_no_reduction(self):
        verifier = ComplianceVerifier()
        original = [{"id": 1}]
        sanitized = [{"id": 1}]
        result = verifier.compare(original, sanitized)
        assert result["fields_removed"] == 0
