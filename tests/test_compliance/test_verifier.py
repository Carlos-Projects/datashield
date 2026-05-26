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

    def test_verify_all_clean(self):
        verifier = ComplianceVerifier()
        results = verifier.verify_all([{"id": 1}])
        assert len(results) == 2
        assert all(r.regulation in ("GDPR", "HIPAA") for r in results)

    def test_verify_all_with_pii(self):
        verifier = ComplianceVerifier()
        results = verifier.verify_all([{"email": "user@test.com", "ssn": "123-45-6789"}])
        assert len(results) == 2
        gdpr = next(r for r in results if r.regulation == "GDPR")
        hipaa = next(r for r in results if r.regulation == "HIPAA")
        assert not gdpr.compliant
        assert not hipaa.compliant

    def test_verify_all_empty(self):
        verifier = ComplianceVerifier()
        results = verifier.verify_all([])
        assert len(results) == 2
        assert verifier._results == results
