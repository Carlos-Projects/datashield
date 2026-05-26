from __future__ import annotations

from datashield.compliance.hipaa import _HIPAA_IDENTIFIERS, HIPAACompliance


class TestHIPAACompliance:
    def test_init(self):
        hipaa = HIPAACompliance()
        assert hipaa.name == "HIPAA"
        assert "privacy_rule" in hipaa.RULES

    def test_verify_clean_data(self):
        hipaa = HIPAACompliance()
        data = [{"id": 1, "score": 95}]
        result = hipaa.verify(data)
        assert result.regulation == "HIPAA"
        assert result.score >= 50

    def test_verify_with_phi(self):
        hipaa = HIPAACompliance()
        data = [{"name": "John Doe", "ssn": "123-45-6789"}]
        result = hipaa.verify(data)
        assert len(result.violations) >= 1

    def test_verify_with_medical_data(self):
        hipaa = HIPAACompliance()
        data = [{"diagnosis": "diabetes", "patient": "John"}]
        result = hipaa.verify(data)
        assert len(result.violations) >= 1

    def test_all_hipaa_identifiers(self):
        assert len(_HIPAA_IDENTIFIERS) == 19
        expected = {
            "name",
            "address",
            "dates",
            "telephone",
            "fax",
            "email",
            "ssn",
            "mrn",
            "health_plan",
            "account",
            "certificate",
            "license",
            "vehicle",
            "device",
            "url",
            "ip",
            "biometric",
            "photo",
            "fingerprint",
        }
        assert _HIPAA_IDENTIFIERS == expected

    def test_phi_with_pii_values_triggers_violation(self):
        hipaa = HIPAACompliance()
        data = [{"name": "John Doe", "email": "john@test.com", "ssn": "123-45-6789"}]
        result = hipaa.verify(data)
        assert not result.compliant
        assert len(result.violations) >= 1
        priv_checks = [c for c in result.checks if c.get("rule") == "privacy_rule"]
        assert not priv_checks[0]["passed"]

    def test_non_phi_data_passes(self):
        hipaa = HIPAACompliance()
        data = [{"irrelevant": "value", "counter": 42}]
        result = hipaa.verify(data)
        assert result.compliant
        assert len(result.violations) == 0
