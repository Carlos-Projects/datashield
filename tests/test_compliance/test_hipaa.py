from __future__ import annotations

from datashield.compliance.hipaa import HIPAACompliance


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
