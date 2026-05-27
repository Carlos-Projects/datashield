from __future__ import annotations

from datashield.compliance.gdpr import GDPRCompliance


class TestGDPRCompliance:
    def test_init(self):
        gdpr = GDPRCompliance()
        assert gdpr.name == "GDPR"
        assert "art_5" in gdpr.ARTICLES

    def test_verify_clean_data(self):
        gdpr = GDPRCompliance()
        data = [{"id": 1, "is_active": True}]
        result = gdpr.verify(data)
        assert result.regulation == "GDPR"
        assert len(result.checks) > 0

    def test_verify_with_pii(self):
        gdpr = GDPRCompliance()
        data = [{"email": "user@example.com", "name": "John Doe"}]
        result = gdpr.verify(data)
        assert len(result.violations) >= 1

    def test_verify_with_special_categories(self):
        gdpr = GDPRCompliance()
        data = [{"notes": "diagnosis: diabetes"}]
        result = gdpr.verify(data)
        assert len(result.violations) >= 1
