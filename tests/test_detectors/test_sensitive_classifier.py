from __future__ import annotations

import pytest

from datashield.detectors.sensitive_classifier import SensitiveClassifier
from datashield.scanner import DataCategory


@pytest.fixture
def classifier():
    return SensitiveClassifier()


class TestSensitiveClassifier:
    async def test_classify_medical(self, classifier):
        findings = await classifier.detect([{"diagnosis": "diabetes", "patient": "John"}])
        medical = [f for f in findings if f.category == DataCategory.MEDICAL]
        assert len(medical) >= 1

    async def test_classify_financial(self, classifier):
        findings = await classifier.detect([{"credit_card": "my credit card number is sensitive"}])
        financial = [f for f in findings if f.category == DataCategory.FINANCIAL]
        assert len(financial) >= 1

    async def test_classify_legal(self, classifier):
        findings = await classifier.detect([{"ssn": "123-45-6789", "contract": "NDA agreement"}])
        legal = [f for f in findings if f.category == DataCategory.LEGAL]
        assert len(legal) >= 1

    async def test_classify_personal(self, classifier):
        findings = await classifier.detect(
            [{"full_name": "John Doe", "date_of_birth": "1990-01-01"}]
        )
        personal = [f for f in findings if f.category == DataCategory.PERSONAL]
        assert len(personal) >= 1

    async def test_no_false_positives(self, classifier):
        findings = await classifier.detect([{"count": 42, "active": True}])
        assert len(findings) == 0

    async def test_nested_records(self, classifier):
        findings = await classifier.detect(
            [
                {
                    "profile": {
                        "medical": {"diagnosis": "hypertension"},
                        "financial": {"credit_score": "low"},
                    }
                }
            ]
        )
        assert len(findings) >= 2

    async def test_confidence_levels(self, classifier):
        findings = await classifier.detect([{"diagnosis": "cancer", "patient": "John Doe"}])
        for f in findings:
            assert f.confidence in ("low", "medium", "high")

    async def test_keyword_in_field_name(self, classifier):
        findings = await classifier.detect([{"diagnosis_code": "12345"}])
        medical = [f for f in findings if f.category == DataCategory.MEDICAL]
        assert len(medical) >= 1
