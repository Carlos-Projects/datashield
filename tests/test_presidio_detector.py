from __future__ import annotations

import pytest

from datashield.detectors.presidio_detector import (
    _PRESIDIO_ENTITY_MAP,
    PresidioDetector,
)


class TestPresidioEntityMap:
    def test_entity_map_has_expected_entities(self):
        assert "PERSON" in _PRESIDIO_ENTITY_MAP
        assert "EMAIL_ADDRESS" in _PRESIDIO_ENTITY_MAP
        assert "CREDIT_CARD" in _PRESIDIO_ENTITY_MAP
        assert "US_SSN" in _PRESIDIO_ENTITY_MAP
        assert "PHONE_NUMBER" in _PRESIDIO_ENTITY_MAP
        assert "IP_ADDRESS" in _PRESIDIO_ENTITY_MAP
        assert len(_PRESIDIO_ENTITY_MAP) >= 15

    def test_entity_map_values(self):
        person = _PRESIDIO_ENTITY_MAP["PERSON"]
        assert person[0].value == "personal"
        assert person[1].value == "medium"

        cc = _PRESIDIO_ENTITY_MAP["CREDIT_CARD"]
        assert cc[0].value == "financial"
        assert cc[1].value == "critical"


class TestPresidioDetector:
    def test_raises_without_presidio(self):
        detector = PresidioDetector()
        with pytest.raises(ImportError, match="presidio-analyzer is not installed"):
            detector._get_engine()

    def test_detector_metadata(self):
        detector = PresidioDetector()
        assert detector.name == "presidio_detector"
        assert detector.detector_type.value == "pii_detector"
