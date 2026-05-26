from __future__ import annotations

import pytest

from datashield.privacy.k_anonymity import KAnonymity


class TestKAnonymity:
    def test_init_defaults(self):
        ka = KAnonymity()
        assert ka.k == 5

    def test_invalid_k(self):
        with pytest.raises(ValueError, match="k must be >= 2"):
            KAnonymity(k=1)

    def test_empty_data(self):
        ka = KAnonymity()
        result = ka.apply([])
        assert result["satisfied"] is True

    def test_sufficient_anonymity(self):
        ka = KAnonymity(k=2)
        data = [
            {"age": 30, "city": "NYC"},
            {"age": 30, "city": "NYC"},
        ]
        result = ka.apply(data)
        assert result["satisfied"] is True

    def test_insufficient_anonymity(self):
        ka = KAnonymity(k=3)
        data = [
            {"age": 30, "city": "NYC"},
            {"age": 30, "city": "NYC"},
            {"age": 25, "city": "LA"},
        ]
        result = ka.apply(data)
        assert result["satisfied"] is False
        assert result["violations"] >= 1

    def test_generalization_applied(self):
        ka = KAnonymity(k=10)
        data = [
            {"age": 30, "city": "New York"},
            {"age": 31, "city": "Los Angeles"},
        ]
        result = ka.apply(data)
        assert result["violations"] > 0

    def test_custom_quasi_identifiers(self):
        ka = KAnonymity(k=2, quasi_identifiers=["zip_code"])
        data = [
            {"zip_code": "10001", "name": "Alice"},
            {"zip_code": "10001", "name": "Bob"},
        ]
        result = ka.apply(data)
        assert result["satisfied"] is True

    def test_generalize_number_ranges(self):
        ka = KAnonymity()
        assert ka._generalize_number(10) == "0-17"
        assert ka._generalize_number(25) == "18-29"
        assert ka._generalize_number(50) == "45-59"
        assert ka._generalize_number(80) == "75+"

    def test_infer_quasi_identifiers(self):
        ka = KAnonymity()
        data = [{"age": 30, "zip_code": "10001", "name": "Alice"}]
        qids = ka._infer_quasi_identifiers(data)
        assert "age" in qids
        assert "zip_code" in qids
        assert "name" not in qids
