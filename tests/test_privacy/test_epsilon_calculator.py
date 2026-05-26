from __future__ import annotations

from datashield.privacy.epsilon_calculator import EpsilonCalculator


class TestEpsilonCalculator:
    def test_init_default(self):
        calc = EpsilonCalculator()
        assert calc.default_epsilon == 1.0

    def test_estimate_empty_data(self):
        calc = EpsilonCalculator()
        eps = calc.estimate([])
        assert eps == 1.0

    def test_estimate_basic(self):
        calc = EpsilonCalculator()
        data = [{"name": "Alice", "age": 30}]
        eps = calc.estimate(data)
        assert eps > 0
        assert eps <= 100

    def test_recommend(self):
        calc = EpsilonCalculator()
        data = [{"name": "Alice", "age": 30}]
        rec = calc.recommend(data)
        assert "estimated_epsilon" in rec
        assert "conservative" in rec
        assert "standard" in rec
        assert "relaxed" in rec
        assert "strict" in rec
        assert rec["conservative"] < rec["standard"]
        assert rec["relaxed"] > rec["standard"]

    def test_unique_ratio_all_unique(self):
        calc = EpsilonCalculator()
        data = [{"a": 1}, {"b": 2}]
        ratio = calc._unique_ratio(data)
        assert ratio == 1.0

    def test_unique_ratio_duplicates(self):
        calc = EpsilonCalculator()
        data = [{"a": 1}, {"a": 1}]
        ratio = calc._unique_ratio(data)
        assert ratio < 1.0

    def test_estimate_entropy(self):
        calc = EpsilonCalculator()
        data = [{"text": "hello"}]
        entropy = calc._estimate_entropy(data)
        assert entropy > 0

    def test_estimate_sensitivity(self):
        calc = EpsilonCalculator()
        data = [{"value": 10}, {"value": 20}, {"value": 30}]
        sens = calc._estimate_sensitivity(data)
        assert sens > 0
