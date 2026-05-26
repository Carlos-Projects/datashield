from __future__ import annotations

import pytest

from datashield.privacy.differential import DifferentialPrivacy


class TestDifferentialPrivacy:
    def test_init_defaults(self):
        dp = DifferentialPrivacy()
        assert dp.epsilon == 1.0
        assert dp.delta == 1e-5
        assert dp.sensitivity == 1.0

    def test_invalid_epsilon(self):
        with pytest.raises(ValueError, match="Epsilon must be positive"):
            DifferentialPrivacy(epsilon=0)

    def test_invalid_delta(self):
        with pytest.raises(ValueError, match="Delta must be in"):
            DifferentialPrivacy(delta=0)

    def test_apply_empty_data(self):
        dp = DifferentialPrivacy()
        result = dp.apply([])
        assert result["data"] == []
        assert result["records_modified"] == 0

    def test_apply_adds_noise_to_numbers(self):
        dp = DifferentialPrivacy(epsilon=100.0)
        data = [{"age": 30, "score": 100}]
        result = dp.apply(data)
        assert result["records_modified"] >= 1
        assert result["noise_added"] is True
        assert result["data"][0]["age"] != 30

    def test_lapace_noise_shape(self):
        dp = DifferentialPrivacy(epsilon=1.0)
        noises = [dp._laplace_noise() for _ in range(1000)]
        mean = sum(noises) / len(noises)
        assert abs(mean) < 0.5

    def test_compute_privacy_loss(self):
        dp = DifferentialPrivacy(epsilon=0.5)
        assert dp.compute_privacy_loss(10) == 5.0
        assert dp.compute_privacy_loss(0) == 0.0

    def test_noisify_string(self):
        dp = DifferentialPrivacy(epsilon=1.0)
        result = dp._noisify_string("hello")
        assert len(result) == len("hello")
