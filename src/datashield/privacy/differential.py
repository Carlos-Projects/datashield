from __future__ import annotations

import copy
import math
from typing import Any

import numpy as np


class DifferentialPrivacy:
    """Adds calibrated Laplace or Gaussian noise to numeric and string data for differential privacy."""

    def __init__(
        self,
        epsilon: float = 1.0,
        delta: float = 1e-5,
        sensitivity: float = 1.0,
        mechanism: str = "laplace",
    ):
        if epsilon <= 0:
            raise ValueError("Epsilon must be positive")
        if delta <= 0 or delta >= 1:
            raise ValueError("Delta must be in (0, 1)")
        if mechanism not in ("laplace", "gaussian"):
            raise ValueError("Mechanism must be 'laplace' or 'gaussian'")
        self.epsilon = epsilon
        self.delta = delta
        self.sensitivity = sensitivity
        self.mechanism = mechanism
        self._rng = np.random.default_rng()

    def apply(self, data: list[dict[str, Any]]) -> dict[str, Any]:
        if not data:
            return {"data": copy.deepcopy(data), "records_modified": 0, "noise_added": False}

        result = copy.deepcopy(data)
        modified = 0
        noise_fn = self._gaussian_noise if self.mechanism == "gaussian" else self._laplace_noise
        for record in result:
            for key, value in record.items():
                if isinstance(value, (int, float)):
                    noise = noise_fn()
                    record[key] = value + noise
                    modified += 1
                elif isinstance(value, str) and len(value) > 0:
                    noisy_str = self._noisify_string(value)
                    if noisy_str != value:
                        record[key] = noisy_str
                        modified += 1

        return {
            "data": result,
            "records_modified": modified,
            "noise_added": True,
            "epsilon": self.epsilon,
            "delta": self.delta,
            "mechanism": self.mechanism,
        }

    def _laplace_noise(self) -> float:
        scale = self.sensitivity / self.epsilon
        return float(self._rng.laplace(0, scale))

    def _gaussian_noise(self) -> float:
        sigma = math.sqrt(2 * math.log(1.25 / self.delta)) * self.sensitivity / self.epsilon
        return float(self._rng.normal(0, sigma))

    def _noisify_string(self, value: str) -> str:
        chars = list(value)
        noise_prob = 1.0 / (len(value) + 1)
        modified = False
        for i in range(len(chars)):
            if self._rng.random() < noise_prob:
                c = chars[i]
                if c.isalpha():
                    shift = self._rng.choice([-1, 1])
                    chars[i] = chr(
                        (ord(c) - ord("a" if c.islower() else "A") + shift) % 26
                        + ord("a" if c.islower() else "A")
                    )
                    modified = True
                elif c.isdigit():
                    chars[i] = str((int(c) + self._rng.integers(1, 10)) % 10)
                    modified = True
        return "".join(chars) if modified else value

    def compute_privacy_loss(self, queries: int) -> float:
        return self.epsilon * queries
