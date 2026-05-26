from __future__ import annotations

import math
from typing import Any

import numpy as np


class DifferentialPrivacy:
    def __init__(self, epsilon: float = 1.0, delta: float = 1e-5, sensitivity: float = 1.0):
        if epsilon <= 0:
            raise ValueError("Epsilon must be positive")
        if delta <= 0 or delta >= 1:
            raise ValueError("Delta must be in (0, 1)")
        self.epsilon = epsilon
        self.delta = delta
        self.sensitivity = sensitivity

    def apply(self, data: list[dict[str, Any]]) -> dict[str, Any]:
        if not data:
            return {"data": data, "records_modified": 0, "noise_added": False}

        modified = 0
        for record in data:
            for key, value in record.items():
                if isinstance(value, (int, float)):
                    noise = self._laplace_noise()
                    record[key] = value + noise
                    modified += 1
                elif isinstance(value, str) and len(value) > 0:
                    noisy_str = self._noisify_string(value)
                    if noisy_str != value:
                        record[key] = noisy_str
                        modified += 1

        return {
            "data": data,
            "records_modified": modified,
            "noise_added": True,
            "epsilon": self.epsilon,
            "delta": self.delta,
        }

    def _laplace_noise(self) -> float:
        scale = self.sensitivity / self.epsilon
        return np.random.laplace(0, scale)

    def _gaussian_noise(self) -> float:
        sigma = math.sqrt(2 * math.log(1.25 / self.delta)) * self.sensitivity / self.epsilon
        return float(np.random.normal(0, sigma))

    def _noisify_string(self, value: str) -> str:
        chars = list(value)
        noise_prob = 1.0 / (len(value) + 1)
        modified = False
        for i in range(len(chars)):
            if np.random.random() < noise_prob:
                c = chars[i]
                if c.isalpha():
                    shift = np.random.choice([-1, 1])
                    chars[i] = chr(
                        (ord(c) - ord("a" if c.islower() else "A") + shift) % 26
                        + ord("a" if c.islower() else "A")
                    )
                    modified = True
                elif c.isdigit():
                    chars[i] = str((int(c) + np.random.randint(1, 10)) % 10)
                    modified = True
        return "".join(chars) if modified else value

    def compute_privacy_loss(self, queries: int) -> float:
        return self.epsilon * queries
