from __future__ import annotations

import math
from typing import Any

import numpy as np


class EpsilonCalculator:
    """Estimates a recommended privacy budget (epsilon) based on dataset characteristics."""

    def __init__(self, default_epsilon: float = 1.0):
        self.default_epsilon = default_epsilon

    def estimate(self, data: list[dict[str, Any]]) -> float:
        if not data:
            return self.default_epsilon
        n_records = len(data)
        n_fields = max(len(r) for r in data) if data else 1
        unique_ratio = self._unique_ratio(data)
        entropy = self._estimate_entropy(data)
        sensitivity = self._estimate_sensitivity(data)
        base = max(1.0, math.log(n_records + 1))
        field_penalty = math.sqrt(n_fields) / 2
        uniqueness = 1.0 + unique_ratio * 2
        entropy_factor = max(0.5, entropy / 10)
        eps = base * field_penalty * uniqueness * entropy_factor / (sensitivity + 0.1)
        return round(min(max(eps, 0.01), 100.0), 4)

    def recommend(self, data: list[dict[str, Any]]) -> dict[str, float]:
        estimated = self.estimate(data)
        return {
            "estimated_epsilon": estimated,
            "conservative": round(estimated * 0.5, 4),
            "standard": round(estimated, 4),
            "relaxed": round(estimated * 2.0, 4),
            "strict": round(estimated * 0.1, 4),
        }

    def _unique_ratio(self, data: list[dict[str, Any]]) -> float:
        if not data:
            return 0.0
        seen: set[str] = set()
        for record in data:
            for key, value in record.items():
                seen.add(f"{key}:{value}")
        total = sum(len(r) for r in data)
        return len(seen) / max(total, 1)

    def _estimate_entropy(self, data: list[dict[str, Any]]) -> float:
        entropies: list[float] = []
        for record in data:
            for value in record.values():
                if isinstance(value, str) and value:
                    freq: dict[str, int] = {}
                    for c in value:
                        freq[c] = freq.get(c, 0) + 1
                    h = 0.0
                    for count in freq.values():
                        p = count / len(value)
                        h -= p * math.log2(p)
                    entropies.append(h)
        return float(np.mean(entropies)) if entropies else 0.0

    def _estimate_sensitivity(self, data: list[dict[str, Any]]) -> float:
        numeric_values: list[float] = []
        for record in data:
            for value in record.values():
                if isinstance(value, (int, float)):
                    numeric_values.append(float(value))
        if len(numeric_values) < 2:
            return 1.0
        return float(np.std(numeric_values)) if len(numeric_values) > 1 else 1.0
