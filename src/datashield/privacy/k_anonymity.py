from __future__ import annotations

from typing import Any


class KAnonymity:
    def __init__(
        self,
        k: int = 5,
        quasi_identifiers: list[str] | None = None,
        generalization_buckets: list[tuple[float, float, str]] | None = None,
    ):
        if k < 2:
            raise ValueError("k must be >= 2")
        self.k = k
        self.quasi_identifiers = quasi_identifiers or []
        self.generalization_buckets = generalization_buckets or [
            (0, 17, "0-17"),
            (18, 29, "18-29"),
            (30, 44, "30-44"),
            (45, 59, "45-59"),
            (60, 74, "60-74"),
            (75, float("inf"), "75+"),
        ]

    def apply(self, data: list[dict[str, Any]]) -> dict[str, Any]:
        if not data:
            return {"data": data, "satisfied": True, "violations": 0, "k": self.k}

        qids = self.quasi_identifiers or self._infer_quasi_identifiers(data)
        violations = 0
        groups: dict[str, list[int]] = {}

        for i, record in enumerate(data):
            key = self._quasi_key(record, qids)
            if key not in groups:
                groups[key] = []
            groups[key].append(i)

        for _group_key, members in groups.items():
            if len(members) < self.k:
                violations += 1
                for idx in members:
                    for qid in qids:
                        if qid in data[idx]:
                            data[idx][qid] = self._generalize(data[idx][qid])

        return {
            "data": data,
            "satisfied": violations == 0,
            "violations": violations,
            "k": self.k,
            "groups": len(groups),
        }

    def _infer_quasi_identifiers(self, data: list[dict[str, Any]]) -> list[str]:
        suggestions = [
            "age",
            "gender",
            "zip",
            "zip_code",
            "postal_code",
            "city",
            "state",
            "dob",
            "birth_date",
            "year_of_birth",
            "occupation",
            "education_level",
            "marital_status",
            "ethnicity",
        ]
        found: list[str] = []
        if data:
            for key in data[0]:
                if key.lower() in suggestions or any(
                    s in key.lower()
                    for s in ["age", "zip", "postal", "city", "state", "birth", "gender"]
                ):
                    found.append(key)
        return found

    def _quasi_key(self, record: dict[str, Any], qids: list[str]) -> str:
        parts: list[str] = []
        for qid in qids:
            val = record.get(qid, "")
            parts.append(str(val))
        return "|".join(parts)

    def _generalize(self, value: Any) -> Any:
        if isinstance(value, (int, float)):
            return self._generalize_number(value)
        if isinstance(value, str):
            if value.isdigit():
                return self._generalize_number(int(value))
            if len(value) > 3:
                return value[:2] + "***"
            return "***"
        return value

    def _generalize_number(self, value: float) -> str:
        for lo, hi, label in self.generalization_buckets:
            if lo <= value <= hi:
                return label
        return f"{value:.0f}+"
