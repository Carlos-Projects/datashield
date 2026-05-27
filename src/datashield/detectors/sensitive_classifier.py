from __future__ import annotations

from typing import Any

from datashield.scanner import (
    BaseDetector,
    Confidence,
    DataCategory,
    DetectorType,
    Finding,
    Severity,
)

_MEDICAL_KEYWORDS: set[str] = {
    "diagnosis",
    "patient",
    "symptom",
    "treatment",
    "medication",
    "prescription",
    "disease",
    "disorder",
    "allergy",
    "immunization",
    "vaccine",
    "surgery",
    "procedure",
    "lab",
    "test_result",
    "blood",
    "biopsy",
    "mri",
    "ct_scan",
    "xray",
    "ultrasound",
    "heart_rate",
    "blood_pressure",
    "temperature",
    "weight",
    "height",
    "bmi",
    "glucose",
    "cholesterol",
    "hemoglobin",
    "mrn",
    "medical_record",
    "health_insurance",
    "provider",
    "clinic",
    "hospital",
    "doctor",
    "nurse",
    "specialist",
    "referral",
    "icd",
    "cpt",
    "code_status",
    "do_not_resuscitate",
    "dnr",
    "living_will",
    "advance_directive",
    "hipaa",
    "phi",
    "protected_health",
}

_FINANCIAL_KEYWORDS: set[str] = {
    "credit_card",
    "debit_card",
    "card_number",
    "cvv",
    "cvc",
    "expiration",
    "bank_account",
    "routing_number",
    "account_number",
    "aba",
    "swift",
    "iban",
    "bic",
    "sort_code",
    "transaction",
    "balance",
    "payment",
    "invoice",
    "receipt",
    "salary",
    "income",
    "wage",
    "compensation",
    "tax_return",
    "w2",
    "w9",
    "1099",
    "credit_score",
    "loan",
    "mortgage",
    "investment",
    "portfolio",
    "stock",
    "bond",
    "dividend",
    "capital_gains",
    "retirement",
    "401k",
    "ira",
    "roth",
    "pension",
    "beneficiary",
    "insurance_policy",
    "premium",
    "deductible",
    "coverage",
    "claim",
}

_LEGAL_KEYWORDS: set[str] = {
    "ssn",
    "social_security",
    "driver_license",
    "passport",
    "national_id",
    "visa",
    "green_card",
    "citizenship",
    "immigration",
    "naturalization",
    "court",
    "lawsuit",
    "litigation",
    "settlement",
    "contract",
    "agreement",
    "nda",
    "non_disclosure",
    "arbitration",
    "mediation",
    "deposition",
    "testimony",
    "judgment",
    "verdict",
    "sentence",
    "appeal",
    "attorney",
    "lawyer",
    "counsel",
    "legal",
    "statute",
    "regulation",
    "compliance",
    "subpoena",
    "warrant",
    "affidavit",
    "notary",
    "power_of_attorney",
    "will",
    "trust",
    "estate",
    "probate",
    "guardianship",
    "custody",
}

_PERSONAL_KEYWORDS: set[str] = {
    "name",
    "full_name",
    "first_name",
    "last_name",
    "middle_name",
    "maiden_name",
    "nickname",
    "alias",
    "username",
    "user_id",
    "email",
    "phone",
    "mobile",
    "telephone",
    "address",
    "city",
    "state",
    "zip",
    "postal",
    "country",
    "birth_date",
    "date_of_birth",
    "dob",
    "age",
    "gender",
    "marital_status",
    "spouse",
    "children",
    "education",
    "school",
    "university",
    "degree",
    "major",
    "gpa",
    "employer",
    "job_title",
    "occupation",
    "work_history",
    "biography",
    "bio",
    "description",
    "about_me",
    "profile",
    "ip_address",
    "mac_address",
    "device_id",
    "browser",
    "user_agent",
    "location",
    "coordinates",
    "latitude",
    "longitude",
    "timezone",
}


class SensitiveClassifier(BaseDetector):
    """Classifies sensitive data by keyword matching across medical, financial, legal, personal categories."""

    name = "sensitive_classifier"
    detector_type = DetectorType.CLASSIFIER

    def __init__(self) -> None:
        self.categories = {
            DataCategory.MEDICAL: _MEDICAL_KEYWORDS,
            DataCategory.FINANCIAL: _FINANCIAL_KEYWORDS,
            DataCategory.LEGAL: _LEGAL_KEYWORDS,
            DataCategory.PERSONAL: _PERSONAL_KEYWORDS,
        }
        self.category_severity = {
            DataCategory.MEDICAL: Severity.HIGH,
            DataCategory.FINANCIAL: Severity.HIGH,
            DataCategory.LEGAL: Severity.MEDIUM,
            DataCategory.PERSONAL: Severity.MEDIUM,
        }

    async def detect(self, records: list[dict[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        for record in records:
            findings.extend(self._classify_record(record))
        return findings

    def _classify_record(self, record: dict[str, Any], path: str = "") -> list[Finding]:
        findings: list[Finding] = []
        for key, value in record.items():
            field_path = f"{path}.{key}" if path else key
            if isinstance(value, dict):
                findings.extend(self._classify_record(value, field_path))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        findings.extend(self._classify_record(item, f"{field_path}[{i}]"))
                    elif isinstance(item, str):
                        classified = self._classify_value(key, item)
                        findings.extend(self._make_findings(classified, field_path, item))
            elif isinstance(value, str):
                classified = self._classify_value(key, value)
                findings.extend(self._make_findings(classified, field_path, value))
        return findings

    def _classify_value(self, key: str, value: str) -> list[tuple[DataCategory, float]]:
        results: list[tuple[DataCategory, float]] = []
        key_lower = key.lower().replace("_", " ").replace("-", " ")
        value_lower = value.lower()
        for category, keywords in self.categories.items():
            score = 0.0
            for kw in keywords:
                if kw.replace("_", " ") in key_lower:
                    score += 0.5
                if kw in value_lower:
                    score += 0.3
            if score > 0:
                results.append((category, min(1.0, score)))
        return results

    def _make_findings(
        self,
        classified: list[tuple[DataCategory, float]],
        field_path: str,
        value: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for category, confidence_score in classified:
            if confidence_score < 0.3:
                conf = Confidence.LOW
            elif confidence_score < 0.6:
                conf = Confidence.MEDIUM
            else:
                conf = Confidence.HIGH
            severity = self.category_severity.get(category, Severity.MEDIUM)
            findings.append(
                Finding(
                    detector=self.name,
                    detector_type=self.detector_type,
                    severity=severity,
                    confidence=conf,
                    title=f"Sensitive data detected: {category.value}",
                    description=f"Field '{field_path}' classified as {category.value} (score: {confidence_score:.2f})",
                    field_path=field_path,
                    value=value[:100] if len(value) > 100 else value,
                    category=category,
                    snippet=value[:200] if len(value) > 200 else value,
                    recommendation=f"Review field '{field_path}' for {category.value} data sensitivity",
                    metadata={
                        "classification_score": confidence_score,
                        "classification_method": "keyword_matching",
                    },
                )
            )
        return findings
