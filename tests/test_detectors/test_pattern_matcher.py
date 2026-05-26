from __future__ import annotations

import pytest

from datashield.detectors.pattern_matcher import PatternMatcher
from datashield.scanner import Confidence, DataCategory, Severity


@pytest.fixture
def detector():
    return PatternMatcher()


class TestPatternMatcher:
    async def test_detect_email(self, detector):
        records = [{"email": "user@example.com"}]
        findings = await detector.detect(records)
        emails = [
            f for f in findings if f.category == DataCategory.PII and "email" in f.title.lower()
        ]
        assert len(emails) >= 1

    async def test_detect_ssn(self, detector):
        records = [{"ssn": "123-45-6789"}]
        findings = await detector.detect(records)
        ssns = [f for f in findings if "ssn" in f.title.lower() or "social" in f.title.lower()]
        assert len(ssns) >= 1

    async def test_detect_credit_card(self, detector):
        records = [{"card": "4111-1111-1111-1111"}]
        findings = await detector.detect(records)
        cards = [f for f in findings if "credit card" in f.title.lower()]
        assert len(cards) >= 1

    async def test_detect_phone(self, detector):
        records = [{"phone": "(555) 123-4567"}]
        findings = await detector.detect(records)
        phones = [f for f in findings if "phone" in f.title.lower()]
        assert len(phones) >= 1

    async def test_detect_ip(self, detector):
        records = [{"ip": "192.168.1.1"}]
        findings = await detector.detect(records)
        ips = [f for f in findings if "ip" in f.title.lower()]
        assert len(ips) >= 1

    async def test_detect_aws_key(self, detector):
        records = [{"aws": "AKIAIOSFODNN7EXAMPLE"}]
        findings = await detector.detect(records)
        aws = [f for f in findings if "aws" in f.title.lower()]
        assert len(aws) >= 1

    async def test_detect_private_key(self, detector):
        records = [{"key": "-----BEGIN RSA PRIVATE KEY-----\nABC\n-----END RSA PRIVATE KEY-----"}]
        findings = await detector.detect(records)
        keys = [f for f in findings if "private key" in f.title.lower()]
        assert len(keys) >= 1

    async def test_detect_github_token(self, detector):
        records = [{"token": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}]
        findings = await detector.detect(records)
        tokens = [f for f in findings if "github" in f.title.lower()]
        assert len(tokens) >= 1

    async def test_detect_jwt(self, detector):
        records = [
            {
                "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNrkPkS0SRASwLL7VgDZ0RyO4tFgPt1eREJmGvE"
            }
        ]
        findings = await detector.detect(records)
        jwts = [f for f in findings if "jwt" in f.title.lower()]
        assert len(jwts) >= 1

    async def test_no_false_positive_on_clean(self, detector):
        records = [{"name": "John Doe", "notes": "This is a clean text without sensitive data"}]
        findings = await detector.detect(records)
        critical = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical) == 0

    async def test_nested_dict_scanning(self, detector):
        records = [{"user": {"email": "test@example.com", "profile": {"ssn": "123-45-6789"}}}]
        findings = await detector.detect(records)
        assert len(findings) >= 2

    async def test_list_values(self, detector):
        records = [{"emails": ["a@b.com", "c@d.com"]}]
        findings = await detector.detect(records)
        assert len(findings) >= 2

    async def test_detect_bearer_token(self, detector):
        records = [{"auth": "Bearer eyJhbGciOiJIUzI1NiJ9.test.test"}]
        findings = await detector.detect(records)
        bearers = [f for f in findings if "bearer" in f.title.lower()]
        assert len(bearers) >= 1

    async def test_custom_patterns(self):
        custom = [
            (
                "custom_key",
                r"CUSTOM\d{3}",
                Severity.HIGH,
                Confidence.HIGH,
                DataCategory.OTHER,
                "Custom pattern",
            ),
        ]
        detector = PatternMatcher(custom_patterns=custom)
        records = [{"field": "CUSTOM123"}]
        findings = await detector.detect(records)
        assert len(findings) == 1
        assert findings[0].title == "Custom pattern"
