from __future__ import annotations

import pytest

from datashield.detectors.secret_scanner import SecretScanner
from datashield.scanner import DataCategory


@pytest.fixture
def scanner():
    return SecretScanner()


class TestSecretScanner:
    async def test_detect_aws_key(self, scanner):
        findings = await scanner.detect([{"key": "AKIAIOSFODNN7EXAMPLE"}])
        assert len(findings) >= 1
        assert any(f.category == DataCategory.CREDENTIAL for f in findings)

    async def test_detect_github_token(self, scanner):
        findings = await scanner.detect([{"token": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}])
        assert len(findings) >= 1

    async def test_detect_private_key(self, scanner):
        findings = await scanner.detect(
            [{"key": "-----BEGIN RSA PRIVATE KEY-----\nABC\n-----END RSA PRIVATE KEY-----"}]
        )
        assert len(findings) >= 1

    async def test_detect_slack_token(self, scanner):
        findings = await scanner.detect([{"slack": "xoxb-1234567890-1234567890123-abcdefghijk"}])
        assert len(findings) >= 1

    async def test_detect_stripe_key(self, scanner):
        findings = await scanner.detect(
            [{"stripe": "sk_test_abcdefghijklmnopqrstuvwxyz1234567890"}]
        )
        assert len(findings) >= 1

    async def test_detect_google_api_key(self, scanner):
        findings = await scanner.detect([{"google": "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567"}])
        assert len(findings) >= 1

    async def test_detect_connection_string(self, scanner):
        findings = await scanner.detect([{"db": "postgres://user:pass@localhost:5432/db"}])
        assert len(findings) >= 1

    async def test_detect_basic_auth(self, scanner):
        findings = await scanner.detect([{"auth": "Basic YWxhZGRpbjpvcGVuc2VzYW1l"}])
        assert len(findings) >= 1

    async def test_no_false_positives(self, scanner):
        findings = await scanner.detect([{"text": "Hello world this is a test"}])
        assert len(findings) == 0

    async def test_multiple_secrets(self, scanner):
        findings = await scanner.detect(
            [
                {
                    "aws": "AKIAIOSFODNN7EXAMPLE",
                    "github": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
                }
            ]
        )
        assert len(findings) >= 2
