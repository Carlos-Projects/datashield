from __future__ import annotations

from datashield.utils.crypto import CryptoUtils


class TestCryptoUtils:
    def test_hash_string(self):
        h = CryptoUtils.hash_string("test")
        assert len(h) == 64
        assert CryptoUtils.hash_string("test") == CryptoUtils.hash_string("test")

    def test_hash_with_salt(self):
        h1, salt1 = CryptoUtils.hash_with_salt("test")
        h2, salt2 = CryptoUtils.hash_with_salt("test", salt1)
        assert h1 == h2
        assert len(salt1) == 32

    def test_generate_key(self):
        k = CryptoUtils.generate_key()
        assert len(k) > 10

    def test_hmac_sign(self):
        sig = CryptoUtils.hmac_sign("test", "key")
        assert len(sig) == 64
        assert CryptoUtils.hmac_sign("test", "key") == CryptoUtils.hmac_sign("test", "key")

    def test_anonymize_email(self):
        assert CryptoUtils.anonymize_email("test@example.com") == "t***t@example.com"
        assert CryptoUtils.anonymize_email("ab@example.com") == "a***@example.com"
        assert CryptoUtils.anonymize_email("noemail") == "noemail"

    def test_anonymize_phone(self):
        assert CryptoUtils.anonymize_phone("+1 (555) 123-4567") == "15****67"
        assert CryptoUtils.anonymize_phone("12") == "12"

    def test_mask_value(self):
        assert CryptoUtils.mask_value("12345678") == "1234****"
        assert CryptoUtils.mask_value("abc") == "abc"

    def test_deterministic_token(self):
        data = {"a": 1, "b": 2}
        t1 = CryptoUtils.deterministic_token(data)
        t2 = CryptoUtils.deterministic_token(data)
        assert t1 == t2
