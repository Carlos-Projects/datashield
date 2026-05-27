from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from typing import Any


class CryptoUtils:
    """Static utility methods for hashing, anonymization, and cryptographic operations."""

    @staticmethod
    def hash_string(value: str, algorithm: str = "sha256") -> str:
        h = hashlib.new(algorithm)
        h.update(value.encode("utf-8"))
        return h.hexdigest()

    @staticmethod
    def hash_with_salt(value: str, salt: str | None = None) -> tuple[str, str]:
        if salt is None:
            salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt.encode("utf-8"), 100000)
        return hashed.hex(), salt

    @staticmethod
    def generate_key(length: int = 32) -> str:
        return base64.b64encode(os.urandom(length)).decode("utf-8")

    @staticmethod
    def hmac_sign(value: str, key: str) -> str:
        return hmac.new(key.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def anonymize_email(email: str) -> str:
        if "@" not in email:
            return email
        local, domain = email.split("@", 1)
        if len(local) <= 2:
            hidden = local[0] + "***"
        else:
            hidden = local[0] + "***" + local[-1]
        return f"{hidden}@{domain}"

    @staticmethod
    def anonymize_phone(phone: str) -> str:
        digits = "".join(c for c in phone if c.isdigit())
        if len(digits) < 4:
            return phone
        return digits[:2] + "****" + digits[-2:]

    @staticmethod
    def mask_value(value: str, visible_chars: int = 4, mask_char: str = "*") -> str:
        if len(value) <= visible_chars:
            return value
        visible = value[:visible_chars]
        masked = mask_char * (len(value) - visible_chars)
        return visible + masked

    @staticmethod
    def sha256_file_hash(filepath: str) -> str:
        sha = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha.update(chunk)
        return sha.hexdigest()

    @staticmethod
    def deterministic_token(data: dict[str, Any], key: str | None = None) -> str:
        serialized = str(sorted(data.items()))
        if key:
            return CryptoUtils.hmac_sign(serialized, key)
        return CryptoUtils.hash_string(serialized)
