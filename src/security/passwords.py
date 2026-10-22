"""Password hashing using PBKDF2-HMAC-SHA256 from the standard library."""
from __future__ import annotations

import hashlib
import hmac
import secrets

_ITERATIONS = 260_000
_ALGORITHM = "pbkdf2_sha256"


def hash_password(password: str) -> str:
    if not password:
        raise ValueError("Password must not be empty")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return f"{_ALGORITHM}${_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = encoded.split("$", 3)
        if algorithm != _ALGORITHM:
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def generate_password(length: int = 20) -> str:
    """Generate a URL-safe random password (never a hard-coded default)."""
    return secrets.token_urlsafe(length)[: max(length, 16)]
