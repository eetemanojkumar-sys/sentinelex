"""Small, dependency-free security primitives for SentinelX local administrator and agent credentials.

These helpers do not replace route-level authorization, CSRF protection, TLS,
rate limiting, or tenant-scoped database queries.
"""
import hashlib
import hmac
import secrets

_PBKDF2_ITERATIONS = 600_000
_SALT_BYTES = 16
_TOKEN_BYTES = 32


def hash_password(password: str) -> str:
    """Return a versioned PBKDF2-SHA256 hash with a random per-password salt."""
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("Password must contain at least 12 characters")
    if len(password) > 1024:
        raise ValueError("Password is too long")
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return "pbkdf2_sha256$%s$%s$%s" % (_PBKDF2_ITERATIONS, salt.hex(), digest.hex())


def verify_password(password: str, encoded: str) -> bool:
    """Verify a stored password hash without leaking comparison timing."""
    try:
        algorithm, iterations_text, salt_hex, digest_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
        if iterations < 100_000 or iterations > 2_000_000:
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        if len(salt) != _SALT_BYTES or len(expected) != 32:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except (AttributeError, TypeError, ValueError):
        return False


def generate_secret() -> str:
    """Generate a URL-safe high-entropy one-time or session secret."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def hash_secret(secret: str) -> str:
    """Return a stable SHA-256 digest suitable for token lookup at rest."""
    if not isinstance(secret, str) or not secret:
        raise ValueError("Secret must be a non-empty string")
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()
