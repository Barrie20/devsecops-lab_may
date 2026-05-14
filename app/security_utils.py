"""
Security Utilities Module

Provides common security functions for input validation,
sanitization, and secure configuration loading.
"""

import hashlib
import hmac
import logging
import os
import re
import secrets

logger = logging.getLogger(__name__)


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_hex(length)


def validate_url(url: str) -> bool:
    """
    Validate that a string is a properly formatted URL.
    Rejects dangerous schemes and internal addresses.
    """
    pattern = re.compile(
        r"^https?://"
        r"(?!(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        r"(?!(?:169\.254|192\.168)\.\d{1,3}\.\d{1,3})"
        r"(?!localhost)"
        r"[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+"
    )
    return bool(pattern.match(url))


def sanitize_input(value: str, max_length: int = 1024) -> str:
    """
    Sanitize user input by stripping dangerous characters
    and enforcing length limits.
    """
    if not isinstance(value, str):
        return ""

    # Truncate to max length
    value = value[:max_length]

    # Remove null bytes and control characters
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)

    return value.strip()


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """
    Verify HMAC-SHA256 signature for webhook payloads.
    Uses constant-time comparison to prevent timing attacks.
    """
    expected = hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(f"sha256={expected}", signature)


def get_secret(key: str, default: str = "") -> str:
    """
    Retrieve a secret from environment variables.
    Never log the actual value.
    """
    value = os.getenv(key, default)
    if value:
        logger.debug("Secret '%s' loaded successfully", key)
    else:
        logger.warning("Secret '%s' not found in environment", key)
    return value
