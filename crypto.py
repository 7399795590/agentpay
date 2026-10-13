"""AgentPay — Encryption helpers for sensitive data at rest.

Used to encrypt:
- webhook_url (may contain secret tokens in query params)

Algorithm: Fernet (AES-128-CBC + HMAC-SHA256 authenticated encryption)
Key source: WEBHOOK_ENCRYPTION_KEY env var (44-char Base64)
"""
import os
import logging

from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger(__name__)

_fernet_cache = None


def _get_fernet():
    """Lazy-init Fernet from env. Returns None if key missing/invalid."""
    global _fernet_cache
    if _fernet_cache is not None:
        return _fernet_cache

    key = (os.environ.get("WEBHOOK_ENCRYPTION_KEY") or "").strip()
    if not key:
        log.warning("WEBHOOK_ENCRYPTION_KEY not set — encryption disabled")
        return None
    if len(key) != 44:
        log.error(f"WEBHOOK_ENCRYPTION_KEY invalid length ({len(key)})")
        return None
    try:
        _fernet_cache = Fernet(key.encode())
        return _fernet_cache
    except Exception as e:
        log.error(f"Failed to init Fernet: {e}")
        return None


def is_enabled() -> bool:
    """Is encryption available?"""
    return _get_fernet() is not None


def encrypt(plaintext: str) -> str:
    """Encrypt a string. Returns base64 token, or "" if plaintext is empty.

    If encryption is not configured, returns plaintext prefixed with "plain:"
    so callers can detect un-encrypted values.
    """
    if not plaintext:
        return ""
    f = _get_fernet()
    if f is None:
        return "plain:" + plaintext
    token = f.encrypt(plaintext.encode("utf-8"))
    return token.decode("ascii")


def decrypt(ciphertext: str) -> str:
    """Decrypt a string. Handles:
    - "" → ""
    - "plain:..." → strips prefix (un-encrypted legacy)
    - valid Fernet token → plaintext
    Returns "" on failure.
    """
    if not ciphertext:
        return ""
    if ciphertext.startswith("plain:"):
        return ciphertext[6:]
    f = _get_fernet()
    if f is None:
        log.error("Cannot decrypt: WEBHOOK_ENCRYPTION_KEY not set")
        return ""
    try:
        return f.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken:
        log.error("Failed to decrypt: invalid token or wrong key")
        return ""
    except Exception as e:
        log.error(f"Failed to decrypt: {e}")
        return ""


def encrypt_webhook_url(url):
    """Encrypt a webhook URL. Returns None if url is None."""
    if url is None:
        return None
    return encrypt(url)


def decrypt_webhook_url(encrypted_url):
    """Decrypt a webhook URL. Returns None if input is None."""
    if encrypted_url is None:
        return None
    return decrypt(encrypted_url)
