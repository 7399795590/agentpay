"""AgentPay — TOTP (2FA) helpers.

Uses pyotp for TOTP generation/verification and segno for QR code rendering.

Design principles:
- Secrets are generated server-side with strong entropy
- QR codes are rendered as SVG data URLs (no filesystem writes)
- Verification uses constant-time comparison
- Recovery codes are hashed (bcrypt-compatible via werkzeug)
"""
import io
import json
import secrets
import base64
import hmac
import hashlib
from typing import Optional, List, Tuple

import pyotp
import segno

from werkzeug.security import generate_password_hash, check_password_hash


# ─── Constants ─────────────────────────────────────────────
ISSUER = "AgentPay"
SECRET_LENGTH = 32              # pyotp generates 32-char base32 secrets
RECOVERY_CODE_COUNT = 10        # how many recovery codes to generate
RECOVERY_CODE_BYTES = 5         # 5 bytes → 10 hex chars per code (e.g. "a1b2c3d4e5")


# ─── Secret generation ─────────────────────────────────────
def generate_secret() -> str:
    """Generate a new random TOTP secret (base32)."""
    return pyotp.random_base32(length=SECRET_LENGTH)


def get_provisioning_uri(secret: str, account_name: str) -> str:
    """Build an otpauth:// URI for authenticator apps.

    Example:
        otpauth://totp/AgentPay:user@example.com?secret=XXX&issuer=AgentPay
    """
    return pyotp.TOTP(secret).provisioning_uri(
        name=account_name,
        issuer_name=ISSUER,
    )


# ─── QR code as data URL (SVG, no filesystem) ──────────────
def provisioning_uri_to_qr_svg_data_url(uri: str) -> str:
    """Render a QR code (SVG) as a data URL: data:image/svg+xml;base64,...

    This keeps everything in-memory (no disk writes) and returns
    a string the frontend can embed directly in <img src="...">.
    """
    qr = segno.make(uri, error='m')            # error correction level M
    buf = io.BytesIO()
    qr.save(buf, kind='svg', scale=5, dark='#0a0a0a', light=None)  # transparent bg
    raw = buf.getvalue()
    b64 = base64.b64encode(raw).decode('ascii')
    return f"data:image/svg+xml;base64,{b64}"


# ─── Verification ──────────────────────────────────────────
def verify_code(secret: str, code: str, valid_window: int = 1) -> bool:
    """Verify a 6-digit TOTP code.

    valid_window=1 allows ±30s clock drift (recommended).
    Returns True/False.
    """
    if not secret or not code:
        return False
    code = str(code).strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False
    try:
        totp = pyotp.TOTP(secret)
        # pyotp uses constant-time comparison internally
        return bool(totp.verify(code, valid_window=valid_window))
    except Exception:
        return False


def get_current_code(secret: str) -> str:
    """Get the current TOTP code (for testing/debugging only)."""
    return pyotp.TOTP(secret).now()


# ─── Recovery codes ────────────────────────────────────────
def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> List[str]:
    """Generate a list of single-use recovery codes (plaintext).

    Format: 10 hex chars, e.g. "a1b2c3d4e5"
    These are returned ONCE to the user — never stored in plaintext.
    """
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(RECOVERY_CODE_BYTES)   # 10 chars
        codes.append(raw)
    return codes


def hash_recovery_codes(codes: List[str]) -> str:
    """Hash recovery codes for storage (JSON array of hashes)."""
    hashes = [generate_password_hash(c) for c in codes]
    return json.dumps(hashes)


def verify_recovery_code(codes_hash_json: Optional[str], code: str) -> Tuple[bool, Optional[str]]:
    """Verify a recovery code against stored hashes.

    Returns (is_valid, remaining_hashes_json).
    - If valid, removes the used code from the list (single-use).
    - If invalid, returns (False, original_json).
    """
    if not codes_hash_json or not code:
        return False, codes_hash_json

    try:
        hashes = json.loads(codes_hash_json)
    except Exception:
        return False, codes_hash_json

    code = code.strip().lower().replace(" ", "").replace("-", "")

    for i, h in enumerate(hashes):
        try:
            if check_password_hash(h, code):
                # Remove the used code (single-use)
                hashes.pop(i)
                return True, json.dumps(hashes)
        except Exception:
            continue

    return False, codes_hash_json


def count_remaining_recovery_codes(codes_hash_json: Optional[str]) -> int:
    """Count how many unused recovery codes remain."""
    if not codes_hash_json:
        return 0
    try:
        return len(json.loads(codes_hash_json))
    except Exception:
        return 0
