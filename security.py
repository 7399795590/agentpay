"""AgentPay — Security utilities.

Centralized security helpers:
- Timing-safe comparisons
- Security headers
- CORS allowlist
"""
import hmac
import os


# ===== Timing-safe comparison =====

def safe_compare(a, b) -> bool:
    """Constant-time string comparison to prevent timing attacks.

    Returns False for any type/None mismatch without leaking info.
    """
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    try:
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
    except Exception:
        return False


# ===== CORS allowlist =====

def get_allowed_origins() -> list:
    """Return list of allowed CORS origins.

    Reads ALLOWED_ORIGINS env (comma-separated) or defaults to known safe origins.
    """
    env = os.environ.get("ALLOWED_ORIGINS", "").strip()
    if env:
        return [o.strip() for o in env.split(",") if o.strip()]
    return [
        "https://agentpay-pearl.vercel.app",
        "http://localhost:5000",
        "http://localhost:3000",
        "http://127.0.0.1:5000",
    ]


# ===== Security headers =====

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}


def apply_security_headers(response):
    """Apply security headers to a Flask response."""
    for key, value in SECURITY_HEADERS.items():
        if key not in response.headers:
            response.headers[key] = value
    return response
