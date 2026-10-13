"""AgentPay — CSRF protection (double-submit cookie pattern).

How it works:
- On login, we set a `csrf_token` cookie (NOT HttpOnly — JS must read it).
- Client sends the same token in `X-CSRF-Token` header on POST/PUT/DELETE.
- Server compares cookie vs header (timing-safe).
- Requests without a valid pair are rejected with 403.

Why not SameSite=Strict?
- Lax is enough for most attacks and preserves usability.
- Double-submit covers the gap and works cross-browser.
"""
import hmac
import secrets
from functools import wraps

from flask import request, jsonify


CSRF_COOKIE_NAME = "ap_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_TOKEN_BYTES = 32

# Methods that must be protected
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def generate_csrf_token() -> str:
    """Generate a new CSRF token."""
    return secrets.token_urlsafe(CSRF_TOKEN_BYTES)


def _safe_eq(a, b) -> bool:
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    try:
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
    except Exception:
        return False


def set_csrf_cookie(response, token: str):
    """Set the CSRF cookie on a response.

    NOT HttpOnly — front-end JS must read it to include in headers.
    SameSite=Lax to reduce cross-site leakage.
    """
    import os
    secure = os.environ.get("FLASK_DEBUG", "0") != "1"
    if isinstance(response, tuple):
        resp_obj, status = response[0], response[1]
    else:
        resp_obj, status = response, None

    resp_obj.set_cookie(
        CSRF_COOKIE_NAME,
        token,
        max_age=7 * 24 * 3600,
        httponly=False,   # must be readable by JS
        secure=secure,
        samesite="Lax",
        path="/",
    )
    return (resp_obj, status) if status is not None else resp_obj


def clear_csrf_cookie(response):
    """Remove the CSRF cookie."""
    import os
    if isinstance(response, tuple):
        resp_obj, status = response[0], response[1]
    else:
        resp_obj, status = response, None
    resp_obj.set_cookie(
        CSRF_COOKIE_NAME,
        "",
        expires=0,
        httponly=False,
        secure=os.environ.get("FLASK_DEBUG", "0") != "1",
        samesite="Lax",
        path="/",
    )
    return (resp_obj, status) if status is not None else resp_obj


def check_csrf() -> bool:
    """Return True if the request has a valid CSRF token pair.

    Only enforced on unsafe methods. GET/HEAD/OPTIONS are always allowed.
    """
    if request.method not in UNSAFE_METHODS:
        return True

    cookie_token = request.cookies.get(CSRF_COOKIE_NAME, "")
    header_token = request.headers.get(CSRF_HEADER_NAME, "")

    if not cookie_token or not header_token:
        return False

    return _safe_eq(cookie_token, header_token)


def require_csrf(view_func):
    """Decorator: enforce CSRF for unsafe methods.

    In TESTING mode, CSRF is bypassed so tests can focus on business logic.
    CSRF-specific tests must use TESTING=False or hit production.
    """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        from flask import current_app
        if current_app.config.get("TESTING"):
            return view_func(*args, **kwargs)
        if not check_csrf():
            return jsonify({
                "ok": False,
                "error": "CSRF validation failed",
                "hint": f"Send {CSRF_HEADER_NAME} header matching {CSRF_COOKIE_NAME} cookie",
            }), 403
        return view_func(*args, **kwargs)
    return wrapper
