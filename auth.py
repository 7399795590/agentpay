"""AgentPay — Authentication & Authorization.

Server-side sessions with secure cookies.
Password hashing via werkzeug (scrypt).
"""
import os
import secrets
import time
from functools import wraps

from flask import request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash

from database import db
from models import User, Session, USER_ROLES


# ===== Config =====

SESSION_TTL_SECONDS = 7 * 24 * 3600  # 7 days
SESSION_COOKIE_NAME = "ap_session"
MAX_FAILED_LOGINS = 10
LOCK_DURATION_SECONDS = 15 * 60  # 15 minutes


# ===== Password =====

def hash_password(password: str) -> str:
    """Hash a password using scrypt."""
    return generate_password_hash(password, method="scrypt")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash (timing-safe)."""
    try:
        return check_password_hash(password_hash, password)
    except Exception:
        return False


# ===== Session =====

def create_session(user: User, ip: str = None, user_agent: str = None) -> Session:
    """Create a new server-side session for a user."""
    now = int(time.time())
    session = Session(
        id=secrets.token_urlsafe(32),
        user_id=user.id,
        created_at=now,
        expires_at=now + SESSION_TTL_SECONDS,
        ip=(ip or "")[:45] or None,
        user_agent=(user_agent or "")[:255] or None,
    )
    db.session.add(session)
    return session


def get_session_from_request():
    """Return the current Session if valid, else None."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    session = db.session.get(Session, token)
    if not session or not session.is_valid():
        return None
    return session


def revoke_session(session: Session):
    """Revoke a session (idempotent)."""
    if session and session.revoked_at is None:
        session.revoked_at = int(time.time())


def revoke_all_user_sessions(user_id: str, except_session_id: str = None):
    """Revoke every active session of a user."""
    now = int(time.time())
    q = Session.query.filter(
        Session.user_id == user_id,
        Session.revoked_at.is_(None),
    )
    if except_session_id:
        q = q.filter(Session.id != except_session_id)
    for s in q.all():
        s.revoked_at = now


def set_session_cookie(response, session: Session):
    """Attach the session cookie to a Flask response.

    Accepts either a Response or a (Response, status_code) tuple.
    """
    secure = os.environ.get("FLASK_DEBUG", "0") != "1"
    if isinstance(response, tuple):
        resp_obj, status = response[0], response[1]
    else:
        resp_obj, status = response, None
    resp_obj.set_cookie(
        SESSION_COOKIE_NAME,
        session.id,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=secure,
        samesite="Lax",
        path="/",
    )
    return (resp_obj, status) if status is not None else resp_obj


def clear_session_cookie(response):
    """Remove the session cookie.

    Accepts either a Response or a (Response, status_code) tuple.
    """
    if isinstance(response, tuple):
        resp_obj, status = response[0], response[1]
    else:
        resp_obj, status = response, None
    resp_obj.set_cookie(
        SESSION_COOKIE_NAME,
        "",
        expires=0,
        httponly=True,
        secure=os.environ.get("FLASK_DEBUG", "0") != "1",
        samesite="Lax",
        path="/",
    )
    return (resp_obj, status) if status is not None else resp_obj


# ===== Errors =====

def error(msg, code=400):
    return jsonify({"ok": False, "error": msg}), code


def success(data=None, code=200):
    return jsonify({"ok": True, **(data or {})}), code


# ===== Decorators =====

def require_user(view_func):
    """Decorator: require an authenticated user (via session cookie)."""
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        session = get_session_from_request()
        if not session:
            return error("Authentication required", 401)
        user = db.session.get(User, session.user_id)
        if not user or not user.is_active:
            revoke_session(session)
            db.session.commit()
            return error("Account disabled or invalid", 401)
        # Attach to request context
        request.current_user = user
        request.current_session = session
        return view_func(*args, **kwargs)
    return wrapper


def require_role(*allowed_roles):
    """Decorator: require authenticated user with one of the given roles.

    Usage: @require_role("admin") or @require_role("admin", "developer")
    """
    def decorator(view_func):
        @wraps(view_func)
        @require_user
        def wrapper(*args, **kwargs):
            user = request.current_user
            if user.role not in allowed_roles:
                return error(f"Role '{user.role}' cannot perform this action", 403)
            return view_func(*args, **kwargs)
        return wrapper
    return decorator



# ===== Agent ownership =====

def get_agent_for_request(agent_id: str):
    """Get an agent if the current request is authorized to see it.

    Authorization rules:
    - If request has a valid session: user must be owner OR admin.
    - Else if request has Authorization: Bearer ap_... : API key must match.
    - Else: not authorized.

    Returns the agent or None. Never leaks existence: caller should return 404.
    """
    # Late import to avoid circular dependency
    from models import Agent

    agent = db.session.get(Agent, agent_id)
    if not agent:
        return None

    # 1) Session-based (user must be owner or admin)
    session = get_session_from_request()
    if session:
        user = db.session.get(User, session.user_id)
        if user and user.is_active:
            if user.role == "admin":
                return agent
            if agent.owner_id == user.id:
                return agent
            return None
        return None

    # 2) API key based (agent itself)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        if token.startswith("ap_") and _safe_eq(agent.api_key, token):
            return agent

    return None


def _safe_eq(a, b) -> bool:
    """Local timing-safe compare (avoids importing security.py globally)."""
    import hmac
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    try:
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
    except Exception:
        return False


def require_agent_owner(view_func):
    """Decorator: require that the current request may access the agent in
    the URL parameter `agent_id`. Attaches the agent to request.current_agent.

    Returns 404 (not 403) if not authorized, to avoid leaking existence.
    """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        agent_id = kwargs.get("agent_id")
        if not agent_id:
            return error("Missing agent_id", 400)
        agent = get_agent_for_request(agent_id)
        if not agent:
            return error("Agent not found", 404)
        request.current_agent = agent
        return view_func(*args, **kwargs)
    return wrapper


def attach_owner_if_logged_in(agent):
    """If the current request has a valid session, set agent.owner_id."""
    session = get_session_from_request()
    if not session:
        return None
    user = db.session.get(User, session.user_id)
    if not user or not user.is_active:
        return None
    agent.owner_id = user.id
    return user

# ===== Validation =====

def is_valid_email(email: str) -> bool:
    """Basic email validation (no external deps)."""
    if not email or len(email) > 255:
        return False
    if "@" not in email or "." not in email.split("@")[1]:
        return False
    local, domain = email.rsplit("@", 1)
    if not local or not domain:
        return False
    return True


def validate_password(password: str):
    """Return (ok, error_message)."""
    if not isinstance(password, str):
        return False, "Password must be a string"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if len(password) > 200:
        return False, "Password too long (max 200)"
    return True, None


def is_user_locked(user: User) -> bool:
    """Check if account is temporarily locked due to failed logins."""
    if user.locked_until is None:
        return False
    if user.locked_until <= int(time.time()):
        # Lock expired — reset
        user.locked_until = None
        user.failed_logins = 0
        db.session.commit()
        return False
    return True


def record_failed_login(user: User):
    """Increment failed login counter and lock if threshold exceeded."""
    user.failed_logins = (user.failed_logins or 0) + 1
    if user.failed_logins >= MAX_FAILED_LOGINS:
        user.locked_until = int(time.time()) + LOCK_DURATION_SECONDS
    db.session.commit()


def reset_failed_logins(user: User):
    """Reset failed login counter after successful auth."""
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = int(time.time())
    db.session.commit()
