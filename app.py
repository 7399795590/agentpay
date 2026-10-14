"""AgentPay — Main Flask app."""
import time
from flask import Flask, request, jsonify
from flask_cors import CORS

from database import db, init_db
from models import Agent, Transaction, Subscription, AuditLog, User, Session, write_audit
from webhooks import fire_webhook
from ratelimit import limit, limiter
from logging_utils import setup_logging, generate_request_id
import stripe_integration
from security import safe_compare, get_allowed_origins, apply_security_headers
import auth
import csrf
import audit
import topup_helpers
import crypto
import totp
from sqlalchemy import update as sql_update
import mailer
import ledger

app = Flask(__name__)

# Restricted CORS: only known origins
CORS(app, resources={r"/*": {"origins": get_allowed_origins()}},
     supports_credentials=False,
     allow_headers=["Content-Type", "Authorization", "Idempotency-Key", "Stripe-Signature"],
     methods=["GET", "POST", "DELETE", "OPTIONS"])

init_db(app)

# Setup structured logging
setup_logging(app)


# ===== Request ID + Error Handlers =====

@app.before_request
def before_request():
    """Generate a request ID and store it in g."""
    from flask import g
    g.request_id = generate_request_id()


@app.after_request
def after_request(response):
    """Add request ID + security headers to every response."""
    from flask import g
    if hasattr(g, "request_id"):
        response.headers["X-Request-ID"] = g.request_id
    # Apply security headers (HSTS, X-Frame-Options, etc.)
    apply_security_headers(response)
    return response


@app.errorhandler(400)
def handle_400(e):
    return jsonify({"ok": False, "error": "Bad request", "detail": str(e)}), 400


@app.errorhandler(401)
def handle_401(e):
    return jsonify({"ok": False, "error": "Unauthorized"}), 401


@app.errorhandler(403)
def handle_403(e):
    return jsonify({"ok": False, "error": "Forbidden"}), 403


@app.errorhandler(404)
def handle_404(e):
    return jsonify({"ok": False, "error": "Not found"}), 404


@app.errorhandler(405)
def handle_405(e):
    return jsonify({"ok": False, "error": "Method not allowed"}), 405


@app.errorhandler(429)
def handle_429(e):
    return jsonify({"ok": False, "error": "Too many requests"}), 429


@app.errorhandler(500)
def handle_500(e):
    from flask import g
    app.logger.error(f"Internal error: {e}", exc_info=True)
    return jsonify({
        "ok": False,
        "error": "Internal server error",
        "request_id": getattr(g, "request_id", None),
    }), 500


@app.errorhandler(Exception)
def handle_unexpected(e):
    from flask import g
    app.logger.error(f"Unexpected error: {e}", exc_info=True)
    return jsonify({
        "ok": False,
        "error": "Internal server error",
        "request_id": getattr(g, "request_id", None),
    }), 500


# ===== Helpers =====

def error(msg, code=400):
    return jsonify({"ok": False, "error": msg}), code


def success(data=None, code=200):
    return jsonify({"ok": True, **(data or {})}), code


def find_agent(agent_id):
    return db.session.get(Agent, agent_id)


def find_agent_for_update(agent_id):
    """Get an agent with a row lock (PostgreSQL) for atomic balance updates.

    Prevents concurrent charge/refund races (double-spend protection).
    On SQLite (dev/test), returns the agent without a lock — SQLite
    serializes writes at the database level.
    """
    drivername = db.engine.url.drivername
    if drivername.startswith("postgresql"):
        return Agent.query.filter_by(id=agent_id).with_for_update().first()
    return db.session.get(Agent, agent_id)


def require_api_key(view_func):
    """Decorator: verifies Bearer token matches the agent in the URL."""
    from functools import wraps
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return error("Missing or invalid Authorization header (use: Bearer ap_...)", 401)
        token = auth[7:].strip()
        if not token.startswith("ap_"):
            return error("Invalid API key format", 401)
        agent_id = kwargs.get("agent_id")
        agent = find_agent(agent_id)
        if not agent:
            return error("Agent not found", 404)
        if not safe_compare(agent.api_key, token):
            return error("API key does not match this agent", 403)
        return view_func(*args, **kwargs)
    return wrapper


def key_ip(request, **kwargs):
    """Rate limit key: by client IP."""
    return f"ip:{request.remote_addr}"


def require_admin(view_func):
    """Decorator: require admin access.

    Two accepted methods:
    1. Session cookie of an authenticated user with role='admin' (preferred)
    2. Authorization: Bearer <ADMIN_API_KEY>  (emergency only)

    Attaches request.current_admin = True for audit context.
    """
    from functools import wraps
    import os

    @wraps(view_func)
    def wrapper(*args, **kwargs):
        # Method 1: session-based admin
        try:
            session = auth.get_session_from_request()
            if session:
                user = db.session.get(User, session.user_id)
                if user and user.is_active and user.role == "admin":
                    request.current_user = user
                    request.current_session = session
                    request.current_admin = True
                    return view_func(*args, **kwargs)
        except Exception:
            pass

        # Method 2: ADMIN_API_KEY (emergency)
        admin_key = os.environ.get("ADMIN_API_KEY", "")
        auth_header = request.headers.get("Authorization", "")

        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if admin_key and safe_compare(token, admin_key):
                request.current_admin = True
                request.current_user = None
                return view_func(*args, **kwargs)

        # Failure — log it
        if not admin_key:
            return error("Admin API is disabled (ADMIN_API_KEY not set)", 503)

        try:
            from models import write_audit
            write_audit(
                "admin.auth.fail",
                actor="unknown",
                ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "")[:200],
                status="error",
                path=request.path,
            )
            db.session.commit()
        except Exception:
            db.session.rollback()

        if not auth_header:
            return error("Authentication required", 401)
        return error("Invalid admin credentials", 403)

    return wrapper


def key_agent(request, **kwargs):
    """Rate limit key: by agent_id."""
    return f"agent:{kwargs.get('agent_id', 'unknown')}"


# ===== Routes =====

@app.route("/health")
def health():
    return success({"service": "agentpay", "version": "0.1.0", "time": int(time.time())})


@app.route("/agents/create", methods=["POST"])
@limit(key_ip, "create")
def create_agent():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name or len(name) > 100:
        return error("Invalid name (required, max 100 chars)")
    webhook_url = (data.get("webhook_url") or "").strip() or None
    if webhook_url and not webhook_url.startswith(("http://", "https://")):
        return error("webhook_url must start with http:// or https://")
    currency = (data.get("currency") or "USD").upper()
    from models import SUPPORTED_CURRENCIES
    if currency not in SUPPORTED_CURRENCIES:
        return error(f"Unsupported currency. Choose from: {SUPPORTED_CURRENCIES}")
    agent = Agent(
        name=name,
        webhook_url=crypto.encrypt_webhook_url(webhook_url),
        currency=currency,
    )
    # If logged in, attach ownership automatically
    owner = auth.attach_owner_if_logged_in(agent)
    db.session.add(agent)
    db.session.flush()
    audit.write_audit_secure("agent.create", agent_id=agent.id,
                user_id=owner.id if owner else None,
                actor=owner.email if owner else "anonymous",
                ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "")[:200],
                name=name, currency=currency, webhook_url=webhook_url or None,
                owner_attached=bool(owner))
    db.session.commit()
    return success({"agent": agent.to_dict(), "api_key": agent.api_key}, 201)


@app.route("/agents/<agent_id>")
@limit(key_ip, "get_agent")
@auth.require_agent_owner
def get_agent(agent_id):
    """Get agent details.

    Authorization:
    - Session (owner or admin)
    - OR API key (Bearer ap_...) matching the agent
    Returns 404 if not authorized (no existence leak).
    """
    agent = request.current_agent
    return success({"agent": agent.to_dict()})


@app.route("/agents/<agent_id>/topup", methods=["POST"])
@limit(key_agent, "topup")
@require_api_key
def topup_disabled(agent_id):
    """DEPRECATED — direct topup removed in task-5.

    Agents must NEVER be able to increase their own balance.
    Allowed alternatives:
    - POST /agents/<id>/stripe/checkout    (real payment)
    - POST /admin/agents/<id>/topup        (admin only, requires reason)

    This stub is kept to avoid silent API breakage: it returns a clear error.
    """
    # Log the attempt (security signal)
    try:
        agent = find_agent(agent_id)
        audit.write_audit_secure(
            "topup.direct.blocked",
            agent_id=agent_id,
            actor=(agent.api_key[:10] + "...") if agent else "unknown",
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")[:200],
            status="error",
        )
        db.session.commit()
    except Exception:
        db.session.rollback()

    return error(
        "Direct topup is disabled. "
        "Use POST /agents/<id>/stripe/checkout for real payments, "
        "or contact an admin to top up your balance.",
        403,
    )


@app.route("/agents/<agent_id>/charge", methods=["POST"])
@limit(key_agent, "charge")
@require_api_key
def charge(agent_id):
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    data = request.get_json(silent=True) or {}
    amount = data.get("amount")
    if not isinstance(amount, int) or amount <= 0 or amount > 1_000_000:
        return error("Invalid amount (must be positive integer in cents, max 1,000,000)")

    # ─── Atomic conditional decrement (task-6, DB-agnostic) ───
    # Single UPDATE with WHERE balance >= amount:
    #   - Prevents double-spend on ALL databases (PostgreSQL + SQLite)
    #   - No race window between check and update
    result = db.session.execute(
        sql_update(Agent)
        .where(Agent.id == agent.id)
        .where(Agent.balance >= amount)
        .values(balance=Agent.balance - amount)
    )
    if result.rowcount == 0:
        # Either agent vanished or insufficient balance
        db.session.rollback()
        current = db.session.get(Agent, agent.id)
        if not current:
            return error("Agent not found", 404)
        return error(f"Insufficient balance ({current.balance} < {amount})", 402)

    # Refresh agent to get new balance
    db.session.expire(agent)
    agent = db.session.get(Agent, agent.id)

    tx = Transaction(agent_id=agent.id, type="charge", amount=amount,
                     description=data.get("description", "Charge"))
    db.session.add(tx)
    db.session.flush()

    # Ledger entry (Task 61)
    ledger.record_entry(
        agent,
        entry_type="charge",
        amount_signed=-amount,
        description=tx.description,
        external_ref=f"tx:{tx.id}",
    )

    audit.write_audit_secure("charge", agent_id=agent.id, ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "")[:200],
                actor=agent.api_key[:10] + "...",
                amount=amount, tx_id=tx.id, description=tx.description)
    db.session.commit()
    fire_webhook(agent, "charge", tx)
    return success({"agent": agent.to_dict(), "transaction": tx.to_dict()})


@app.route("/agents/<agent_id>/transactions")
@limit(key_agent, "transactions")
@require_api_key
def list_transactions(agent_id):
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    limit = min(int(request.args.get("limit", 20)), 100)
    txs = Transaction.query.filter_by(agent_id=agent.id).order_by(Transaction.id.desc()).limit(limit).all()
    return success({"agent_id": agent.id, "transactions": [t.to_dict() for t in txs], "count": len(txs)})


# ===== API Documentation =====

@app.route("/openapi.json")
def openapi_spec():
    """Serve OpenAPI 3.0 spec."""
    from pathlib import Path
    spec_path = Path(__file__).parent / "openapi.json"
    if not spec_path.exists():
        return error("OpenAPI spec not found", 404)
    return app.response_class(
        response=spec_path.read_text(encoding="utf-8"),
        status=200,
        mimetype="application/json",
    )


@app.route("/docs")
def swagger_ui():
    """Swagger UI — interactive API docs."""
    html = """<!DOCTYPE html>
<html>
<head>
  <title>AgentPay API — Docs</title>
  <meta charset="UTF-8">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
window.onload = () => {
  window.ui = SwaggerUIBundle({
    url: "/openapi.json",
    dom_id: "#swagger-ui",
    deepLinking: true,
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
    layout: "BaseLayout",
  });
};
</script>
</body>
</html>"""
    return app.response_class(response=html, status=200, mimetype="text/html")


@app.route("/redoc")
def redoc_ui():
    """ReDoc — alternative API docs."""
    html = """<!DOCTYPE html>
<html>
<head>
  <title>AgentPay API — ReDoc</title>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
  <redoc spec-url="/openapi.json"></redoc>
  <script src="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"></script>
</body>
</html>"""
    return app.response_class(response=html, status=200, mimetype="text/html")




# ===== User-owned agents =====

@app.route("/me/agents", methods=["POST"])
@csrf.require_csrf
@auth.require_user
@limit(key_ip, "create")
def me_create_agent():
    """Create an agent owned by the authenticated user.

    Unlike POST /agents/create, this endpoint requires a session and always
    sets owner_id from the authenticated user (never from request body).
    """
    user = request.current_user
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name or len(name) > 100:
        return error("Invalid name (required, max 100 chars)")
    webhook_url = (data.get("webhook_url") or "").strip() or None
    if webhook_url and not webhook_url.startswith(("http://", "https://")):
        return error("webhook_url must start with http:// or https://")

    currency = (data.get("currency") or "USD").upper()
    from models import SUPPORTED_CURRENCIES
    if currency not in SUPPORTED_CURRENCIES:
        return error(f"Unsupported currency. Choose from: {SUPPORTED_CURRENCIES}")

    agent = Agent(
        name=name,
        webhook_url=crypto.encrypt_webhook_url(webhook_url),
        currency=currency,
        owner_id=user.id,  # always from session, never from body
    )
    db.session.add(agent)
    db.session.flush()
    audit.write_audit_secure(
        "agent.create.owned",
        agent_id=agent.id,
        user_id=user.id,
        actor=user.email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
        name=name, currency=currency,
    )
    db.session.commit()
    return success({"agent": agent.to_dict(), "api_key": agent.api_key}, 201)


@app.route("/me/agents")
@auth.require_user
@limit(key_ip, "get_agent")
def me_list_agents():
    """List agents owned by the authenticated user."""
    user = request.current_user
    agents = Agent.query.filter_by(owner_id=user.id).order_by(Agent.created_at.desc()).all()
    return success({
        "agents": [a.to_dict() for a in agents],
        "count": len(agents),
    })


@app.route("/agents/<agent_id>/claim", methods=["POST"])
@csrf.require_csrf
@auth.require_user
@limit(key_ip, "topup")
def claim_agent(agent_id):
    """Claim an orphan agent (owner_id IS NULL).

    Requirements:
    - User must be authenticated
    - Agent must exist and have no owner (owner_id is NULL)
    - User must provide their password (proof of intent)
    - Agent must not be owned by another user

    Returns 404 if agent missing, 409 if already owned.
    """
    user = request.current_user
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""

    if not auth.verify_password(password, user.password_hash):
        audit.write_audit_secure(
            "agent.claim.fail",
            agent_id=agent_id,
            user_id=user.id,
            actor=user.email,
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")[:200],
            status="error",
            reason="bad_password",
        )
        db.session.commit()
        return error("Password is incorrect", 401)

    agent = db.session.get(Agent, agent_id)
    if not agent:
        return error("Agent not found", 404)

    if agent.owner_id is not None:
        if agent.owner_id == user.id:
            return success({"agent": agent.to_dict(), "message": "Already yours"})
        return error("Agent already claimed by another user", 409)

    # Attach to current user
    agent.owner_id = user.id
    audit.write_audit_secure(
        "agent.claim.success",
        agent_id=agent.id,
        user_id=user.id,
        actor=user.email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
    )
    db.session.commit()
    return success({"agent": agent.to_dict()})



@app.route("/agents/<agent_id>/rotate-key", methods=["POST"])
@csrf.require_csrf
@auth.require_agent_owner
@limit(key_ip, "topup")
def rotate_agent_key(agent_id):
    """Rotate an agent's API key.

    Requirements:
    - Authenticated owner (session) OR admin
    - CSRF token (session-based)
    - Old key is invalidated immediately

    Response includes new api_key (shown once).
    """
    agent = request.current_agent

    from models import generate_api_key
    import time as _time
    old_key_prefix = agent.api_key[:10] + "..."

    agent.api_key = generate_api_key()
    agent.updated_at = int(_time.time())

    actor_user = getattr(request, "current_user", None)
    audit.write_audit_secure(
        "agent.rotate_key",
        agent_id=agent.id,
        user_id=actor_user.id if actor_user else None,
        actor=actor_user.email if actor_user else "unknown",
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
        old_key_prefix=old_key_prefix,
    )
    db.session.commit()

    return success({
        "agent": agent.to_dict(),
        "api_key": agent.api_key,
        "warning": "Old key is now invalid. Save the new key.",
    })


# ===== Auth API (users + sessions) =====

@app.route("/auth/register", methods=["POST"])
@limit(key_ip, "create")
def auth_register():
    """Register a new user account.

    Security note: the FIRST registered user becomes 'admin' automatically
    so the system is bootstrappable. Subsequent registrations default to
    'developer'. Admins can promote/demote later.
    """
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not auth.is_valid_email(email):
        return error("Invalid email address")
    ok, msg = auth.validate_password(password)
    if not ok:
        return error(msg)

    # Check duplicate
    existing = User.query.filter_by(email=email).first()
    if existing:
        return error("Email already registered", 409)

    # Bootstrap: first user = admin
    is_first_user = User.query.count() == 0
    role = "admin" if is_first_user else "developer"

    user = User(
        email=email,
        password_hash=auth.hash_password(password),
        role=role,
        is_active=True,
        email_verified=False,
    )
    db.session.add(user)
    db.session.flush()

    # Audit
    audit.write_audit_secure(
        "auth.register",
        user_id=user.id,
        actor=email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
        role=role,
        is_first_user=is_first_user,
    )
    db.session.commit()

    return success({
        "user": user.to_dict(),
        "bootstrap_admin": is_first_user,
    }, 201)


@app.route("/auth/login", methods=["POST"])
@limit(key_ip, "create")  # reuse 'create' rate limit (5/min per IP)
def auth_login():
    """Log in with email + password. Sets a session cookie."""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return error("Email and password required")

    user = User.query.filter_by(email=email).first()
    # Uniform error to prevent user enumeration
    GENERIC_ERR = "Invalid credentials"

    if not user:
        return error(GENERIC_ERR, 401)

    if not user.is_active:
        return error("Account disabled", 403)

    if auth.is_user_locked(user):
        return error("Account temporarily locked. Try again later.", 429)

    if not auth.verify_password(password, user.password_hash):
        auth.record_failed_login(user)
        audit.write_audit_secure(
            "auth.login.fail",
            user_id=user.id,
            actor=email,
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")[:200],
            status="error",
        )
        db.session.commit()
        return error(GENERIC_ERR, 401)

    # ─── 2FA check (Task 19) ───
    if user.totp_enabled:
        totp_code = (data.get("totp_code") or "").strip()
        recovery_code = (data.get("recovery_code") or "").strip()

        if not totp_code and not recovery_code:
            audit.write_audit_secure(
                "auth.login.2fa.required",
                user_id=user.id,
                actor=email,
                ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "")[:200],
                status="pending",
            )
            db.session.commit()
            return jsonify({
                "ok": False,
                "requires_2fa": True,
                "error": "2FA code required",
            }), 401

        verified = False
        if totp_code:
            if totp.verify_code(user.totp_secret, totp_code):
                verified = True
        elif recovery_code:
            ok, remaining = totp.verify_recovery_code(user.recovery_codes_hash, recovery_code)
            if ok:
                user.recovery_codes_hash = remaining
                verified = True

        if not verified:
            auth.record_failed_login(user)
            audit.write_audit_secure(
                "auth.login.2fa.fail",
                user_id=user.id,
                actor=email,
                ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "")[:200],
                status="error",
            )
            db.session.commit()
            return error("Invalid 2FA code", 401)

    # Success — create session
    session = auth.create_session(
        user,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
    )
    auth.reset_failed_logins(user)

    audit.write_audit_secure(
        "auth.login.success",
        user_id=user.id,
        actor=email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
        session_id=session.id[:8] + "...",
    )
    db.session.commit()

    csrf_token = csrf.generate_csrf_token()
    resp = success({"user": user.to_dict()})
    auth.set_session_cookie(resp, session)
    csrf.set_csrf_cookie(resp, csrf_token)
    return resp


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    """Log out the current session."""
    session = auth.get_session_from_request()
    if session:
        user_id = session.user_id
        auth.revoke_session(session)
        audit.write_audit_secure(
            "auth.logout",
            user_id=user_id,
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")[:200],
        )
        db.session.commit()
    resp = success({"message": "Logged out"})
    auth.clear_session_cookie(resp)
    csrf.clear_csrf_cookie(resp)
    return resp


@app.route("/auth/me")
@auth.require_user
def auth_me():
    """Return the authenticated user's info + current session."""
    user = request.current_user
    session = request.current_session
    return success({
        "user": user.to_dict(),
        "session": session.to_dict(),
    })


@app.route("/auth/logout-all", methods=["POST"])
@auth.require_write
def auth_logout_all():
    """Revoke all sessions except the current one."""
    user = request.current_user
    current = request.current_session
    auth.revoke_all_user_sessions(user.id, except_session_id=current.id)
    audit.write_audit_secure(
        "auth.logout_all",
        user_id=user.id,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
    )
    db.session.commit()
    return success({"message": "All other sessions revoked"})



@app.route("/auth/change-password", methods=["POST"])
@csrf.require_csrf
@auth.require_write
def auth_change_password():
    """Change the current user's password.

    Requires the current password as confirmation.
    All other sessions are revoked (the current session stays).
    """
    user = request.current_user
    current_session = request.current_session
    data = request.get_json(silent=True) or {}

    current_password = data.get("current_password") or ""
    new_password = data.get("new_password") or ""

    if not auth.verify_password(current_password, user.password_hash):
        audit.write_audit_secure(
            "auth.change_password.fail",
            user_id=user.id,
            actor=user.email,
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")[:200],
            status="error",
        )
        db.session.commit()
        return error("Current password is incorrect", 401)

    ok, msg = auth.validate_password(new_password)
    if not ok:
        return error(msg)

    if current_password == new_password:
        return error("New password must be different from current password")

    user.password_hash = auth.hash_password(new_password)

    # Revoke all other sessions (security best practice)
    auth.revoke_all_user_sessions(user.id, except_session_id=current_session.id)

    audit.write_audit_secure(
        "auth.change_password.success",
        user_id=user.id,
        actor=user.email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
        revoked_other_sessions=True,
    )
    db.session.commit()

    return success({
        "message": "Password changed. All other sessions revoked.",
    })


@app.route("/auth/change-email", methods=["POST"])
@csrf.require_csrf
@auth.require_write
def auth_change_email():
    """Change the current user's email.

    Requires the current password as confirmation.
    All other sessions are revoked.
    """
    user = request.current_user
    current_session = request.current_session
    data = request.get_json(silent=True) or {}

    new_email = (data.get("new_email") or "").strip().lower()
    password = data.get("password") or ""

    if not auth.verify_password(password, user.password_hash):
        audit.write_audit_secure(
            "auth.change_email.fail",
            user_id=user.id,
            actor=user.email,
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")[:200],
            status="error",
        )
        db.session.commit()
        return error("Password is incorrect", 401)

    if not auth.is_valid_email(new_email):
        return error("Invalid email address")

    if new_email == user.email:
        return error("New email is the same as current email")

    existing = User.query.filter_by(email=new_email).first()
    if existing:
        return error("Email already in use", 409)

    old_email = user.email
    user.email = new_email
    # Any change to email should mark as unverified (security)
    user.email_verified = False

    auth.revoke_all_user_sessions(user.id, except_session_id=current_session.id)

    audit.write_audit_secure(
        "auth.change_email.success",
        user_id=user.id,
        actor=old_email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
        old_email=old_email,
        new_email=new_email,
        revoked_other_sessions=True,
    )
    db.session.commit()

    return success({
        "message": "Email changed. Verification required.",
        "user": user.to_dict(),
    })


@app.route("/auth/sessions")
@auth.require_user
def auth_list_sessions():
    """List all active sessions of the current user."""
    user = request.current_user
    current = request.current_session

    now = int(time.time())
    sessions = Session.query.filter(
        Session.user_id == user.id,
        Session.revoked_at.is_(None),
        Session.expires_at > now,
    ).order_by(Session.created_at.desc()).all()

    return success({
        "sessions": [
            {
                **s.to_dict(),
                "is_current": s.id == current.id,
            }
            for s in sessions
        ],
        "count": len(sessions),
    })



# ===== Admin: User Management =====

def _count_active_admins(exclude_user_id=None):
    """Count active users with role=admin. Optionally exclude a user."""
    q = User.query.filter_by(role="admin", is_active=True)
    if exclude_user_id:
        q = q.filter(User.id != exclude_user_id)
    return q.count()



# ═══════════════════════════════════════════════════════
# 2FA / TOTP Endpoints (Task 19)
# ═══════════════════════════════════════════════════════

@app.route("/auth/2fa/status")
@auth.require_user
def auth_2fa_status():
    """Return whether 2FA is enabled for the current user."""
    user = request.current_user
    remaining = totp.count_remaining_recovery_codes(user.recovery_codes_hash)
    return success({
        "totp_enabled": bool(user.totp_enabled),
        "recovery_codes_remaining": remaining,
    })


@app.route("/auth/2fa/setup", methods=["POST"])
@auth.require_write
def auth_2fa_setup():
    """Generate a new TOTP secret + provisioning URI + QR data URL.

    Does NOT enable 2FA yet — user must verify a code first via /auth/2fa/enable.
    The secret is stored temporarily (not activated).
    """
    user = request.current_user

    if user.totp_enabled:
        return error("2FA is already enabled. Disable it first.", 400)

    secret = totp.generate_secret()
    uri = totp.get_provisioning_uri(secret, user.email)
    qr_data_url = totp.provisioning_uri_to_qr_svg_data_url(uri)

    # Store secret but keep totp_enabled=False until verified
    user.totp_secret = secret
    db.session.commit()

    audit.write_audit_secure(
        "auth.2fa.setup",
        user_id=user.id,
        actor=user.email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
    )
    db.session.commit()

    return success({
        "secret": secret,
        "provisioning_uri": uri,
        "qr_data_url": qr_data_url,
        "instructions": "Scan the QR with Google Authenticator, then POST a code to /auth/2fa/enable",
    })


@app.route("/auth/2fa/enable", methods=["POST"])
@auth.require_write
def auth_2fa_enable():
    """Enable 2FA after verifying a TOTP code against the pending secret.

    Returns 10 recovery codes (plaintext — shown ONCE).
    """
    user = request.current_user

    if user.totp_enabled:
        return error("2FA is already enabled", 400)

    if not user.totp_secret:
        return error("No pending 2FA secret. Call /auth/2fa/setup first.", 400)

    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()

    if not totp.verify_code(user.totp_secret, code):
        audit.write_audit_secure(
            "auth.2fa.enable.fail",
            user_id=user.id,
            actor=user.email,
            ip=request.remote_addr,
            status="error",
        )
        db.session.commit()
        return error("Invalid TOTP code", 401)

    # Generate + hash recovery codes
    plaintext_codes = totp.generate_recovery_codes()
    user.recovery_codes_hash = totp.hash_recovery_codes(plaintext_codes)
    user.totp_enabled = True
    db.session.commit()

    audit.write_audit_secure(
        "auth.2fa.enabled",
        user_id=user.id,
        actor=user.email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
    )
    db.session.commit()

    return success({
        "totp_enabled": True,
        "recovery_codes": plaintext_codes,
        "warning": "Save these recovery codes now. They will NOT be shown again.",
    })


@app.route("/auth/2fa/disable", methods=["POST"])
@auth.require_write
def auth_2fa_disable():
    """Disable 2FA. Requires password + current TOTP code (or recovery code)."""
    user = request.current_user

    if not user.totp_enabled:
        return error("2FA is not enabled", 400)

    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""
    code = (data.get("code") or "").strip()
    recovery_code = (data.get("recovery_code") or "").strip()

    if not auth.verify_password(password, user.password_hash):
        return error("Invalid password", 401)

    verified = False
    if code and totp.verify_code(user.totp_secret, code):
        verified = True
    elif recovery_code:
        ok, _ = totp.verify_recovery_code(user.recovery_codes_hash, recovery_code)
        if ok:
            verified = True

    if not verified:
        return error("Invalid 2FA code or recovery code", 401)

    user.totp_secret = None
    user.totp_enabled = False
    user.recovery_codes_hash = None
    db.session.commit()

    audit.write_audit_secure(
        "auth.2fa.disabled",
        user_id=user.id,
        actor=user.email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
    )
    db.session.commit()

    return success({"totp_enabled": False})


@app.route("/auth/2fa/recovery/regenerate", methods=["POST"])
@auth.require_write
def auth_2fa_recovery_regenerate():
    """Regenerate recovery codes. Requires password + current TOTP code."""
    user = request.current_user

    if not user.totp_enabled:
        return error("2FA is not enabled", 400)

    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""
    code = (data.get("code") or "").strip()

    if not auth.verify_password(password, user.password_hash):
        return error("Invalid password", 401)

    if not totp.verify_code(user.totp_secret, code):
        return error("Invalid 2FA code", 401)

    plaintext_codes = totp.generate_recovery_codes()
    user.recovery_codes_hash = totp.hash_recovery_codes(plaintext_codes)
    db.session.commit()

    audit.write_audit_secure(
        "auth.2fa.recovery.regenerated",
        user_id=user.id,
        actor=user.email,
        ip=request.remote_addr,
    )
    db.session.commit()

    return success({
        "recovery_codes": plaintext_codes,
        "warning": "Old recovery codes are now invalid.",
    })


# ═══════════════════════════════════════════════════════
# Password Reset Endpoints (Task 17)
# ═══════════════════════════════════════════════════════

@app.route("/auth/forgot-password", methods=["POST"])
@limit(key_ip, "create")
def auth_forgot_password():
    """Request a password reset email. Always returns success (anti-enumeration)."""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return error("Email is required")

    GENERIC_OK = {"ok": True, "message": "If that email exists, a reset link has been sent."}

    user = User.query.filter_by(email=email).first()
    if not user or not user.is_active:
        # Anti-enumeration: same response for missing/inactive users
        audit.write_audit_secure(
            "auth.password.forgot.unknown",
            actor=email,
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")[:200],
            status="noop",
        )
        db.session.commit()
        return jsonify(GENERIC_OK)

    token = auth.generate_reset_token(
        user.id,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
    )
    sent = mailer.send_password_reset(user.email, token)

    audit.write_audit_secure(
        "auth.password.forgot",
        user_id=user.id,
        actor=email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
        email_sent=sent,
    )
    db.session.commit()

    return jsonify(GENERIC_OK)


@app.route("/auth/reset-password", methods=["POST"])
@limit(key_ip, "create")
def auth_reset_password():
    """Reset password using a valid token. Marks token as used."""
    data = request.get_json(silent=True) or {}
    raw_token = (data.get("token") or "").strip()
    new_password = data.get("password") or ""

    if not raw_token:
        return error("Token is required")

    if len(new_password) < 8:
        return error("Password must be at least 8 characters")

    token = auth.consume_reset_token(raw_token)
    if not token:
        audit.write_audit_secure(
            "auth.password.reset.invalid",
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")[:200],
            status="error",
        )
        db.session.commit()
        return error("Invalid or expired token", 400)

    user = db.session.get(User, token.user_id)
    if not user or not user.is_active:
        return error("Invalid or expired token", 400)

    # Update password
    user.password_hash = auth.hash_password(new_password)
    token.used_at = int(time.time())

    # Revoke all existing sessions (security)
    auth.revoke_all_user_sessions(user.id)

    audit.write_audit_secure(
        "auth.password.reset",
        user_id=user.id,
        actor=user.email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
        sessions_revoked=True,
    )
    db.session.commit()

    return success({"message": "Password updated. Please log in again."})


# ═══════════════════════════════════════════════════════
# Email Verification Endpoints (Task 18)
# ═══════════════════════════════════════════════════════

@app.route("/auth/verify-email/send", methods=["POST"])
@auth.require_write
def auth_verify_email_send():
    """Send a verification email to the current user."""
    user = request.current_user

    if user.email_verified:
        return success({"message": "Email already verified", "email_verified": True})

    token = auth.generate_verification_token(
        user.id,
        user.email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
    )
    sent = mailer.send_email_verification(user.email, token)

    audit.write_audit_secure(
        "auth.email.verify.sent",
        user_id=user.id,
        actor=user.email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
        email_sent=sent,
    )
    db.session.commit()

    return success({
        "message": "Verification email sent" if sent else "Email service unavailable",
        "email_sent": sent,
    })


@app.route("/auth/verify-email/confirm", methods=["POST"])
@limit(key_ip, "create")
def auth_verify_email_confirm():
    """Confirm email verification with a valid token."""
    data = request.get_json(silent=True) or {}
    raw_token = (data.get("token") or "").strip()

    if not raw_token:
        return error("Token is required")

    token = auth.consume_verification_token(raw_token)
    if not token:
        return error("Invalid or expired token", 400)

    user = db.session.get(User, token.user_id)
    if not user:
        return error("Invalid or expired token", 400)

    # Only mark verified if email still matches (user may have changed email)
    if user.email.lower() != token.email.lower():
        return error("Token does not match current email", 400)

    user.email_verified = True
    token.used_at = int(time.time())
    db.session.commit()

    audit.write_audit_secure(
        "auth.email.verified",
        user_id=user.id,
        actor=user.email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
    )
    db.session.commit()

    return success({"email_verified": True, "message": "Email verified successfully"})

@app.route("/admin/users")
@auth.require_role("admin")
@limit(key_ip, "transactions")
def admin_list_users():
    """List all users (admin only)."""
    q = request.args.get("q", "").strip()
    try:
        limit_n = min(int(request.args.get("limit", 100)), 500)
    except ValueError:
        return error("Invalid limit")

    query = User.query
    if q:
        query = query.filter(User.email.like(f"%{q}%"))

    users = query.order_by(User.created_at.desc()).limit(limit_n).all()
    return success({
        "users": [u.to_dict() for u in users],
        "count": len(users),
    })


@app.route("/admin/users/<user_id>")
@auth.require_role("admin")
@limit(key_ip, "transactions")
def admin_get_user(user_id):
    """Get a specific user's details."""
    user = db.session.get(User, user_id)
    if not user:
        return error("User not found", 404)

    agent_count = Agent.query.filter_by(owner_id=user.id).count()

    data = user.to_dict()
    data["agent_count"] = agent_count
    return success({"user": data})


@app.route("/admin/users/<user_id>/promote", methods=["POST"])
@csrf.require_csrf
@auth.require_role("admin")
@limit(key_ip, "topup")
def admin_promote_user(user_id):
    """Promote a user to admin role."""
    current = request.current_user
    target = db.session.get(User, user_id)
    if not target:
        return error("User not found", 404)

    if target.role == "admin":
        return success({"user": target.to_dict(), "message": "Already admin"})

    target.role = "admin"
    audit.write_audit_secure(
        "admin.user.promote",
        user_id=current.id,
        actor=current.email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
        target_user_id=target.id,
        target_email=target.email,
    )
    db.session.commit()
    return success({"user": target.to_dict()})


@app.route("/admin/users/<user_id>/demote", methods=["POST"])
@csrf.require_csrf
@auth.require_role("admin")
@limit(key_ip, "topup")
def admin_demote_user(user_id):
    """Demote an admin to developer. Protects the last admin."""
    current = request.current_user
    target = db.session.get(User, user_id)
    if not target:
        return error("User not found", 404)

    if target.id == current.id:
        return error("Cannot demote yourself", 403)

    if target.role != "admin":
        return success({"user": target.to_dict(), "message": "Not an admin"})

    if _count_active_admins(exclude_user_id=target.id) == 0:
        return error("Cannot demote the last active admin", 403)

    target.role = "developer"
    audit.write_audit_secure(
        "admin.user.demote",
        user_id=current.id,
        actor=current.email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
        target_user_id=target.id,
        target_email=target.email,
    )
    db.session.commit()
    return success({"user": target.to_dict()})


@app.route("/admin/users/<user_id>/disable", methods=["POST"])
@csrf.require_csrf
@auth.require_role("admin")
@limit(key_ip, "topup")
def admin_disable_user(user_id):
    """Disable a user and revoke all their sessions. Protects last admin."""
    current = request.current_user
    target = db.session.get(User, user_id)
    if not target:
        return error("User not found", 404)

    if target.id == current.id:
        return error("Cannot disable yourself", 403)

    if not target.is_active:
        return success({"user": target.to_dict(), "message": "Already disabled"})

    if target.role == "admin" and _count_active_admins(exclude_user_id=target.id) == 0:
        return error("Cannot disable the last active admin", 403)

    target.is_active = False
    auth.revoke_all_user_sessions(target.id)

    audit.write_audit_secure(
        "admin.user.disable",
        user_id=current.id,
        actor=current.email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
        target_user_id=target.id,
        target_email=target.email,
        sessions_revoked=True,
    )
    db.session.commit()
    return success({"user": target.to_dict(), "sessions_revoked": True})


@app.route("/admin/users/<user_id>/enable", methods=["POST"])
@csrf.require_csrf
@auth.require_role("admin")
@limit(key_ip, "topup")
def admin_enable_user(user_id):
    """Re-enable a disabled user account."""
    current = request.current_user
    target = db.session.get(User, user_id)
    if not target:
        return error("User not found", 404)

    if target.is_active:
        return success({"user": target.to_dict(), "message": "Already active"})

    target.is_active = True
    target.failed_logins = 0
    target.locked_until = None

    audit.write_audit_secure(
        "admin.user.enable",
        user_id=current.id,
        actor=current.email,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
        target_user_id=target.id,
        target_email=target.email,
    )
    db.session.commit()
    return success({"user": target.to_dict()})



# ===== Admin: Topup with full protection =====

@app.route("/admin/agents/<agent_id>/topup", methods=["POST"])
@csrf.require_csrf
@require_admin
@limit(key_ip, "topup")
def admin_topup(agent_id):
    """Admin-only topup with daily limit + idempotency.

    Body (JSON):
      - amount_cents (int, required, >0, <= 50000)
      - reason (str, required, 5-500 chars)
      - currency (str, default "USD")
    Headers:
      - Idempotency-Key (required)
      - X-CSRF-Token (required for session-based admin)
    """
    data = request.get_json(silent=True) or {}

    amount_cents = data.get("amount_cents")
    reason = (data.get("reason") or "").strip()
    currency = (data.get("currency") or "USD").upper()

    # Validate
    if not isinstance(amount_cents, int) or amount_cents <= 0:
        return error("amount_cents must be a positive integer", 400)
    if amount_cents > topup_helpers.MAX_TOPUP_PER_TXN_CENTS:
        return error(
            f"amount_cents exceeds per-transaction limit "
            f"({topup_helpers.MAX_TOPUP_PER_TXN_CENTS} cents = "
            f"${topup_helpers.MAX_TOPUP_PER_TXN_CENTS/100:.2f})",
            400,
        )
    if len(reason) < 5 or len(reason) > 500:
        return error("reason is required (5-500 chars)", 400)

    idem_key = request.headers.get("Idempotency-Key", "").strip()
    if not idem_key or len(idem_key) > 128:
        return error("Idempotency-Key header required (max 128 chars)", 400)

    actor_user = getattr(request, "current_user", None)

    result = topup_helpers.perform_topup(
        agent_id=agent_id,
        amount_cents=amount_cents,
        source="admin",
        currency=currency,
        actor_user=actor_user,
        actor_email=actor_user.email if actor_user else "admin-api-key",
        reason=reason,
        idempotency_key=idem_key,
    )

    if not result["ok"]:
        code = result.get("code", 400)
        return error(result["error"], code)

    if result.get("replay"):
        return success(result["data"])

    # Fire webhook
    try:
        fire_webhook(result["agent"], "topup", result["transaction"])
    except Exception:
        pass

    return success(result["data"], 201)


# ===== Admin API =====

@app.route("/admin/stats")
@require_admin
def admin_stats():
    """Get overall system stats."""
    total_agents = Agent.query.count()
    total_txs = Transaction.query.count()
    total_subs = Subscription.query.count()
    active_subs = Subscription.query.filter_by(status="active").count()
    # Sum balances grouped by currency
    balances = {}
    for agent in Agent.query.all():
        cur = agent.currency
        balances[cur] = balances.get(cur, 0) + agent.balance
    # Sum by transaction type
    tx_by_type = {}
    for tx in Transaction.query.all():
        tx_by_type[tx.type] = tx_by_type.get(tx.type, 0) + tx.amount
    return success({
        "agents": {"total": total_agents},
        "transactions": {"total": total_txs, "by_type": tx_by_type},
        "subscriptions": {"total": total_subs, "active": active_subs},
        "balances": balances,
    })


@app.route("/admin/agents")
@require_admin
def admin_list_agents():
    """List all agents (with optional search)."""
    q = request.args.get("q", "").strip()
    try:
        limit_n = min(int(request.args.get("limit", 50)), 500)
    except ValueError:
        return error("Invalid limit")
    query = Agent.query
    if q:
        query = query.filter(Agent.name.like(f"%{q}%"))
    agents = query.order_by(Agent.created_at.desc()).limit(limit_n).all()
    return success({"agents": [a.to_dict() for a in agents], "count": len(agents)})


@app.route("/admin/agents/<agent_id>", methods=["DELETE"])
@require_admin
def admin_delete_agent(agent_id):
    """Delete an agent and all its transactions/subscriptions."""
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    Subscription.query.filter_by(agent_id=agent.id).delete()
    Transaction.query.filter_by(agent_id=agent.id).delete()
    db.session.delete(agent)
    audit.write_audit_secure("admin.agent.delete", agent_id=agent_id,
                ip=request.remote_addr,
                actor="admin")
    db.session.commit()
    return success({"deleted": agent_id})


@app.route("/admin/agents/<agent_id>/balance", methods=["POST"])
@require_admin
def admin_set_balance(agent_id):
    """Set an agent's balance directly (admin override)."""
    agent = find_agent_for_update(agent_id)  # Row lock (task-6)
    if not agent:
        return error("Agent not found", 404)
    data = request.get_json(silent=True) or {}
    new_balance = data.get("balance")
    if not isinstance(new_balance, int) or new_balance < 0:
        return error("balance must be a non-negative integer (in smallest unit)")
    old_balance = agent.balance
    diff = new_balance - old_balance
    agent.balance = new_balance
    tx = Transaction(
        agent_id=agent.id,
        type="admin_adjust" if diff >= 0 else "admin_adjust",
        amount=abs(diff),
        description=f"Admin: {old_balance} -> {new_balance}",
    )
    db.session.add(tx)
    db.session.flush()

    # Ledger entry (Task 61) — signed delta for admin adjustment
    actor_user_id = request.current_user.id if hasattr(request, "current_user") and request.current_user else None
    ledger.record_entry(
        agent,
        entry_type="admin_adjust",
        amount_signed=diff,
        description=tx.description,
        created_by_user_id=actor_user_id,
        external_ref=f"tx:{tx.id}",
    )

    audit.write_audit_secure("admin.balance.set", agent_id=agent.id,
                ip=request.remote_addr, actor="admin",
                old_balance=old_balance, new_balance=new_balance,
                tx_id=tx.id)
    db.session.commit()
    return success({"agent": agent.to_dict(), "transaction": tx.to_dict()})


# ===== Audit Log =====

@app.route("/admin/audit")
@require_admin
@limit(key_ip, "transactions")
def list_audit():
    """List audit log entries (admin only).

    Pagination: limit (max 200), offset.
    Filters: action, user_id, agent_id, status, since, until.
    Logs this read as 'audit.read' (with hash chain).
    """
    try:
        limit_n = min(int(request.args.get("limit", 50)), 200)
    except ValueError:
        return error("Invalid limit (must be int)")
    try:
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return error("Invalid offset (must be int)")

    action = request.args.get("action")
    user_id = request.args.get("user_id")
    agent_id = request.args.get("agent_id")
    status_f = request.args.get("status")
    since = request.args.get("since")
    until = request.args.get("until")

    q = AuditLog.query
    if action:
        q = q.filter_by(action=action[:80])
    if user_id:
        q = q.filter_by(user_id=user_id[:32])
    if agent_id:
        q = q.filter_by(agent_id=agent_id[:32])
    if status_f:
        if status_f not in ("ok", "error"):
            return error("status must be 'ok' or 'error'")
        q = q.filter_by(status=status_f)
    if since:
        try:
            q = q.filter(AuditLog.timestamp >= int(since))
        except ValueError:
            return error("Invalid since (must be unix timestamp)")
    if until:
        try:
            q = q.filter(AuditLog.timestamp <= int(until))
        except ValueError:
            return error("Invalid until (must be unix timestamp)")

    total = q.count()
    entries = q.order_by(AuditLog.id.desc()).offset(offset).limit(limit_n).all()

    # Log the read itself (post-query, so no infinite recursion)
    try:
        audit.write_audit_secure(
            "audit.read",
            actor="admin",
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")[:200],
            filters={
                "action": action, "user_id": user_id,
                "agent_id": agent_id, "status": status_f,
                "since": since, "until": until,
            },
            returned=len(entries),
        )
        db.session.commit()
    except Exception:
        db.session.rollback()

    return success({
        "entries": [e.to_dict() for e in entries],
        "count": len(entries),
        "total": total,
        "limit": limit_n,
        "offset": offset,
    })


@app.route("/admin/audit/verify")
@require_admin
@limit(key_ip, "transactions")
def admin_audit_verify():
    """Verify the integrity of the audit hash chain."""
    try:
        start_id = request.args.get("start_id")
        start_id = int(start_id) if start_id else None
        limit_n = min(int(request.args.get("limit", 10000)), 50000)
    except ValueError:
        return error("Invalid parameters")

    result = audit.verify_audit_chain(start_id=start_id, limit=limit_n)
    result["legacy_entries_skipped"] = AuditLog.query.filter(AuditLog.record_hash.is_(None)).count()

    try:
        audit.write_audit_secure(
            "audit.verify",
            actor="admin",
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")[:200],
            result_ok=result["ok"],
            checked=result["checked"],
        )
        db.session.commit()
    except Exception:
        db.session.rollback()

    return success(result)


@app.route("/admin/audit/checkpoint")
@require_admin
@limit(key_ip, "transactions")
def admin_audit_checkpoint():
    """Return a compact checkpoint of the audit chain (store off-site)."""
    return success(audit.get_chain_checkpoint())


# ===== Refunds =====


# ═══════════════════════════════════════════════════════
# Ledger & Reconciliation (Tasks 61 + 70)
# ═══════════════════════════════════════════════════════

@app.route("/admin/ledger/<agent_id>")
@require_admin
def admin_ledger_list(agent_id):
    """List ledger entries for an agent (admin). Newest first, paginated."""
    agent = db.session.get(Agent, agent_id)
    if not agent:
        return error("Agent not found", 404)

    limit = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))
    entry_type = request.args.get("type")

    q = ledger.LedgerEntry.query.filter_by(agent_id=agent.id)
    if entry_type:
        q = q.filter_by(type=entry_type)
    q = q.order_by(ledger.LedgerEntry.created_at.desc(), ledger.LedgerEntry.id.desc())

    total = q.count()
    entries = q.limit(limit).offset(offset).all()

    return success({
        "agent_id": agent.id,
        "balance": agent.balance,
        "total_entries": total,
        "limit": limit,
        "offset": offset,
        "entries": [e.to_dict() for e in entries],
    })


@app.route("/admin/audit/reconcile/<agent_id>", methods=["POST"])
@require_admin
def admin_audit_reconcile_agent(agent_id):
    """Reconcile one agent: verify balance == sum(ledger entries)."""
    agent = db.session.get(Agent, agent_id)
    if not agent:
        return error("Agent not found", 404)

    result = ledger.reconcile_agent(agent)

    actor_user = getattr(request, "current_user", None)
    audit.write_audit_secure(
        "admin.audit.reconcile",
        user_id=actor_user.id if actor_user else None,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
        agent_id=agent.id,
        matches=result["matches"],
        discrepancy=result["discrepancy"],
    )
    db.session.commit()

    return success({"reconciliation": result})


@app.route("/admin/audit/reconcile-all", methods=["POST"])
@require_admin
def admin_audit_reconcile_all():
    """Reconcile all agents. Returns summary + list of mismatches."""
    result = ledger.reconcile_all()

    actor_user = getattr(request, "current_user", None)
    audit.write_audit_secure(
        "admin.audit.reconcile_all",
        user_id=actor_user.id if actor_user else None,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200],
        total=result["total_agents"],
        matched=result["matched"],
        mismatched=result["mismatched"],
    )
    db.session.commit()

    return success({"summary": {
        "total_agents": result["total_agents"],
        "matched": result["matched"],
        "mismatched": result["mismatched"],
    }, "mismatches": result["mismatches"]})

@app.route("/agents/<agent_id>/refund", methods=["POST"])
@limit(key_agent, "topup")
@require_api_key
def refund_transaction(agent_id):
    """Refund a previous charge by creating a reverse transaction."""
    agent = find_agent_for_update(agent_id)  # Row lock (task-6)
    if not agent:
        return error("Agent not found", 404)
    data = request.get_json(silent=True) or {}
    tx_id = data.get("transaction_id")
    if not isinstance(tx_id, int):
        return error("transaction_id (integer) is required")
    reason = (data.get("reason") or "").strip()[:200]

    original = db.session.get(Transaction, tx_id)
    if not original or original.agent_id != agent.id:
        return error("Transaction not found for this agent", 404)
    if original.type != "charge":
        return error("Only 'charge' transactions can be refunded")
    # Prevent double refunds (check by prefix "Refund:{id}")
    prefix = f"Refund:{original.id}"
    already = Transaction.query.filter(
        Transaction.agent_id == agent.id,
        Transaction.type == "refund",
        Transaction.description.like(prefix + "%"),
    ).first()
    if already:
        return error("Already refunded", 409)

    agent.balance += original.amount
    refund = Transaction(
        agent_id=agent.id,
        type="refund",
        amount=original.amount,
        description=f"Refund:{original.id}" + (f" ({reason})" if reason else ""),
    )
    db.session.add(refund)
    db.session.flush()  # get refund.id without committing

    # Ledger entry (Task 61) — references the original charge
    original_ledger = ledger.LedgerEntry.query.filter_by(
        agent_id=agent.id,
        external_ref=f"tx:{original.id}",
    ).first()

    ledger.record_entry(
        agent,
        entry_type="refund",
        amount_signed=original.amount,
        description=refund.description,
        related_entry_id=original_ledger.id if original_ledger else None,
        external_ref=f"tx:{refund.id}",
    )
    audit.write_audit_secure("refund", agent_id=agent.id, ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "")[:200],
                metadata={"refund_tx_id": refund.id, "original_tx_id": original.id,
                          "amount": original.amount, "reason": reason})
    db.session.commit()
    return success({"agent": agent.to_dict(), "refund": refund.to_dict(), "original_tx_id": original.id})


# ===== Subscriptions =====

INTERVALS = {
    "daily": 86400,
    "weekly": 604800,
    "monthly": 2592000,
    "yearly": 31536000,
}


@app.route("/agents/<agent_id>/subscriptions/create", methods=["POST"])
@limit(key_agent, "topup")
@require_api_key
def create_subscription(agent_id):
    """Create a recurring subscription for an agent."""
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name or len(name) > 100:
        return error("Invalid name (required, max 100 chars)")
    amount = data.get("amount")
    if not isinstance(amount, int) or amount <= 0 or amount > 1_000_000:
        return error("Invalid amount (positive integer, max 1,000,000)")
    interval_key = (data.get("interval") or "monthly").lower()
    if interval_key not in INTERVALS:
        return error(f"Invalid interval. Choose from: {list(INTERVALS.keys())}")
    interval_seconds = INTERVALS[interval_key]
    now = int(time.time())
    sub = Subscription(
        agent_id=agent.id,
        name=name,
        amount=amount,
        interval_seconds=interval_seconds,
        next_charge_at=now + interval_seconds,
    )
    db.session.add(sub)
    db.session.flush()  # get sub.id without committing
    audit.write_audit_secure("subscription.create", agent_id=agent.id, ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "")[:200],
                metadata={"sub_id": sub.id, "name": name, "amount": amount,
                          "interval_seconds": interval_seconds})
    db.session.commit()
    return success({"subscription": sub.to_dict()}, 201)


@app.route("/agents/<agent_id>/subscriptions")
@limit(key_agent, "transactions")
@require_api_key
def list_subscriptions(agent_id):
    """List agent's subscriptions."""
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    subs = Subscription.query.filter_by(agent_id=agent.id).order_by(Subscription.id.desc()).all()
    return success({"subscriptions": [x.to_dict() for x in subs], "count": len(subs)})


@app.route("/agents/<agent_id>/subscriptions/<int:sub_id>/cancel", methods=["POST"])
@limit(key_agent, "topup")
@require_api_key
def cancel_subscription(agent_id, sub_id):
    """Cancel a subscription."""
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    sub = db.session.get(Subscription, sub_id)
    if not sub or sub.agent_id != agent.id:
        return error("Subscription not found", 404)
    if sub.status == "cancelled":
        return success({"subscription": sub.to_dict(), "message": "Already cancelled"})
    sub.status = "cancelled"
    sub.cancelled_at = int(time.time())
    audit.write_audit_secure("subscription.cancel", agent_id=agent.id, ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "")[:200],
                metadata={"sub_id": sub.id, "name": sub.name, "amount": sub.amount})
    db.session.commit()
    return success({"subscription": sub.to_dict()})


@app.route("/admin/run-billing", methods=["POST"])
@csrf.require_csrf
@require_admin
@limit(key_ip, "topup")
def run_billing():
    """Run billing for due subscriptions.

    Security:
    - CSRF required (session-based admin)
    - Idempotency-Key header required (prevents duplicate charges)
    - dry_run defaults to true; must pass {"dry_run": false} to actually charge
    - Batch limit: 100 subscriptions per run
    - PostgreSQL advisory lock: prevents concurrent runs
    - Every run logged in audit log

    Body (JSON):
      - dry_run (bool): default true
      - limit (int): default 100, max 100
      - Idempotency-Key (header): required
    """
    from models import IdempotencyKey, BillingRun
    from sqlalchemy import text as sql_text
    import hashlib, json as _json

    # ===== 1. Read & validate body =====
    data = request.get_json(silent=True) or {}
    dry_run = data.get("dry_run", True)
    if not isinstance(dry_run, bool):
        return error("dry_run must be boolean")

    try:
        limit_n = int(data.get("limit", 100))
        if limit_n < 1 or limit_n > 100:
            return error("limit must be between 1 and 100")
    except (ValueError, TypeError):
        return error("Invalid limit")

    # ===== 2. Idempotency key =====
    idem_key = request.headers.get("Idempotency-Key", "").strip()
    if not idem_key or len(idem_key) > 128:
        return error("Idempotency-Key header required (max 128 chars)", 400)

    # Request fingerprint: (endpoint, dry_run, limit)
    fingerprint_src = f"run-billing|dry_run={dry_run}|limit={limit_n}"
    fingerprint = hashlib.sha256(fingerprint_src.encode()).hexdigest()

    # Check existing idempotency record
    existing_idem = IdempotencyKey.query.filter_by(key=idem_key).first()
    if existing_idem:
        # Same key + same fingerprint = return cached response
        if existing_idem.request_fingerprint == fingerprint:
            if existing_idem.status == "completed" and existing_idem.response_json:
                cached = _json.loads(existing_idem.response_json)
                cached["_idempotent_replay"] = True
                return success(cached)
            if existing_idem.status == "pending":
                return error("This request is currently being processed", 409)
            # Failed — allow retry? No, protect. Return error.
            return error("Previous attempt with this key failed. Use a new key.", 409)
        # Same key + different fingerprint = conflict
        return error("Idempotency-Key reused with different parameters", 409)

    # Register new idempotency key (status=pending)
    idem = IdempotencyKey(
        key=idem_key,
        endpoint="/admin/run-billing",
        request_fingerprint=fingerprint,
        status="pending",
    )
    db.session.add(idem)

    # ===== 3. Create BillingRun record =====
    actor_user = getattr(request, "current_user", None)
    run = BillingRun(
        run_key=idem_key,
        dry_run=dry_run,
        status="running",
        actor_user_id=actor_user.id if actor_user else None,
        actor_email=actor_user.email if actor_user else "admin-api-key",
    )
    db.session.add(run)
    db.session.commit()

    # ===== 4. Acquire lock (prevents concurrent billing) =====
    # Postgres: use pg_try_advisory_lock (global across all app instances)
    # SQLite/dev: fall back to an in-process lock
    LOCK_KEY = 20261013190000  # arbitrary constant
    lock_acquired = False
    lock_is_advisory = False

    db_url = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    is_postgres = db_url.startswith("postgresql")

    if is_postgres:
        try:
            lock_result = db.session.execute(
                sql_text("SELECT pg_try_advisory_lock(:key)"),
                {"key": LOCK_KEY},
            ).scalar()
            if lock_result:
                lock_acquired = True
                lock_is_advisory = True
        except Exception as e:
            app.logger.warning(f"advisory lock failed: {e}")
    else:
        # SQLite / dev: use threading lock
        import threading
        if not hasattr(app, "_billing_lock"):
            app._billing_lock = threading.Lock()
        if app._billing_lock.acquire(blocking=False):
            lock_acquired = True

    if not lock_acquired:
        idem.status = "failed"
        run.status = "aborted"
        run.error_message = "another billing run is in progress"
        db.session.commit()
        return error("Another billing run is in progress. Try again later.", 409)

    try:
        # ===== 5. Process =====
        now = int(time.time())
        due = Subscription.query.filter(
            Subscription.status == "active",
            Subscription.next_charge_at <= now,
        ).limit(limit_n).all()

        processed = []
        failed = []
        total_amount = 0

        for sub in due:
            agent = db.session.get(Agent, sub.agent_id)
            if not agent:
                sub.status = "cancelled"
                db.session.flush()
                failed.append({"sub_id": sub.id, "reason": "agent_missing"})
                continue

            if agent.balance < sub.amount:
                failed.append({
                    "sub_id": sub.id,
                    "reason": "insufficient_balance",
                    "needed": sub.amount,
                    "have": agent.balance,
                })
                continue

            if dry_run:
                # Preview only — no changes
                processed.append({
                    "sub_id": sub.id,
                    "amount": sub.amount,
                    "agent_id": agent.id,
                    "preview": True,
                })
                total_amount += sub.amount
                continue

            # Real charge
            agent.balance -= sub.amount
            tx = Transaction(
                agent_id=agent.id,
                type="charge",
                amount=sub.amount,
                description=f"Subscription: {sub.name} (#{sub.id})",
            )
            sub.next_charge_at = now + sub.interval_seconds
            db.session.add(tx)
            db.session.flush()

            # Ledger entry (Task 61) — subscription billing
            ledger.record_entry(
                agent,
                entry_type="subscription",
                amount_signed=-sub.amount,
                description=f"Subscription: {sub.name} (#{sub.id})",
                external_ref=f"tx:{tx.id}",
            )

            audit.write_audit_secure(
                "subscription.billing",
                agent_id=agent.id,
                user_id=actor_user.id if actor_user else None,
                actor=actor_user.email if actor_user else "admin-api-key",
                ip=request.remote_addr,
                sub_id=sub.id,
                name=sub.name,
                amount=sub.amount,
                tx_id=tx.id,
                run_id=run.id,
            )
            processed.append({
                "sub_id": sub.id,
                "amount": sub.amount,
                "tx_id": tx.id,
            })
            total_amount += sub.amount

        # ===== 6. Finalize =====
        run.status = "completed"
        run.processed_count = len(processed)
        run.failed_count = len(failed)
        run.total_due = len(due)
        run.total_amount_cents = total_amount
        run.finished_at = int(time.time())
        run.details_json = _json.dumps({
            "processed": processed,
            "failed": failed,
        })

        response_data = {
            "dry_run": dry_run,
            "processed": processed,
            "failed": failed,
            "total": len(due),
            "total_amount_cents": total_amount,
            "run_id": run.id,
        }

        idem.status = "completed"
        idem.response_json = _json.dumps(response_data)
        idem.completed_at = int(time.time())

        # Log the run
        audit.write_audit_secure(
            "admin.billing.run",
            user_id=actor_user.id if actor_user else None,
            actor=actor_user.email if actor_user else "admin-api-key",
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")[:200],
            dry_run=dry_run,
            processed=len(processed),
            failed=len(failed),
            total_amount_cents=total_amount,
            run_id=run.id,
        )

        db.session.commit()

        # Release lock
        if lock_is_advisory:
            try:
                db.session.execute(sql_text("SELECT pg_advisory_unlock(:key)"), {"key": LOCK_KEY})
                db.session.commit()
            except Exception:
                db.session.rollback()
        else:
            try:
                app._billing_lock.release()
            except Exception:
                pass

        return success(response_data)

    except Exception as e:
        db.session.rollback()
        # Release lock on failure
        if lock_is_advisory:
            try:
                db.session.execute(sql_text("SELECT pg_advisory_unlock(:key)"), {"key": LOCK_KEY})
                db.session.commit()
            except Exception:
                db.session.rollback()
        else:
            try:
                app._billing_lock.release()
            except Exception:
                pass
        # Mark failed
        try:
            idem.status = "failed"
            run.status = "failed"
            run.error_message = str(e)[:500]
            run.finished_at = int(time.time())
            db.session.commit()
        except Exception:
            db.session.rollback()
        app.logger.error(f"run_billing failed: {e}", exc_info=True)
        return error("Billing run failed", 500)


# ===== Stripe Endpoints =====

@app.route("/agents/<agent_id>/stripe/checkout", methods=["POST"])
@limit(key_agent, "topup")
@require_api_key
def stripe_checkout(agent_id):
    """Create a Stripe Checkout session to top up the agent."""
    if not stripe_integration.is_configured():
        return error("Stripe not configured on server", 503)
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    data = request.get_json(silent=True) or {}
    amount_cents = data.get("amount_cents")
    if not isinstance(amount_cents, int):
        return error("amount_cents must be an integer (USD cents, min 100)")
    success_url = data.get("success_url") or "https://agentpay-pearl.vercel.app/?stripe=success"
    cancel_url = data.get("cancel_url") or "https://agentpay-pearl.vercel.app/?stripe=cancel"
    try:
        session = stripe_integration.create_checkout_session(
            agent, amount_cents, success_url, cancel_url
        )
    except (ValueError, RuntimeError) as e:
        return error(str(e), 400)
    except Exception as e:
        app.logger.error(f"Stripe error: {e}", exc_info=True)
        return error("Stripe error", 500)
    return success({"checkout": session})


@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    """Handle Stripe webhook events."""
    if not stripe_integration.is_configured():
        return error("Stripe not configured", 503)
    payload = request.get_data()
    sig = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe_integration.verify_webhook(payload, sig)
    except Exception as e:
        app.logger.warning(f"Stripe webhook signature failed: {e}")
        return error("Invalid signature", 400)
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        ok, msg, tx = stripe_integration.credit_agent_from_checkout(session)
        if ok:
            app.logger.info(f"Stripe webhook OK: {msg}")
        else:
            app.logger.warning(f"Stripe webhook failed: {msg}")
    return success({"received": True})


@app.route("/stripe/config")
def stripe_config():
    """Return Stripe publishable key (for frontend) or 'not configured'."""
    import os
    pk = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
    return success({
        "configured": stripe_integration.is_configured(),
        "publishable_key": pk if pk else None,
    })


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    print(f"AgentPay starting on port {port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
