"""AgentPay — Database models."""
import secrets
import time
from database import db


CURRENCY_SYMBOLS = {"USD": "$", "EUR": "€", "GBP": "£"}
SUPPORTED_CURRENCIES = list(CURRENCY_SYMBOLS.keys())


def format_balance(amount_cents: int, currency: str = "USD") -> str:
    """Format balance with currency symbol."""
    symbol = CURRENCY_SYMBOLS.get(currency, currency + " ")
    return f"{symbol}{amount_cents / 100:.2f}"


def generate_api_key():
    """Generate a secure API key."""
    return "ap_" + secrets.token_hex(24)



# ===== Organizations (nullable, for future B2B) =====

class Organization(db.Model):
    """An organization that groups users (nullable for individual users)."""
    __tablename__ = "organizations"

    id = db.Column(db.String(32), primary_key=True, default=lambda: secrets.token_hex(8))
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.Integer, default=lambda: int(time.time()))
    updated_at = db.Column(db.Integer, default=lambda: int(time.time()), onupdate=lambda: int(time.time()))

    users = db.relationship("User", backref="organization", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at,
        }


# ===== Users (human accounts) =====

USER_ROLES = ("admin", "developer", "viewer")


class User(db.Model):
    """A human user account."""
    __tablename__ = "users"

    id = db.Column(db.String(32), primary_key=True, default=lambda: secrets.token_hex(8))
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="developer")  # admin/developer/viewer
    organization_id = db.Column(db.String(32), db.ForeignKey("organizations.id"), nullable=True)

    is_active = db.Column(db.Boolean, default=True, nullable=False)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)

    # 2FA (TOTP)
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)
    recovery_codes_hash = db.Column(db.Text, nullable=True)  # JSON array of hashes

    # Anti-bruteforce
    failed_logins = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.Integer, nullable=True)

    created_at = db.Column(db.Integer, default=lambda: int(time.time()))
    updated_at = db.Column(db.Integer, default=lambda: int(time.time()), onupdate=lambda: int(time.time()))
    last_login_at = db.Column(db.Integer, nullable=True)

    agents = db.relationship("Agent", backref="owner", lazy=True, foreign_keys="Agent.owner_id")
    sessions = db.relationship("Session", backref="user", lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        """Safe public representation (never includes password_hash or totp_secret)."""
        return {
            "id": self.id,
            "email": self.email,
            "role": self.role,
            "organization_id": self.organization_id,
            "is_active": self.is_active,
            "email_verified": self.email_verified,
            "totp_enabled": self.totp_enabled,
            "created_at": self.created_at,
            "last_login_at": self.last_login_at,
        }


# ===== Sessions (server-side auth for dashboard) =====

class Session(db.Model):
    """A server-side session for a logged-in user."""
    __tablename__ = "sessions"

    id = db.Column(db.String(64), primary_key=True, default=lambda: secrets.token_urlsafe(32))
    user_id = db.Column(db.String(32), db.ForeignKey("users.id"), nullable=False, index=True)
    created_at = db.Column(db.Integer, default=lambda: int(time.time()))
    expires_at = db.Column(db.Integer, nullable=False, index=True)
    ip = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    revoked_at = db.Column(db.Integer, nullable=True)

    def is_valid(self):
        if self.revoked_at is not None:
            return False
        return self.expires_at > int(time.time())

    def to_dict(self):
        return {
            "id": self.id[:8] + "...",  # never expose full token
            "user_id": self.user_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "ip": self.ip,
            "user_agent": self.user_agent,
            "revoked_at": self.revoked_at,
            "is_valid": self.is_valid(),
        }


class Agent(db.Model):
    """An AI agent that can make payments."""
    __tablename__ = "agents"

    id = db.Column(db.String(32), primary_key=True, default=lambda: secrets.token_hex(8))
    name = db.Column(db.String(100), nullable=False)
    api_key = db.Column(db.String(64), unique=True, nullable=False, default=generate_api_key)
    balance = db.Column(db.Integer, default=0)  # in smallest unit
    currency = db.Column(db.String(3), default="USD")  # USD, EUR, GBP
    webhook_url = db.Column(db.String(500), nullable=True)
    owner_id = db.Column(db.String(32), db.ForeignKey("users.id"), nullable=True, index=True)
    organization_id = db.Column(db.String(32), db.ForeignKey("organizations.id"), nullable=True, index=True)
    created_at = db.Column(db.Integer, default=lambda: int(time.time()))
    updated_at = db.Column(db.Integer, default=lambda: int(time.time()), onupdate=lambda: int(time.time()))

    transactions = db.relationship("Transaction", backref="agent", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "balance": self.balance,
            "currency": self.currency,
            "balance_display": format_balance(self.balance, self.currency),
            "webhook_url": _safe_decrypt_webhook(self.webhook_url),
            "created_at": self.created_at,
        }


class Transaction(db.Model):
    """A charge or topup for an agent."""
    __tablename__ = "transactions"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.String(32), db.ForeignKey("agents.id"), nullable=False)
    type = db.Column(db.String(30), nullable=False, index=True)  # topup/charge/refund/admin_adjust/...
    amount = db.Column(db.Integer, nullable=False)  # in cents
    description = db.Column(db.String(200), default="")
    status = db.Column(db.String(20), default="completed")  # completed, failed
    created_at = db.Column(db.Integer, default=lambda: int(time.time()))

    def to_dict(self):
        cur = self.agent.currency if self.agent else "USD"
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "type": self.type,
            "amount": self.amount,
            "amount_display": format_balance(abs(self.amount), cur),
            "description": self.description,
            "status": self.status,
            "created_at": self.created_at,
        }

class Subscription(db.Model):
    """A recurring payment plan for an agent."""
    __tablename__ = "subscriptions"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.String(32), db.ForeignKey("agents.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Integer, nullable=False)  # per charge, in smallest unit
    interval_seconds = db.Column(db.Integer, nullable=False)  # e.g. 2592000 (30 days)
    next_charge_at = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default="active")  # active, cancelled
    created_at = db.Column(db.Integer, default=lambda: int(time.time()))
    cancelled_at = db.Column(db.Integer, nullable=True)

    def to_dict(self):
        agent = db.session.get(Agent, self.agent_id)
        cur = agent.currency if agent else "USD"
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "name": self.name,
            "amount": self.amount,
            "amount_display": format_balance(self.amount, cur),
            "interval_seconds": self.interval_seconds,
            "interval_days": self.interval_seconds // 86400,
            "next_charge_at": self.next_charge_at,
            "status": self.status,
            "created_at": self.created_at,
            "cancelled_at": self.cancelled_at,
        }

class AuditLog(db.Model):
    """Audit log: track all sensitive operations."""
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.Integer, default=lambda: int(time.time()), index=True)
    action = db.Column(db.String(80), nullable=False, index=True)
    agent_id = db.Column(db.String(32), nullable=True, index=True)
    user_id = db.Column(db.String(32), nullable=True, index=True)  # actor user (nullable for agent-driven ops)
    actor = db.Column(db.String(100), nullable=True)  # API key prefix, "admin", or user email
    ip = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(200), nullable=True)
    metadata_json = db.Column(db.Text, nullable=True)  # JSON blob
    status = db.Column(db.String(20), default="ok")  # ok, error
    prev_hash = db.Column(db.String(64), nullable=True, index=True)  # SHA-256 of previous record
    record_hash = db.Column(db.String(64), nullable=True, index=True)  # SHA-256 of this record

    def to_dict(self):
        import json
        meta = {}
        if self.metadata_json:
            try:
                meta = json.loads(self.metadata_json)
            except Exception:
                meta = {"raw": self.metadata_json}
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "action": self.action,
            "agent_id": self.agent_id,
            "user_id": self.user_id,
            "actor": self.actor,
            "ip": self.ip,
            "user_agent": self.user_agent,
            "status": self.status,
            "metadata": meta,
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
        }


# ===== Idempotency & Billing =====

class IdempotencyKey(db.Model):
    """Stores idempotency keys and their responses.

    Used by /admin/run-billing to prevent duplicate charges on retry.
    """
    __tablename__ = "idempotency_keys"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    key = db.Column(db.String(128), unique=True, nullable=False, index=True)
    endpoint = db.Column(db.String(100), nullable=False, index=True)
    request_fingerprint = db.Column(db.String(64), nullable=False)  # SHA-256 of request params
    response_json = db.Column(db.Text, nullable=True)  # cached response body
    status = db.Column(db.String(20), nullable=False, default="pending")  # pending, completed, failed
    created_at = db.Column(db.Integer, default=lambda: int(time.time()), index=True)
    completed_at = db.Column(db.Integer, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "key": self.key[:12] + "...",
            "endpoint": self.endpoint,
            "status": self.status,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


class BillingRun(db.Model):
    """Records each run of the billing engine (dry-run or live)."""
    __tablename__ = "billing_runs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    run_key = db.Column(db.String(128), unique=True, nullable=False, index=True)  # idempotency key
    dry_run = db.Column(db.Boolean, nullable=False, default=True)
    status = db.Column(db.String(20), nullable=False, default="running")  # running, completed, failed, aborted
    processed_count = db.Column(db.Integer, default=0)
    failed_count = db.Column(db.Integer, default=0)
    total_due = db.Column(db.Integer, default=0)  # number of due subscriptions
    total_amount_cents = db.Column(db.Integer, default=0)
    actor_user_id = db.Column(db.String(32), nullable=True)
    actor_email = db.Column(db.String(255), nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    details_json = db.Column(db.Text, nullable=True)  # per-subscription results
    started_at = db.Column(db.Integer, default=lambda: int(time.time()), index=True)
    finished_at = db.Column(db.Integer, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "run_key": self.run_key[:12] + "...",
            "dry_run": self.dry_run,
            "status": self.status,
            "processed": self.processed_count,
            "failed": self.failed_count,
            "total_due": self.total_due,
            "total_amount_cents": self.total_amount_cents,
            "actor_email": self.actor_email,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }

# ===== Topup Tracking (Task 5) =====

class TopupRecord(db.Model):
    """Records every topup attempt (Stripe or admin).

    Central record for auditability and daily-limit enforcement.
    """
    __tablename__ = "topup_records"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.String(32), db.ForeignKey("agents.id"), nullable=False, index=True)
    amount_cents = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(3), nullable=False, default="USD")

    # Source: "stripe" | "admin" | "migration"
    source = db.Column(db.String(20), nullable=False, index=True)

    # Status: "completed" | "failed" | "pending"
    status = db.Column(db.String(20), nullable=False, default="completed", index=True)

    # References
    idempotency_key = db.Column(db.String(128), nullable=True, index=True)
    stripe_session_id = db.Column(db.String(200), nullable=True, unique=True, index=True)
    transaction_id = db.Column(db.Integer, db.ForeignKey("transactions.id"), nullable=True)

    # Admin context (when source="admin")
    actor_user_id = db.Column(db.String(32), nullable=True)
    actor_email = db.Column(db.String(255), nullable=True)
    reason = db.Column(db.String(500), nullable=True)

    # Timestamps
    created_at = db.Column(db.Integer, default=lambda: int(time.time()), index=True)
    completed_at = db.Column(db.Integer, nullable=True)

    agent = db.relationship("Agent", backref="topup_records", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "amount_cents": self.amount_cents,
            "currency": self.currency,
            "source": self.source,
            "status": self.status,
            "reason": self.reason,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


class DailyTopupCounter(db.Model):
    """Per-agent per-day aggregate of successful topups.

    Used to enforce the daily topup limit atomically (row lock during UPDATE).
    """
    __tablename__ = "daily_topup_counters"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.String(32), db.ForeignKey("agents.id"), nullable=False, index=True)
    day = db.Column(db.String(10), nullable=False, index=True)  # YYYY-MM-DD (UTC)
    total_cents = db.Column(db.Integer, nullable=False, default=0)

    __table_args__ = (
        db.UniqueConstraint("agent_id", "day", name="uq_daily_topup_agent_day"),
    )

    def to_dict(self):
        return {
            "agent_id": self.agent_id,
            "day": self.day,
            "total_cents": self.total_cents,
        }

def _safe_decrypt_webhook(value):
    """Decrypt webhook_url if encrypted; pass through otherwise.

    Handles legacy un-encrypted values gracefully.
    """
    if value is None:
        return None
    try:
        import crypto
        return crypto.decrypt_webhook_url(value)
    except Exception:
        # If decryption fails, return None (don't leak ciphertext)
        return None

# Sensitive fields that must NEVER be stored in audit metadata
_AUDIT_SENSITIVE_KEYS = {
    "password", "password_hash", "new_password", "current_password",
    "totp_secret", "recovery_codes", "recovery_codes_hash",
    "api_key", "session_id", "token", "csrf_token",
    "secret", "stripe_secret", "stripe_webhook_secret",
    "authorization", "cookie", "set-cookie",
}


def _is_audit_sensitive(key):
    if not isinstance(key, str):
        return False
    k = key.lower().strip()
    if k in _AUDIT_SENSITIVE_KEYS:
        return True
    for marker in ("password", "secret", "token", "api_key", "csrf"):
        if marker in k:
            return True
    return False


def sanitize_metadata(obj, _depth=0):
    """Recursively sanitize metadata before audit storage."""
    if _depth > 5:
        return "[truncated]"
    if isinstance(obj, dict):
        return {
            k: ("[REDACTED]" if _is_audit_sensitive(k) else sanitize_metadata(v, _depth + 1))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [sanitize_metadata(x, _depth + 1) for x in obj[:50]]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        if isinstance(obj, str) and len(obj) > 500:
            return obj[:500] + "...[truncated]"
        return obj
    return str(obj)[:200]


def write_audit(action, agent_id=None, user_id=None, actor=None, ip=None, user_agent=None, status="ok", **metadata):
    """LEGACY: write an audit log entry without hash chain.

    Deprecated — use audit.write_audit_secure() for hash-chained entries.
    Kept for backward compatibility during migration.
    """
    import json
    clean = sanitize_metadata(metadata) if metadata else None
    entry = AuditLog(
        action=action,
        agent_id=agent_id,
        user_id=user_id,
        actor=actor,
        ip=ip,
        user_agent=(user_agent or "")[:200] or None,
        status=status,
        metadata_json=json.dumps(clean, sort_keys=True) if clean else None,
    )
    db.session.add(entry)
    # Note: does NOT commit — caller commits with their transaction
    return entry


# ═══════════════════════════════════════════════════════
# Password Reset & Email Verification Tokens (Tasks 17+18)
# ═══════════════════════════════════════════════════════

class PasswordResetToken(db.Model):
    """Single-use token for password reset.

    Security:
    - Token is hashed (SHA-256) before storage — raw token never persisted.
    - Expires in 1 hour.
    - Marked used_at after consumption (prevents replay).
    - user_id + ip + user_agent logged for audit.
    """
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.String(32), primary_key=True, default=lambda: secrets.token_hex(8))
    user_id = db.Column(db.String(32), db.ForeignKey("users.id"), nullable=False, index=True)
    token_hash = db.Column(db.String(128), nullable=False, unique=True, index=True)
    created_at = db.Column(db.Integer, default=lambda: int(time.time()), nullable=False)
    expires_at = db.Column(db.Integer, nullable=False, index=True)
    used_at = db.Column(db.Integer, nullable=True)
    ip = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)

    def is_valid(self) -> bool:
        if self.used_at is not None:
            return False
        return self.expires_at > int(time.time())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "used_at": self.used_at,
            "is_valid": self.is_valid(),
        }


class EmailVerificationToken(db.Model):
    """Single-use token for email verification.

    Security:
    - Token is hashed (SHA-256) before storage.
    - Expires in 24 hours.
    - Marked used_at after consumption.
    """
    __tablename__ = "email_verification_tokens"

    id = db.Column(db.String(32), primary_key=True, default=lambda: secrets.token_hex(8))
    user_id = db.Column(db.String(32), db.ForeignKey("users.id"), nullable=False, index=True)
    email = db.Column(db.String(255), nullable=False)   # email being verified
    token_hash = db.Column(db.String(128), nullable=False, unique=True, index=True)
    created_at = db.Column(db.Integer, default=lambda: int(time.time()), nullable=False)
    expires_at = db.Column(db.Integer, nullable=False, index=True)
    used_at = db.Column(db.Integer, nullable=True)
    ip = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)

    def is_valid(self) -> bool:
        if self.used_at is not None:
            return False
        return self.expires_at > int(time.time())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "email": self.email,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "used_at": self.used_at,
            "is_valid": self.is_valid(),
        }

# ═══════════════════════════════════════════════════════
# Ledger (re-exported from ledger.py for migrations/discovery)
# ═══════════════════════════════════════════════════════
from ledger import LedgerEntry  # noqa: F401, E402
