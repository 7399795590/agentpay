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
            "webhook_url": self.webhook_url,
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
        }


def write_audit(action, agent_id=None, user_id=None, actor=None, ip=None, user_agent=None, status="ok", **metadata):
    """Helper to write an audit log entry."""
    import json
    entry = AuditLog(
        action=action,
        agent_id=agent_id,
        user_id=user_id,
        actor=actor,
        ip=ip,
        user_agent=user_agent,
        status=status,
        metadata_json=json.dumps(metadata) if metadata else None,
    )
    db.session.add(entry)
    # Note: does NOT commit — caller commits with their transaction
    return entry

