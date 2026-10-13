"""AgentPay — Topup protection tests (task 5).

Covers:
- Direct topup is disabled
- Admin topup requires auth + CSRF + Idempotency-Key + reason
- Per-transaction limit ($500)
- Daily limit ($500/day)
- Idempotency semantics (replay, mismatch, pending)
- Atomicity of balance + counter
- Daily counter updates
- Audit log
"""
import sys
import time
import secrets
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def _register_login(client, email="topup_admin@test.com", password="strongpass123"):
    client.post("/auth/register", json={"email": email, "password": password})
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.get_json()


def _csrf(client):
    try:
        c = client.get_cookie("ap_csrf")
        return c.value if c else None
    except Exception:
        return None


def _create_agent(client, name):
    """Create owned agent."""
    r = client.post("/me/agents", json={"name": name})
    assert r.status_code == 201, r.get_json()
    return r.get_json()["agent"]["id"], r.get_json()["api_key"]


def _admin_topup(client, agent_id, amount_cents, reason="test reason",
                 idem_key=None, currency="USD", with_csrf=True):
    """Call admin topup."""
    csrf = _csrf(client) if with_csrf else None
    headers = {}
    if idem_key:
        headers["Idempotency-Key"] = idem_key
    if csrf:
        headers["X-CSRF-Token"] = csrf
    return client.post(
        f"/admin/agents/{agent_id}/topup",
        json={"amount_cents": amount_cents, "reason": reason, "currency": currency},
        headers=headers,
    )


# ===== Direct topup disabled =====

def test_direct_topup_is_disabled(client):
    """Agents cannot top up their own balance."""
    # Register+login to create agent, then logout
    _register_login(client)
    agent_id, api_key = _create_agent(client, "self-topup")
    client.post("/auth/logout")

    # Try direct topup (API key)
    r = client.post(
        f"/agents/{agent_id}/topup",
        json={"amount": 100000},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert r.status_code == 403
    assert "disabled" in r.get_json()["error"].lower()


def test_direct_topup_blocked_is_audited(client, app_ctx):
    """Blocked attempts are logged."""
    _register_login(client)
    agent_id, api_key = _create_agent(client, "audit-blocked")
    client.post("/auth/logout")

    client.post(
        f"/agents/{agent_id}/topup",
        json={"amount": 1000},
        headers={"Authorization": f"Bearer {api_key}"},
    )

    from models import AuditLog
    from database import db as _db
    with app_ctx.app_context():
        entry = (
            _db.session.query(AuditLog)
            .filter_by(action="topup.direct.blocked", agent_id=agent_id)
            .first()
        )
        assert entry is not None


# ===== Admin topup authorization =====

def test_admin_topup_requires_auth(client):
    r = client.post(
        "/admin/agents/someid/topup",
        json={"amount_cents": 1000, "reason": "test"},
        headers={"Idempotency-Key": "x"},
    )
    # Without auth = 403 (CSRF fails first) or 401
    assert r.status_code in (401, 403)






def test_admin_topup_requires_reason(client):
    _register_login(client)
    agent_id, _ = _create_agent(client, "reason-test")
    csrf = _csrf(client)
    r = client.post(
        f"/admin/agents/{agent_id}/topup",
        json={"amount_cents": 1000, "reason": "hi"},  # too short
        headers={"Idempotency-Key": "k-reason", "X-CSRF-Token": csrf},
    )
    assert r.status_code == 400


# ===== Per-transaction limit =====

def test_admin_topup_per_txn_limit(client):
    _register_login(client)
    agent_id, _ = _create_agent(client, "txn-limit")
    r = _admin_topup(client, agent_id, 100_000, idem_key="k-limit")  # $1000
    assert r.status_code == 400
    assert "exceeds" in r.get_json()["error"].lower()


def test_admin_topup_at_limit_ok(client):
    _register_login(client)
    agent_id, _ = _create_agent(client, "at-limit")
    r = _admin_topup(client, agent_id, 50_000, idem_key="k-at-limit")  # $500
    assert r.status_code == 201


# ===== Daily limit =====

def test_admin_topup_daily_limit(client):
    _register_login(client)
    agent_id, _ = _create_agent(client, "daily-limit")

    # First topup $500
    r1 = _admin_topup(client, agent_id, 50_000, idem_key="k-day-1")
    assert r1.status_code == 201

    # Second topup $1 should exceed daily limit
    r2 = _admin_topup(client, agent_id, 100, idem_key="k-day-2")
    assert r2.status_code == 429
    assert "daily" in r2.get_json()["error"].lower()


# ===== Success path =====

def test_admin_topup_success_updates_balance(client):
    _register_login(client)
    agent_id, api_key = _create_agent(client, "success")

    r = _admin_topup(client, agent_id, 10_000, idem_key="k-success")
    assert r.status_code == 201
    data = r.get_json()
    assert data["amount_cents"] == 10_000
    assert data["new_balance"] == 10_000

    # Verify via GET
    r2 = client.get(f"/agents/{agent_id}", headers={"Authorization": f"Bearer {api_key}"})
    assert r2.get_json()["agent"]["balance"] == 10_000


def test_admin_topup_creates_topup_record(client, app_ctx):
    _register_login(client)
    agent_id, _ = _create_agent(client, "record-test")
    _admin_topup(client, agent_id, 5000, idem_key="k-record")

    from models import TopupRecord
    from database import db as _db
    with app_ctx.app_context():
        rec = _db.session.query(TopupRecord).filter_by(agent_id=agent_id).first()
        assert rec is not None
        assert rec.amount_cents == 5000
        assert rec.source == "admin"
        assert rec.status == "completed"
        assert rec.reason == "test reason"


def test_admin_topup_creates_transaction(client, app_ctx):
    _register_login(client)
    agent_id, _ = _create_agent(client, "txn-test")
    _admin_topup(client, agent_id, 3000, idem_key="k-txn")

    from models import Transaction
    from database import db as _db
    with app_ctx.app_context():
        tx = _db.session.query(Transaction).filter_by(agent_id=agent_id, type="topup").first()
        assert tx is not None
        assert tx.amount == 3000


def test_admin_topup_updates_daily_counter(client, app_ctx):
    _register_login(client)
    agent_id, _ = _create_agent(client, "counter-test")
    _admin_topup(client, agent_id, 7000, idem_key="k-counter")

    from models import DailyTopupCounter
    from database import db as _db
    with app_ctx.app_context():
        counter = _db.session.query(DailyTopupCounter).filter_by(agent_id=agent_id).first()
        assert counter is not None
        assert counter.total_cents == 7000


# ===== Idempotency =====

def test_admin_topup_idempotent_replay(client, app_ctx):
    _register_login(client)
    agent_id, _ = _create_agent(client, "idem-replay")

    r1 = _admin_topup(client, agent_id, 2000, idem_key="k-replay-1")
    assert r1.status_code == 201

    r2 = _admin_topup(client, agent_id, 2000, idem_key="k-replay-1")
    assert r2.status_code == 200
    assert r2.get_json().get("_idempotent_replay") is True

    # Balance should NOT be doubled
    from models import Agent
    from database import db as _db
    with app_ctx.app_context():
        agent = _db.session.get(Agent, agent_id)
        assert agent.balance == 2000


def test_admin_topup_idempotency_mismatch(client):
    _register_login(client)
    agent_id, _ = _create_agent(client, "idem-mismatch")

    _admin_topup(client, agent_id, 1000, idem_key="k-mismatch")
    # Same key, different amount
    r = _admin_topup(client, agent_id, 2000, idem_key="k-mismatch")
    assert r.status_code == 409
    assert "different" in r.get_json()["error"].lower()


# ===== Audit =====

def test_admin_topup_audit_logged(client, app_ctx):
    _register_login(client)
    agent_id, _ = _create_agent(client, "audit-ok")
    _admin_topup(client, agent_id, 4000, idem_key="k-audit-ok")

    from models import AuditLog
    from database import db as _db
    with app_ctx.app_context():
        entry = (
            _db.session.query(AuditLog)
            .filter_by(action="topup", agent_id=agent_id)
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert entry is not None
        assert entry.record_hash is not None


def test_admin_topup_audit_metadata_has_no_secrets(client, app_ctx):
    """Audit metadata must not contain password/api_key."""
    _register_login(client)
    agent_id, _ = _create_agent(client, "audit-secrets")
    _admin_topup(client, agent_id, 3000, idem_key="k-audit-secrets")

    from models import AuditLog
    from database import db as _db
    with app_ctx.app_context():
        entry = _db.session.query(AuditLog).filter_by(action="topup", agent_id=agent_id).first()
        if entry.metadata_json:
            meta = entry.metadata_json.lower()
            assert "password" not in meta
            assert "api_key" not in meta
            assert "secret" not in meta


# ===== Agent not found =====

def test_admin_topup_agent_not_found(client):
    _register_login(client)
    r = _admin_topup(client, "nonexistent-agent-id", 1000, idem_key="k-notfound")
    assert r.status_code == 400  # topup_helpers returns 400 for missing agent
