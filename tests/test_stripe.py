"""AgentPay — Stripe webhook credit tests (task 5)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def _register_login(client, email="stripe_admin@test.com", password="strongpass123"):
    client.post("/auth/register", json={"email": email, "password": password})
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200


def _create_agent(client, name):
    r = client.post("/me/agents", json={"name": name})
    assert r.status_code == 201, r.get_json()
    return r.get_json()["agent"]["id"], r.get_json()["api_key"]


def _fake_session(session_id, agent_id, amount_cents, currency="usd",
                  payment_status="paid", metadata_override=None):
    """Build a fake Stripe session dict."""
    meta = {
        "agent_id": agent_id,
        "amount_cents": str(amount_cents),
    }
    if metadata_override:
        meta.update(metadata_override)
    return {
        "id": session_id,
        "payment_status": payment_status,
        "amount_total": amount_cents,
        "currency": currency,
        "metadata": meta,
    }


# ===== Success path =====

def test_stripe_credit_success(client, app_ctx):
    _register_login(client)
    agent_id, _ = _create_agent(client, "stripe-agent-1")

    from app import app
    from database import db
    import stripe_integration

    session = _fake_session("cs_test_001", agent_id, 2000)
    with app.app_context():
        ok, msg, tx = stripe_integration.credit_agent_from_checkout(session)
        assert ok is True, msg
        assert msg == "Credited"
        assert tx is not None

        # Verify balance
        from models import Agent
        agent = db.session.get(Agent, agent_id)
        assert agent.balance == 2000


def test_stripe_credit_creates_topup_record(client, app_ctx):
    _register_login(client)
    agent_id, _ = _create_agent(client, "stripe-agent-2")

    from app import app
    from database import db
    import stripe_integration

    session = _fake_session("cs_test_002", agent_id, 1500)
    with app.app_context():
        ok, msg, _ = stripe_integration.credit_agent_from_checkout(session)
        assert ok is True

        from models import TopupRecord
        rec = db.session.query(TopupRecord).filter_by(stripe_session_id="cs_test_002").first()
        assert rec is not None
        assert rec.amount_cents == 1500
        assert rec.source == "stripe"
        assert rec.status == "completed"


# ===== Payment status =====

def test_stripe_requires_paid_status(client, app_ctx):
    """Only 'paid' sessions should credit."""
    _register_login(client)
    agent_id, _ = _create_agent(client, "stripe-agent-3")

    from app import app
    import stripe_integration

    session = _fake_session("cs_test_003", agent_id, 1000, payment_status="unpaid")
    with app.app_context():
        ok, msg, tx = stripe_integration.credit_agent_from_checkout(session)
        assert ok is False
        assert "paid" in msg.lower()
        assert tx is None


def test_stripe_rejects_pending_status(client, app_ctx):
    _register_login(client)
    agent_id, _ = _create_agent(client, "stripe-agent-4")

    from app import app
    import stripe_integration

    session = _fake_session("cs_test_004", agent_id, 1000, payment_status="pending")
    with app.app_context():
        ok, msg, _ = stripe_integration.credit_agent_from_checkout(session)
        assert ok is False


# ===== Amount cross-check =====

def test_stripe_rejects_amount_mismatch(client, app_ctx):
    """Metadata amount must match session.amount_total."""
    _register_login(client)
    agent_id, _ = _create_agent(client, "stripe-agent-5")

    from app import app
    import stripe_integration

    # Session says $10, metadata says $100
    session = _fake_session("cs_test_005", agent_id, 1000,
                            metadata_override={"amount_cents": "10000"})
    with app.app_context():
        ok, msg, _ = stripe_integration.credit_agent_from_checkout(session)
        assert ok is False
        assert "match" in msg.lower()


# ===== Currency check =====

def test_stripe_rejects_wrong_currency(client, app_ctx):
    _register_login(client)
    agent_id, _ = _create_agent(client, "stripe-agent-6")

    from app import app
    import stripe_integration

    session = _fake_session("cs_test_006", agent_id, 1000, currency="eur")
    with app.app_context():
        ok, msg, _ = stripe_integration.credit_agent_from_checkout(session)
        assert ok is False
        assert "currency" in msg.lower()


# ===== Missing metadata =====

def test_stripe_rejects_missing_metadata(client, app_ctx):
    _register_login(client)
    agent_id, _ = _create_agent(client, "stripe-agent-7")

    from app import app
    import stripe_integration

    session = {
        "id": "cs_test_007",
        "payment_status": "paid",
        "amount_total": 1000,
        "currency": "usd",
        "metadata": {},
    }
    with app.app_context():
        ok, msg, _ = stripe_integration.credit_agent_from_checkout(session)
        assert ok is False
        assert "metadata" in msg.lower()


# ===== Idempotency =====

def test_stripe_idempotent_same_session(client, app_ctx):
    """Same session ID sent twice should not double-credit."""
    _register_login(client)
    agent_id, _ = _create_agent(client, "stripe-agent-8")

    from app import app
    from database import db
    import stripe_integration

    session = _fake_session("cs_test_008", agent_id, 3000)
    with app.app_context():
        # First
        ok1, _, _ = stripe_integration.credit_agent_from_checkout(session)
        assert ok1 is True

        # Second — should be idempotent replay
        ok2, msg2, tx2 = stripe_integration.credit_agent_from_checkout(session)
        # Either "replay" success OR "already credited"
        assert ok2 is True
        assert "already" in msg2.lower() or tx2 is None

        # Balance must NOT be doubled
        from models import Agent
        agent = db.session.get(Agent, agent_id)
        assert agent.balance == 3000


# ===== Daily limit =====

def test_stripe_respects_daily_limit(client, app_ctx):
    """Multiple Stripe credits in same day cannot exceed $500."""
    _register_login(client)
    agent_id, _ = _create_agent(client, "stripe-agent-9")

    from app import app
    import stripe_integration

    with app.app_context():
        # First: $500 (at limit)
        s1 = _fake_session("cs_test_009a", agent_id, 50_000)
        ok1, _, _ = stripe_integration.credit_agent_from_checkout(s1)
        assert ok1 is True

        # Second: $1 (would exceed)
        s2 = _fake_session("cs_test_009b", agent_id, 100)
        ok2, msg2, _ = stripe_integration.credit_agent_from_checkout(s2)
        assert ok2 is False
        assert "daily" in msg2.lower() or "limit" in msg2.lower()


# ===== Audit =====

def test_stripe_creates_audit_entry(client, app_ctx):
    _register_login(client)
    agent_id, _ = _create_agent(client, "stripe-agent-10")

    from app import app
    from database import db
    import stripe_integration

    session = _fake_session("cs_test_010", agent_id, 500)
    with app.app_context():
        stripe_integration.credit_agent_from_checkout(session)

        from models import AuditLog
        entry = (
            db.session.query(AuditLog)
            .filter_by(action="topup", agent_id=agent_id)
            .first()
        )
        assert entry is not None
        assert entry.record_hash is not None


# ===== Invalid amount =====

def test_stripe_rejects_invalid_amount_total(client, app_ctx):
    _register_login(client)
    agent_id, _ = _create_agent(client, "stripe-agent-11")

    from app import app
    import stripe_integration

    session = _fake_session("cs_test_011", agent_id, 1000)
    session["amount_total"] = -100  # negative
    with app.app_context():
        ok, msg, _ = stripe_integration.credit_agent_from_checkout(session)
        assert ok is False
