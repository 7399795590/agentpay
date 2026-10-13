"""AgentPay — Billing engine tests (task 4)."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def _register_login(client, email="billing_admin@test.com", password="strongpass123"):
    client.post("/auth/register", json={"email": email, "password": password})
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.get_json()


def _csrf(client):
    """Extract CSRF token from Flask test client cookie jar."""
    try:
        cookie = client.get_cookie("ap_csrf")
        if cookie is not None:
            return cookie.value
    except Exception:
        pass
    return None


def _create_agent_with_balance(client, name, balance=10000):
    """Create an owned agent and topup its balance."""
    r = client.post("/me/agents", json={"name": name})
    assert r.status_code == 201, r.get_json()
    agent_id = r.get_json()["agent"]["id"]
    api_key = r.get_json()["api_key"]
    r2 = client.post(
        f"/agents/{agent_id}/topup",
        json={"amount": balance},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert r2.status_code == 200, r2.get_json()
    return agent_id, api_key


def _create_due_subscription(client, agent_id, api_key, app_ctx, name, amount):
    """Create a subscription and force next_charge_at into the past."""
    from database import db
    from models import Subscription
    r = client.post(
        f"/agents/{agent_id}/subscriptions/create",
        json={"name": name, "amount": amount, "interval": "monthly"},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert r.status_code == 201, r.get_json()
    sub_id = r.get_json()["subscription"]["id"]
    with app_ctx.app_context():
        sub = db.session.get(Subscription, sub_id)
        sub.next_charge_at = int(time.time()) - 60
        db.session.commit()
    return sub_id


def _run_billing(client, idem_key, dry_run=False, limit=100):
    """Call /admin/run-billing with proper CSRF."""
    csrf = _csrf(client)
    assert csrf, "No CSRF token in client"
    return client.post(
        "/admin/run-billing",
        json={"dry_run": dry_run, "limit": limit},
        headers={"Idempotency-Key": idem_key, "X-CSRF-Token": csrf},
    )


# ===== Authorization =====

def test_run_billing_requires_auth(client):
    r = client.post(
        "/admin/run-billing",
        json={"dry_run": True, "limit": 100},
        headers={"Idempotency-Key": "k-no-auth"},
    )
    assert r.status_code == 401


def test_run_billing_requires_idempotency_key(client):
    _register_login(client)
    csrf = _csrf(client)
    r = client.post(
        "/admin/run-billing",
        json={"dry_run": True, "limit": 100},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 400
    assert "idempotency" in r.get_json()["error"].lower()


# ===== Dry-run =====

def test_run_billing_dry_run_default(client):
    _register_login(client)
    csrf = _csrf(client)
    r = client.post(
        "/admin/run-billing",
        json={"limit": 100},
        headers={"Idempotency-Key": "k-default", "X-CSRF-Token": csrf},
    )
    assert r.status_code == 200
    assert r.get_json()["dry_run"] is True


def test_run_billing_dry_run_no_changes(client, app_ctx):
    _register_login(client)
    agent_id, api_key = _create_agent_with_balance(client, "dry-agent", 5000)
    sub_id = _create_due_subscription(client, agent_id, api_key, app_ctx, "dry-sub", 1000)

    r = _run_billing(client, "k-dry-1", dry_run=True)
    assert r.status_code == 200
    data = r.get_json()
    assert data["dry_run"] is True
    assert len(data["processed"]) >= 1

    # Balance unchanged
    r = client.get(f"/agents/{agent_id}", headers={"Authorization": f"Bearer {api_key}"})
    assert r.get_json()["agent"]["balance"] == 5000

    # next_charge_at unchanged
    from models import Subscription
    with app_ctx.app_context():
        sub = app_ctx.extensions["sqlalchemy"].session.get(Subscription, sub_id) if hasattr(app_ctx, "extensions") else None
    # Simpler: query via fresh context
    from database import db as _db
    with app_ctx.app_context():
        sub = _db.session.get(Subscription, sub_id)
        assert sub.next_charge_at < int(time.time())


# ===== Live =====

def test_run_billing_live_charges(client, app_ctx):
    _register_login(client)
    agent_id, api_key = _create_agent_with_balance(client, "live-agent", 5000)
    sub_id = _create_due_subscription(client, agent_id, api_key, app_ctx, "live-sub", 1000)

    r = _run_billing(client, "k-live-1", dry_run=False)
    assert r.status_code == 200
    data = r.get_json()
    assert data["dry_run"] is False
    assert len(data["processed"]) >= 1

    # Balance reduced
    r = client.get(f"/agents/{agent_id}", headers={"Authorization": f"Bearer {api_key}"})
    assert r.get_json()["agent"]["balance"] == 4000

    # next_charge_at moved forward
    from models import Subscription
    from database import db as _db
    with app_ctx.app_context():
        sub = _db.session.get(Subscription, sub_id)
        assert sub.next_charge_at > int(time.time())


# ===== Idempotency =====

def test_run_billing_idempotency_same_key_same_response(client):
    _register_login(client)
    agent_id, api_key = _create_agent_with_balance(client, "idem-agent", 5000)
    r1 = _run_billing(client, "k-idem-A", dry_run=False)
    assert r1.status_code == 200

    r2 = _run_billing(client, "k-idem-A", dry_run=False)
    assert r2.status_code == 200
    assert r2.get_json().get("_idempotent_replay") is True
    assert r1.get_json()["total_amount_cents"] == r2.get_json()["total_amount_cents"]


def test_run_billing_idempotency_key_reuse_different_params(client):
    _register_login(client)
    r1 = _run_billing(client, "k-idem-B", dry_run=True)
    assert r1.status_code == 200
    # Same key, different dry_run
    r2 = _run_billing(client, "k-idem-B", dry_run=False)
    assert r2.status_code == 409
    assert "different parameters" in r2.get_json()["error"].lower()


# ===== Limit =====

def test_run_billing_limit_max_100(client):
    _register_login(client)
    r = _run_billing(client, "k-limit-big", limit=200)
    assert r.status_code == 400
    assert "100" in r.get_json()["error"]


def test_run_billing_limit_min_1(client):
    _register_login(client)
    r = _run_billing(client, "k-limit-0", limit=0)
    assert r.status_code == 400


# ===== Edge cases =====

def test_run_billing_insufficient_balance(client, app_ctx):
    _register_login(client)
    agent_id, api_key = _create_agent_with_balance(client, "poor-agent", 100)
    sub_id = _create_due_subscription(client, agent_id, api_key, app_ctx, "expensive-sub", 5000)

    r = _run_billing(client, "k-poor", dry_run=False)
    assert r.status_code == 200
    data = r.get_json()
    failures = [f for f in data["failed"] if f["sub_id"] == sub_id]
    assert len(failures) == 1
    assert failures[0]["reason"] == "insufficient_balance"

    r = client.get(f"/agents/{agent_id}", headers={"Authorization": f"Bearer {api_key}"})
    assert r.get_json()["agent"]["balance"] == 100


def test_run_billing_skips_not_due(client):
    _register_login(client)
    agent_id, api_key = _create_agent_with_balance(client, "future-agent", 5000)
    # Subscription due in the future
    r = client.post(
        f"/agents/{agent_id}/subscriptions/create",
        json={"name": "future-sub", "amount": 500, "interval": "monthly"},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert r.status_code == 201

    r = _run_billing(client, "k-future", dry_run=False)
    assert r.status_code == 200
    assert r.get_json()["total"] == 0


# ===== Audit =====

def test_run_billing_audit_logged(client, app_ctx):
    _register_login(client)
    _run_billing(client, "k-audit", dry_run=True)

    from models import AuditLog
    from database import db as _db
    with app_ctx.app_context():
        entry = (
            _db.session.query(AuditLog)
            .filter_by(action="admin.billing.run")
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert entry is not None
        assert entry.record_hash is not None
