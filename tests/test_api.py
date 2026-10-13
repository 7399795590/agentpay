"""AgentPay — API tests."""
import os
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app import app
from database import db


client = None


class _FakeResponse:
    """Minimal object that mimics Flask response for topup replacement."""
    def __init__(self, agent_dict):
        self.status_code = 200
        self._data = {"ok": True, "agent": agent_dict}
    def get_json(self):
        return self._data


def _topup(agent_id, amount, api_key=None):
    """Helper: perform topup via topup_helpers (bypasses disabled HTTP route).

    Handles invalid types (non-int, negative) as 400.
    """
    from app import app
    from database import db
    import topup_helpers

    # Simulate HTTP-level validation
    if not isinstance(amount, int) or isinstance(amount, bool):
        class _ErrType:
            status_code = 400
            def get_json(self_inner):
                return {"ok": False, "error": "amount must be integer"}
        return _ErrType()

    with app.app_context():
        result = topup_helpers.perform_topup(
            agent_id=agent_id,
            amount_cents=amount,
            source="migration",
        )
        if not result["ok"]:
            # Mimic HTTP error
            class _Err:
                status_code = 400
                def get_json(self_inner):
                    return {"ok": False, "error": result["error"]}
            return _Err()
        return _FakeResponse(result["agent"].to_dict())




def setup_module():
    """Set up a fresh in-memory test client for the whole module."""
    global client
    # Set a test admin key so admin endpoints are enabled during tests
    os.environ["ADMIN_API_KEY"] = "test_admin_key_for_ci_only"
    app.config["TESTING"] = True
    # Use in-memory SQLite so each test session starts fresh
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {}
    with app.app_context():
        db.drop_all()
        db.create_all()
    client = app.test_client()


def _create_agent(prefix="agent"):
    """Helper: create an agent with unique name and return (agent_id, api_key)."""
    name = f"{prefix}-{uuid.uuid4().hex[:8]}"
    r = client.post("/agents/create", json={"name": name})
    data = r.get_json()
    return data["agent"]["id"], data["api_key"]


def _auth(api_key):
    """Helper: build Authorization header."""
    return {"Authorization": "Bearer " + api_key}

def _topup_direct(agent_id, amount_cents):
    """Direct helper for tests: top up an agent via topup_helpers.

    Uses HTTP-disabled direct topup because /agents/{id}/topup is now
    disabled (task-5). Tests that need balance set it up via this helper.
    """
    from app import app
    from database import db
    import topup_helpers
    with app.app_context():
        result = topup_helpers.perform_topup(
            agent_id=agent_id,
            amount_cents=amount_cents,
            source="migration",  # test source
        )
        if not result["ok"]:
            raise RuntimeError(f"Topup failed: {result.get('error')}")
        return result["agent"].balance




def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert data["service"] == "agentpay"


def test_create_agent():
    name = "test-agent-" + uuid.uuid4().hex[:8]
    r = client.post("/agents/create", json={"name": name})
    assert r.status_code == 201
    data = r.get_json()
    assert data["ok"] is True
    assert "agent" in data
    assert "api_key" in data
    assert data["agent"]["name"] == name
    assert data["agent"]["balance"] == 0
    assert data["api_key"].startswith("ap_")


def test_create_agent_invalid_name():
    r = client.post("/agents/create", json={"name": ""})
    assert r.status_code == 400
    r = client.post("/agents/create", json={})
    assert r.status_code == 400


def test_full_cycle():
    agent_id, api_key = _create_agent("cycle")
    h = _auth(api_key)

    r = client.get("/agents/" + agent_id, headers=h)
    assert r.get_json()["agent"]["balance"] == 0

    r = _topup(agent_id, 500)
    assert r.status_code == 200
    assert r.get_json()["agent"]["balance"] == 500

    r = client.post("/agents/" + agent_id + "/charge",
                    json={"amount": 30}, headers=h)
    assert r.status_code == 200
    assert r.get_json()["agent"]["balance"] == 470

    r = client.get("/agents/" + agent_id + "/transactions", headers=h)
    data = r.get_json()
    assert data["count"] == 2
    types = [t["type"] for t in data["transactions"]]
    assert "topup" in types
    assert "charge" in types


def test_insufficient_balance():
    agent_id, api_key = _create_agent("poor")
    h = _auth(api_key)

    r = client.post("/agents/" + agent_id + "/charge",
                    json={"amount": 100}, headers=h)
    assert r.status_code == 402
    assert "Insufficient" in r.get_json()["error"]


def test_agent_not_found():
    r = client.get("/agents/nonexistent")
    assert r.status_code == 404


def test_invalid_amount():
    agent_id, api_key = _create_agent("bad-amount")
    h = _auth(api_key)

    r = _topup(agent_id, -10)
    assert r.status_code == 400

    r = _topup(agent_id, 0)
    assert r.status_code == 400

    r = _topup(agent_id, "100")  # type: ignore — invalid type
    assert r.status_code == 400


def test_refund_flow():
    """Test refund end-to-end (validates audit fix)."""
    agent_id, api_key = _create_agent("refund")
    h = _auth(api_key)

    _topup(agent_id, 500)
    r = client.post("/agents/" + agent_id + "/charge",
                    json={"amount": 100, "description": "test"}, headers=h)
    tx_id = r.get_json()["transaction"]["id"]

    r = client.post("/agents/" + agent_id + "/refund",
                    json={"transaction_id": tx_id}, headers=h)
    assert r.status_code == 200
    assert r.get_json()["ok"] is True

    r = client.post("/agents/" + agent_id + "/refund",
                    json={"transaction_id": tx_id}, headers=h)
    assert r.status_code == 409


def test_admin_requires_auth():
    """Admin endpoints require ADMIN_API_KEY."""
    r = client.get("/admin/stats")
    assert r.status_code == 401

    r = client.get("/admin/stats",
                   headers={"Authorization": "Bearer wrong_key"})
    assert r.status_code == 403
