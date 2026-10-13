"""AgentPay — Agent ownership & IDOR tests."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def _register(client, email, password="strongpass123"):
    return client.post("/auth/register", json={"email": email, "password": password})


def _login(client, email, password="strongpass123"):
    return client.post("/auth/login", json={"email": email, "password": password})


def _auth(api_key):
    return {"Authorization": f"Bearer {api_key}"}


def _create_owned_agent(client, name="owned"):
    """Create an agent via /me/agents (requires session)."""
    r = client.post("/me/agents", json={"name": name})
    assert r.status_code == 201, r.get_json()
    return r.get_json()["agent"]["id"], r.get_json()["api_key"]


def _create_orphan_agent(client, name="orphan"):
    """Create an agent via /agents/create (no session → orphan)."""
    r = client.post("/agents/create", json={"name": name})
    assert r.status_code == 201, r.get_json()
    return r.get_json()["agent"]["id"], r.get_json()["api_key"]


# ===== Ownership on create =====

def test_me_agents_requires_auth(client):
    r = client.post("/me/agents", json={"name": "test"})
    assert r.status_code == 401


def test_create_owned_agent_sets_owner(client):
    _register(client, "owner1@example.com")
    _login(client, "owner1@example.com")

    agent_id, api_key = _create_owned_agent(client, "my-first-agent")
    assert agent_id
    assert api_key.startswith("ap_")

    # GET /me/agents should list it
    r = client.get("/me/agents")
    assert r.status_code == 200
    data = r.get_json()
    assert data["count"] == 1
    assert data["agents"][0]["id"] == agent_id


def test_orphan_agent_has_no_owner(client):
    agent_id, _ = _create_orphan_agent(client, "orphan-1")
    r = client.get("/me/agents")
    # Not logged in → 401 (we still don't leak)
    assert r.status_code == 401


def test_create_orphan_with_session_attaches_owner(client):
    """POST /agents/create with session attaches owner automatically."""
    _register(client, "attach@example.com")
    _login(client, "attach@example.com")

    r = client.post("/agents/create", json={"name": "attached"})
    assert r.status_code == 201

    # Should appear in /me/agents
    r = client.get("/me/agents")
    assert r.get_json()["count"] == 1


# ===== IDOR protection on GET =====

def test_get_agent_via_session_own(client):
    _register(client, "getown@example.com")
    _login(client, "getown@example.com")
    agent_id, _ = _create_owned_agent(client)

    r = client.get(f"/agents/{agent_id}")
    assert r.status_code == 200
    assert r.get_json()["agent"]["id"] == agent_id


def test_get_agent_via_session_other_user_returns_404(client):
    """IDOR: user A cannot see user B's agent."""
    # User A
    cA = client.application.test_client()
    _register(cA, "userA@example.com")
    _login(cA, "userA@example.com")
    agent_A_id, _ = _create_owned_agent(cA, "agent-A")

    # User B
    cB = client.application.test_client()
    _register(cB, "userB@example.com")
    _login(cB, "userB@example.com")

    # B tries to access A's agent
    r = cB.get(f"/agents/{agent_A_id}")
    assert r.status_code == 404  # NOT 403 (no existence leak)


def test_get_agent_via_api_key(client):
    agent_id, api_key = _create_orphan_agent(client, "viakey")
    r = client.get(f"/agents/{agent_id}", headers=_auth(api_key))
    assert r.status_code == 200


def test_get_agent_without_auth_returns_404(client):
    """No auth → 404 (not 401, no existence leak)."""
    agent_id, _ = _create_orphan_agent(client, "noauth")
    r = client.get(f"/agents/{agent_id}")
    assert r.status_code == 404


def test_get_agent_wrong_api_key_returns_404(client):
    agent_id, _ = _create_orphan_agent(client, "wrongkey")
    r = client.get(f"/agents/{agent_id}", headers=_auth("ap_wrong_key_xyz"))
    assert r.status_code == 404


def test_admin_can_view_any_agent(client):
    """Admin role sees all agents."""
    # First user = admin (bootstrap)
    cAdmin = client.application.test_client()
    _register(cAdmin, "admin2@example.com")
    _login(cAdmin, "admin2@example.com")

    # Regular user creates agent
    cUser = client.application.test_client()
    _register(cUser, "regular@example.com")
    _login(cUser, "regular@example.com")
    agent_id, _ = _create_owned_agent(cUser, "user-agent")

    # Admin can view it
    r = cAdmin.get(f"/agents/{agent_id}")
    assert r.status_code == 200
    assert r.get_json()["agent"]["id"] == agent_id


# ===== Claim =====

def test_claim_requires_auth(client):
    agent_id, _ = _create_orphan_agent(client, "claim-noauth")
    r = client.post(f"/agents/{agent_id}/claim", json={"password": "x"})
    assert r.status_code == 401


def test_claim_orphan_agent(client):
    agent_id, _ = _create_orphan_agent(client, "claimable")

    _register(client, "claimer@example.com")
    _login(client, "claimer@example.com")

    r = client.post(
        f"/agents/{agent_id}/claim",
        json={"password": "strongpass123"},
    )
    assert r.status_code == 200
    assert r.get_json()["agent"]["id"] == agent_id

    # Now visible in /me/agents
    r = client.get("/me/agents")
    assert r.get_json()["count"] == 1


def test_claim_requires_password(client):
    agent_id, _ = _create_orphan_agent(client, "claim-nopass")
    _register(client, "nopass@example.com")
    _login(client, "nopass@example.com")

    r = client.post(f"/agents/{agent_id}/claim", json={"password": "wrongpass"})
    assert r.status_code == 401


def test_claim_already_owned_fails(client):
    """Cannot claim an agent owned by another user."""
    # User A claims agent
    cA = client.application.test_client()
    _register(cA, "claimerA@example.com")
    _login(cA, "claimerA@example.com")
    agent_id, _ = _create_orphan_agent(cA, "contested")
    r = cA.post(f"/agents/{agent_id}/claim", json={"password": "strongpass123"})
    assert r.status_code == 200

    # User B tries to claim it
    cB = client.application.test_client()
    _register(cB, "claimerB@example.com")
    _login(cB, "claimerB@example.com")
    r = cB.post(f"/agents/{agent_id}/claim", json={"password": "strongpass123"})
    assert r.status_code == 409  # Conflict — already owned


def test_claim_same_user_twice_is_idempotent(client):
    agent_id, _ = _create_orphan_agent(client, "idempotent")
    _register(client, "idem@example.com")
    _login(client, "idem@example.com")

    r1 = client.post(f"/agents/{agent_id}/claim", json={"password": "strongpass123"})
    assert r1.status_code == 200

    r2 = client.post(f"/agents/{agent_id}/claim", json={"password": "strongpass123"})
    assert r2.status_code == 200
    assert "already" in r2.get_json().get("message", "").lower()
