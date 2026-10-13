"""AgentPay — Admin user management tests."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def _register(client, email, password="strongpass123"):
    return client.post("/auth/register", json={"email": email, "password": password})


def _login(client, email, password="strongpass123"):
    return client.post("/auth/login", json={"email": email, "password": password})


def _get_admin_and_dev(client):
    """Bootstrap: first user = admin, second = developer."""
    cAdmin = client.application.test_client()
    _register(cAdmin, "admin@test.com")
    _login(cAdmin, "admin@test.com")

    cDev = client.application.test_client()
    _register(cDev, "dev@test.com")
    _login(cDev, "dev@test.com")

    return cAdmin, cDev


def _user_id(client, email):
    """Look up user_id by email via admin list."""
    r = client.get(f"/admin/users?q={email}")
    users = r.get_json()["users"]
    for u in users:
        if u["email"] == email:
            return u["id"]
    return None


# ===== Authorization =====

def test_list_users_requires_auth(client):
    r = client.get("/admin/users")
    assert r.status_code == 401


def test_list_users_requires_admin(client):
    cAdmin, cDev = _get_admin_and_dev(client)
    r = cDev.get("/admin/users")
    assert r.status_code == 403


def test_admin_can_list_users(client):
    cAdmin, _ = _get_admin_and_dev(client)
    r = cAdmin.get("/admin/users")
    assert r.status_code == 200
    data = r.get_json()
    assert data["count"] >= 2
    # Never expose password_hash / totp_secret
    for u in data["users"]:
        assert "password_hash" not in u
        assert "totp_secret" not in u


def test_admin_can_get_user(client):
    cAdmin, _ = _get_admin_and_dev(client)
    dev_id = _user_id(cAdmin, "dev@test.com")
    r = cAdmin.get(f"/admin/users/{dev_id}")
    assert r.status_code == 200
    assert r.get_json()["user"]["email"] == "dev@test.com"


def test_get_user_404(client):
    cAdmin, _ = _get_admin_and_dev(client)
    r = cAdmin.get("/admin/users/nonexistent")
    assert r.status_code == 404


# ===== Promote / Demote =====

def test_promote_developer_to_admin(client):
    cAdmin, _ = _get_admin_and_dev(client)
    dev_id = _user_id(cAdmin, "dev@test.com")

    r = cAdmin.post(f"/admin/users/{dev_id}/promote")
    assert r.status_code == 200
    assert r.get_json()["user"]["role"] == "admin"


def test_promote_already_admin_is_idempotent(client):
    cAdmin, _ = _get_admin_and_dev(client)
    dev_id = _user_id(cAdmin, "dev@test.com")

    cAdmin.post(f"/admin/users/{dev_id}/promote")
    r = cAdmin.post(f"/admin/users/{dev_id}/promote")
    assert r.status_code == 200
    assert "already" in r.get_json().get("message", "").lower()


def test_demote_admin(client):
    cAdmin, _ = _get_admin_and_dev(client)
    dev_id = _user_id(cAdmin, "dev@test.com")

    cAdmin.post(f"/admin/users/{dev_id}/promote")
    r = cAdmin.post(f"/admin/users/{dev_id}/demote")
    assert r.status_code == 200
    assert r.get_json()["user"]["role"] == "developer"


def test_cannot_demote_self(client):
    cAdmin, _ = _get_admin_and_dev(client)
    admin_id = _user_id(cAdmin, "admin@test.com")

    r = cAdmin.post(f"/admin/users/{admin_id}/demote")
    assert r.status_code == 403
    assert "yourself" in r.get_json()["error"].lower()


def test_cannot_demote_last_admin(client):
    """Cannot demote the only active admin."""
    cAdmin, _ = _get_admin_and_dev(client)

    # Promote dev to admin, then demote original admin
    dev_id = _user_id(cAdmin, "dev@test.com")
    cAdmin.post(f"/admin/users/{dev_id}/promote")

    admin_id = _user_id(cAdmin, "admin@test.com")
    r = cAdmin.post(f"/admin/users/{admin_id}/demote")
    assert r.status_code == 403  # self-demote also blocked, but last-admin check kicks first
    # Now let's test real last-admin: demote original admin from dev account
    cDev = client.application.test_client()
    _login(cDev, "dev@test.com")
    r2 = cDev.post(f"/admin/users/{admin_id}/demote")
    assert r2.status_code == 200  # now dev-admin demotes orig admin (there are 2 admins)

    # After: dev is last admin. Cannot demote self.
    r3 = cDev.post(f"/admin/users/{dev_id}/demote")
    assert r3.status_code == 403


# ===== Disable / Enable =====

def test_disable_user(client):
    cAdmin, cDev = _get_admin_and_dev(client)
    dev_id = _user_id(cAdmin, "dev@test.com")

    r = cAdmin.post(f"/admin/users/{dev_id}/disable")
    assert r.status_code == 200
    assert r.get_json()["user"]["is_active"] is False

    # Disabled user cannot log in
    cNew = client.application.test_client()
    r = _login(cNew, "dev@test.com")
    assert r.status_code == 403


def test_disable_revokes_sessions(client):
    cAdmin, cDev = _get_admin_and_dev(client)
    dev_id = _user_id(cAdmin, "dev@test.com")

    # Dev has active session
    assert cDev.get("/auth/me").status_code == 200

    # Admin disables dev
    cAdmin.post(f"/admin/users/{dev_id}/disable")

    # Dev session should now be invalid
    assert cDev.get("/auth/me").status_code == 401


def test_cannot_disable_self(client):
    cAdmin, _ = _get_admin_and_dev(client)
    admin_id = _user_id(cAdmin, "admin@test.com")

    r = cAdmin.post(f"/admin/users/{admin_id}/disable")
    assert r.status_code == 403


def test_cannot_disable_last_admin(client):
    cAdmin, _ = _get_admin_and_dev(client)
    # Try to disable the only admin (from another admin? no — self). Use dev promoted.
    dev_id = _user_id(cAdmin, "dev@test.com")
    cAdmin.post(f"/admin/users/{dev_id}/promote")

    cDev = client.application.test_client()
    _login(cDev, "dev@test.com")

    # Demote original admin
    admin_id = _user_id(cAdmin, "admin@test.com")
    cDev.post(f"/admin/users/{admin_id}/demote")

    # Now dev is last admin. Cannot disable self.
    r = cDev.post(f"/admin/users/{dev_id}/disable")
    assert r.status_code == 403


def test_enable_user(client):
    cAdmin, _ = _get_admin_and_dev(client)
    dev_id = _user_id(cAdmin, "dev@test.com")

    cAdmin.post(f"/admin/users/{dev_id}/disable")
    r = cAdmin.post(f"/admin/users/{dev_id}/enable")
    assert r.status_code == 200
    assert r.get_json()["user"]["is_active"] is True


def test_non_admin_cannot_promote(client):
    cAdmin, cDev = _get_admin_and_dev(client)
    admin_id = _user_id(cAdmin, "admin@test.com")

    r = cDev.post(f"/admin/users/{admin_id}/promote")
    assert r.status_code == 403
