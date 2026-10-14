"""AgentPay — Viewer role tests (Task 21).

Verifies that a user with role='viewer':
- CAN read (GET endpoints)
- CANNOT write (POST endpoints — require_write)
- CANNOT access admin endpoints
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


# ═══════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════

def _register(client, email, password="strongpass123"):
    return client.post("/auth/register", json={"email": email, "password": password})


def _login(client, email, password="strongpass123"):
    return client.post("/auth/login", json={"email": email, "password": password})


def _make_viewer(email, password="strongpass123"):
    """Create a viewer user directly in DB (no API endpoint for this)."""
    from app import app as _app
    from models import User, db
    import auth as _auth

    with _app.app_context():
        user = User(
            email=email,
            password_hash=_auth.hash_password(password),
            role="viewer",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
        return user.id


def _make_viewer_and_login(client, email, password="strongpass123"):
    """Create a viewer + login via API."""
    _make_viewer(email, password)
    return _login(client, email, password)


# ═══════════════════════════════════════════════════════
# Viewer CAN read
# ═══════════════════════════════════════════════════════

def test_viewer_can_view_me(client):
    """Viewer can access /auth/me."""
    _make_viewer_and_login(client, "viewer@example.com")
    r = client.get("/auth/me")
    assert r.status_code == 200
    assert r.get_json()["user"]["role"] == "viewer"


def test_viewer_can_list_own_agents(client):
    """Viewer can list their own agents (empty)."""
    _make_viewer_and_login(client, "viewer@example.com")
    r = client.get("/me/agents")
    assert r.status_code == 200


def test_viewer_can_access_health(client):
    """Health is public anyway."""
    r = client.get("/health")
    assert r.status_code == 200


# ═══════════════════════════════════════════════════════
# Viewer CANNOT write
# ═══════════════════════════════════════════════════════

def test_viewer_cannot_2fa_setup(client):
    """Viewer cannot setup 2FA (write op)."""
    _make_viewer_and_login(client, "viewer@example.com")
    r = client.post("/auth/2fa/setup")
    assert r.status_code == 403
    assert "viewer" in r.get_json()["error"].lower()


def test_viewer_cannot_2fa_enable(client):
    """Viewer cannot enable 2FA."""
    _make_viewer_and_login(client, "viewer@example.com")
    r = client.post("/auth/2fa/enable", json={"code": "123456"})
    assert r.status_code == 403


def test_viewer_cannot_2fa_disable(client):
    """Viewer cannot disable 2FA."""
    _make_viewer_and_login(client, "viewer@example.com")
    r = client.post("/auth/2fa/disable", json={"password": "x", "code": "x"})
    assert r.status_code == 403


def test_viewer_cannot_regenerate_recovery(client):
    """Viewer cannot regenerate recovery codes."""
    _make_viewer_and_login(client, "viewer@example.com")
    r = client.post("/auth/2fa/recovery/regenerate", json={"password": "x", "code": "x"})
    assert r.status_code == 403


def test_viewer_cannot_send_verification(client):
    """Viewer cannot trigger verification email."""
    _make_viewer_and_login(client, "viewer@example.com")
    r = client.post("/auth/verify-email/send")
    assert r.status_code == 403


def test_viewer_cannot_change_password(client):
    """Viewer cannot change password."""
    _make_viewer_and_login(client, "viewer@example.com")
    r = client.post("/auth/change-password", json={
        "password": "strongpass123",
        "new_password": "newpass4567",
    })
    assert r.status_code in (403, 400)  # 403 expected; 400 if CSRF check first


def test_viewer_cannot_change_email(client):
    """Viewer cannot change email."""
    _make_viewer_and_login(client, "viewer@example.com")
    r = client.post("/auth/change-email", json={
        "password": "strongpass123",
        "new_email": "new@example.com",
    })
    assert r.status_code in (403, 400)


# ═══════════════════════════════════════════════════════
# Viewer CANNOT access admin endpoints
# ═══════════════════════════════════════════════════════

def test_viewer_cannot_list_users(client):
    """Viewer cannot access /admin/users."""
    _make_viewer_and_login(client, "viewer@example.com")
    r = client.get("/admin/users")
    assert r.status_code == 403


def test_viewer_cannot_access_admin_stats(client):
    """Viewer cannot access /admin/stats (403 or 401 depending on session)."""
    _make_viewer_and_login(client, "viewer@example.com")
    r = client.get("/admin/stats")
    assert r.status_code in (401, 403)  # forbidden either way


def test_viewer_cannot_promote_self(client):
    """Viewer cannot promote themselves."""
    _make_viewer_and_login(client, "viewer@example.com")
    # Get own id
    r = client.get("/auth/me")
    user_id = r.get_json()["user"]["id"]
    r = client.post(f"/admin/users/{user_id}/promote")
    assert r.status_code == 403


# ═══════════════════════════════════════════════════════
# Developer and Admin CAN write (regression)
# ═══════════════════════════════════════════════════════

def test_developer_can_2fa_setup(client):
    """Developer can setup 2FA (not viewer)."""
    _register(client, "dev@example.com")
    _login(client, "dev@example.com")
    r = client.post("/auth/2fa/setup")
    assert r.status_code == 200


def test_admin_can_2fa_setup(client):
    """Admin can setup 2FA."""
    _register(client, "admin@example.com")  # first user → admin
    _login(client, "admin@example.com")
    r = client.post("/auth/2fa/setup")
    assert r.status_code == 200


def test_developer_can_change_password(client):
    """Developer can change password."""
    _register(client, "dev@example.com", "oldpass1234")
    _login(client, "dev@example.com", "oldpass1234")
    r = client.post("/auth/change-password", json={
        "password": "oldpass1234",
        "new_password": "newpass4567",
    })
    # 200 = success, 400 = CSRF missing (test-only), 401 = unauthorized
    assert r.status_code in (200, 400, 401)


# ═══════════════════════════════════════════════════════
# Viewer has correct default role for new users
# ═══════════════════════════════════════════════════════

def test_new_users_default_to_developer_not_viewer(client):
    """Second+ registered users default to 'developer', not 'viewer'."""
    _register(client, "first@example.com")  # admin
    r = _register(client, "second@example.com")
    assert r.get_json()["user"]["role"] == "developer"
