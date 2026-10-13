"""AgentPay — Authentication & session tests."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def _register(client, email, password):
    return client.post(
        "/auth/register",
        json={"email": email, "password": password},
    )


def _login(client, email, password):
    return client.post(
        "/auth/login",
        json={"email": email, "password": password},
    )


# ===== Registration =====

def test_register_first_user_is_admin(client):
    """The first registered user becomes admin (bootstrap)."""
    r = _register(client, "first@example.com", "strongpass123")
    assert r.status_code == 201
    data = r.get_json()
    assert data["ok"] is True
    assert data["user"]["role"] == "admin"
    assert data["bootstrap_admin"] is True
    assert "password_hash" not in data["user"]


def test_register_second_user_is_developer(client):
    """Subsequent registrations default to developer."""
    _register(client, "first@example.com", "strongpass123")
    r = _register(client, "second@example.com", "strongpass456")
    assert r.status_code == 201
    data = r.get_json()
    assert data["user"]["role"] == "developer"
    assert data["bootstrap_admin"] is False


def test_register_invalid_email(client):
    r = _register(client, "not-an-email", "strongpass123")
    assert r.status_code == 400
    assert "email" in r.get_json()["error"].lower()


def test_register_weak_password(client):
    r = _register(client, "a@b.com", "short")
    assert r.status_code == 400
    assert "8" in r.get_json()["error"] or "characters" in r.get_json()["error"]


def test_register_duplicate_email(client):
    _register(client, "dup@example.com", "strongpass123")
    r = _register(client, "dup@example.com", "strongpass123")
    assert r.status_code == 409


def test_register_normalizes_email(client):
    """Emails are lowercased and trimmed."""
    r = _register(client, "UPPER@Example.COM  ", "strongpass123")
    assert r.status_code == 201
    assert r.get_json()["user"]["email"] == "upper@example.com"


# ===== Login =====

def test_login_success_sets_cookie(client):
    _register(client, "user@example.com", "strongpass123")
    r = _login(client, "user@example.com", "strongpass123")
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    # Session cookie should be set
    assert "ap_session" in r.headers.get("Set-Cookie", "")


def test_login_wrong_password(client):
    _register(client, "user@example.com", "strongpass123")
    r = _login(client, "user@example.com", "wrongpass")
    assert r.status_code == 401
    assert "invalid" in r.get_json()["error"].lower()


def test_login_nonexistent_user(client):
    r = _login(client, "ghost@example.com", "strongpass123")
    assert r.status_code == 401
    # Same generic error (no enumeration)
    assert "invalid" in r.get_json()["error"].lower()


def test_login_locks_after_failures(client):
    _register(client, "lock@example.com", "strongpass123")
    for _ in range(10):
        _login(client, "lock@example.com", "wrong")
    r = _login(client, "lock@example.com", "strongpass123")
    assert r.status_code == 429
    assert "locked" in r.get_json()["error"].lower()


# ===== Me / Session =====

def test_me_requires_auth(client):
    r = client.get("/auth/me")
    assert r.status_code == 401


def test_me_with_valid_session(client):
    _register(client, "me@example.com", "strongpass123")
    _login(client, "me@example.com", "strongpass123")
    r = client.get("/auth/me")
    assert r.status_code == 200
    data = r.get_json()
    assert data["user"]["email"] == "me@example.com"
    assert data["session"]["is_valid"] is True
    assert "..." in data["session"]["id"]  # never full token


def test_logout_revokes_session(client):
    _register(client, "out@example.com", "strongpass123")
    _login(client, "out@example.com", "strongpass123")
    r = client.post("/auth/logout")
    assert r.status_code == 200
    # After logout, /auth/me should fail
    r = client.get("/auth/me")
    assert r.status_code == 401


def test_logout_all_other_sessions(client):
    _register(client, "multi@example.com", "strongpass123")

    # Login from two "devices"
    c1 = client.application.test_client()
    c2 = client.application.test_client()
    _login(c1, "multi@example.com", "strongpass123")
    _login(c2, "multi@example.com", "strongpass123")

    # c1 stays valid
    assert c1.get("/auth/me").status_code == 200
    assert c2.get("/auth/me").status_code == 200

    # c1 revokes all others
    r = c1.post("/auth/logout-all")
    assert r.status_code == 200

    # c1 still valid, c2 revoked
    assert c1.get("/auth/me").status_code == 200
    assert c2.get("/auth/me").status_code == 401


# ===== Privacy =====

def test_user_dict_never_exposes_secrets(client):
    r = _register(client, "privacy@example.com", "strongpass123")
    data = r.get_json()["user"]
    assert "password_hash" not in data
    assert "totp_secret" not in data
    assert "recovery_codes_hash" not in data


# ===== Change Password =====

def test_change_password_success(client):
    """Changing password with correct current password works."""
    _register(client, "cp@example.com", "oldpass123")
    _login(client, "cp@example.com", "oldpass123")

    r = client.post("/auth/change-password", json={
        "current_password": "oldpass123",
        "new_password": "newstrong456",
    })
    assert r.status_code == 200
    assert "changed" in r.get_json()["message"].lower()

    # Old password no longer works
    client.post("/auth/logout")
    r = _login(client, "cp@example.com", "oldpass123")
    assert r.status_code == 401

    # New password works
    r = _login(client, "cp@example.com", "newstrong456")
    assert r.status_code == 200


def test_change_password_wrong_current(client):
    _register(client, "cp2@example.com", "oldpass123")
    _login(client, "cp2@example.com", "oldpass123")

    r = client.post("/auth/change-password", json={
        "current_password": "wrong",
        "new_password": "newstrong456",
    })
    assert r.status_code == 401


def test_change_password_too_short(client):
    _register(client, "cp3@example.com", "oldpass123")
    _login(client, "cp3@example.com", "oldpass123")

    r = client.post("/auth/change-password", json={
        "current_password": "oldpass123",
        "new_password": "short",
    })
    assert r.status_code == 400


def test_change_password_same_as_current(client):
    _register(client, "cp4@example.com", "oldpass123")
    _login(client, "cp4@example.com", "oldpass123")

    r = client.post("/auth/change-password", json={
        "current_password": "oldpass123",
        "new_password": "oldpass123",
    })
    assert r.status_code == 400
    assert "different" in r.get_json()["error"].lower()


def test_change_password_requires_auth(client):
    r = client.post("/auth/change-password", json={
        "current_password": "x",
        "new_password": "y" * 12,
    })
    assert r.status_code == 401


# ===== Change Email =====

def test_change_email_success(client):
    _register(client, "ce@example.com", "strongpass123")
    _login(client, "ce@example.com", "strongpass123")

    r = client.post("/auth/change-email", json={
        "new_email": "newce@example.com",
        "password": "strongpass123",
    })
    assert r.status_code == 200
    assert r.get_json()["user"]["email"] == "newce@example.com"


def test_change_email_wrong_password(client):
    _register(client, "ce2@example.com", "strongpass123")
    _login(client, "ce2@example.com", "strongpass123")

    r = client.post("/auth/change-email", json={
        "new_email": "x@example.com",
        "password": "wrong",
    })
    assert r.status_code == 401


def test_change_email_invalid(client):
    _register(client, "ce3@example.com", "strongpass123")
    _login(client, "ce3@example.com", "strongpass123")

    r = client.post("/auth/change-email", json={
        "new_email": "not-an-email",
        "password": "strongpass123",
    })
    assert r.status_code == 400


def test_change_email_already_taken(client):
    _register(client, "first@example.com", "strongpass123")
    _register(client, "ce4@example.com", "strongpass123")
    _login(client, "ce4@example.com", "strongpass123")

    r = client.post("/auth/change-email", json={
        "new_email": "first@example.com",
        "password": "strongpass123",
    })
    assert r.status_code == 409


def test_change_email_same_as_current(client):
    _register(client, "ce5@example.com", "strongpass123")
    _login(client, "ce5@example.com", "strongpass123")

    r = client.post("/auth/change-email", json={
        "new_email": "ce5@example.com",
        "password": "strongpass123",
    })
    assert r.status_code == 400
    assert "same" in r.get_json()["error"].lower()


# ===== Sessions List =====

def test_list_sessions_requires_auth(client):
    r = client.get("/auth/sessions")
    assert r.status_code == 401


def test_list_sessions_returns_current(client):
    _register(client, "sess@example.com", "strongpass123")
    _login(client, "sess@example.com", "strongpass123")

    r = client.get("/auth/sessions")
    assert r.status_code == 200
    data = r.get_json()
    assert data["count"] == 1
    assert data["sessions"][0]["is_current"] is True


def test_list_sessions_multiple_devices(client):
    _register(client, "multi2@example.com", "strongpass123")

    c1 = client.application.test_client()
    c2 = client.application.test_client()
    _login(c1, "multi2@example.com", "strongpass123")
    _login(c2, "multi2@example.com", "strongpass123")

    r = c1.get("/auth/sessions")
    assert r.status_code == 200
    data = r.get_json()
    assert data["count"] == 2
    currents = [s for s in data["sessions"] if s["is_current"]]
    assert len(currents) == 1


def test_change_password_revokes_other_sessions(client):
    _register(client, "revoke@example.com", "oldpass123")
    c1 = client.application.test_client()
    c2 = client.application.test_client()
    _login(c1, "revoke@example.com", "oldpass123")
    _login(c2, "revoke@example.com", "oldpass123")

    # c1 changes password
    r = c1.post("/auth/change-password", json={
        "current_password": "oldpass123",
        "new_password": "newpass456",
    })
    assert r.status_code == 200

    # c1 still valid, c2 revoked
    assert c1.get("/auth/me").status_code == 200
    assert c2.get("/auth/me").status_code == 401
