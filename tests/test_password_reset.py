"""AgentPay — Password reset tests (Task 17)."""
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def _register(client, email, password="strongpass123"):
    return client.post("/auth/register", json={"email": email, "password": password})


def _login(client, email, password="strongpass123"):
    return client.post("/auth/login", json={"email": email, "password": password})


# ═══════════════════════════════════════════════════════
# /auth/forgot-password
# ═══════════════════════════════════════════════════════

def test_forgot_password_existing_user(client):
    """Returns generic success message for existing users."""
    _register(client, "user@example.com")
    r = client.post("/auth/forgot-password", json={"email": "user@example.com"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert "reset link" in data["message"].lower() or "email exists" in data["message"].lower()


def test_forgot_password_unknown_user_same_response(client):
    """Anti-enumeration: unknown email returns same response as known."""
    _register(client, "user@example.com")
    r_known = client.post("/auth/forgot-password", json={"email": "user@example.com"})
    r_unknown = client.post("/auth/forgot-password", json={"email": "nobody@example.com"})
    assert r_known.status_code == r_unknown.status_code
    assert r_known.get_json() == r_unknown.get_json()


def test_forgot_password_missing_email(client):
    """Missing email returns 400."""
    r = client.post("/auth/forgot-password", json={})
    assert r.status_code == 400


def test_forgot_password_creates_token(client):
    """A reset token is created for existing users."""
    from app import app as _app
    from models import PasswordResetToken

    _register(client, "user@example.com")
    with _app.app_context():
        before = PasswordResetToken.query.count()
    client.post("/auth/forgot-password", json={"email": "user@example.com"})
    with _app.app_context():
        after = PasswordResetToken.query.count()
    assert after == before + 1


def test_forgot_password_unknown_creates_no_token(client):
    """No token is created for unknown emails."""
    from app import app as _app
    from models import PasswordResetToken

    with _app.app_context():
        before = PasswordResetToken.query.count()
    client.post("/auth/forgot-password", json={"email": "nobody@example.com"})
    with _app.app_context():
        after = PasswordResetToken.query.count()
    assert after == before


# ═══════════════════════════════════════════════════════
# /auth/reset-password
# ═══════════════════════════════════════════════════════

def _get_reset_token(client, email):
    """Helper: request reset and pull raw token from DB."""
    from app import app as _app
    from models import PasswordResetToken

    client.post("/auth/forgot-password", json={"email": email})
    with _app.app_context():
        token = PasswordResetToken.query.order_by(PasswordResetToken.id.desc()).first()
        return token


def test_reset_password_valid_token(client):
    """Reset with valid token changes password."""
    _register(client, "user@example.com", "oldpass1234")
    _get_reset_token(client, "user@example.com")

    # Get raw token — we need to re-issue because raw is not stored
    # So we call the helper directly inside app context
    from app import app as _app
    import auth
    with _app.app_context():
        from models import User
        user = User.query.filter_by(email="user@example.com").first()
        raw = auth.generate_reset_token(user.id)

    r = client.post("/auth/reset-password", json={"token": raw, "password": "newpass4567"})
    assert r.status_code == 200

    # Login with new password
    r = _login(client, "user@example.com", "newpass4567")
    assert r.status_code == 200


def test_reset_password_old_password_invalid_after(client):
    """After reset, the old password no longer works."""
    _register(client, "user@example.com", "oldpass1234")

    from app import app as _app
    import auth
    with _app.app_context():
        from models import User
        user = User.query.filter_by(email="user@example.com").first()
        raw = auth.generate_reset_token(user.id)

    client.post("/auth/reset-password", json={"token": raw, "password": "newpass4567"})

    r = _login(client, "user@example.com", "oldpass1234")
    assert r.status_code == 401


def test_reset_password_invalid_token(client):
    """Invalid token is rejected."""
    r = client.post("/auth/reset-password", json={"token": "invalid_token_xyz", "password": "newpass4567"})
    assert r.status_code == 400


def test_reset_password_short_password(client):
    """Short passwords are rejected."""
    r = client.post("/auth/reset-password", json={"token": "any", "password": "short"})
    assert r.status_code == 400


def test_reset_password_missing_token(client):
    """Missing token returns 400."""
    r = client.post("/auth/reset-password", json={"password": "newpass4567"})
    assert r.status_code == 400


def test_reset_password_token_single_use(client):
    """Same token cannot be reused."""
    _register(client, "user@example.com", "oldpass1234")

    from app import app as _app
    import auth
    with _app.app_context():
        from models import User
        user = User.query.filter_by(email="user@example.com").first()
        raw = auth.generate_reset_token(user.id)

    # First use: OK
    r1 = client.post("/auth/reset-password", json={"token": raw, "password": "newpass4567"})
    assert r1.status_code == 200

    # Second use: FAIL
    r2 = client.post("/auth/reset-password", json={"token": raw, "password": "anotherpass789"})
    assert r2.status_code == 400


def test_reset_password_revokes_sessions(client):
    """Reset revokes all existing sessions."""
    _register(client, "user@example.com", "oldpass1234")
    _login(client, "user@example.com", "oldpass1234")  # create a session

    # Now reset
    from app import app as _app
    import auth
    with _app.app_context():
        from models import User
        user = User.query.filter_by(email="user@example.com").first()
        raw = auth.generate_reset_token(user.id)

    client.post("/auth/reset-password", json={"token": raw, "password": "newpass4567"})

    # The old session cookie should be invalid
    r = client.get("/auth/me")
    assert r.status_code == 401


def test_reset_password_expired_token(client):
    """Expired tokens are rejected."""
    _register(client, "user@example.com", "oldpass1234")

    from app import app as _app
    import auth
    from models import PasswordResetToken
    import time

    with _app.app_context():
        from models import User, db
        user = User.query.filter_by(email="user@example.com").first()
        # Create token then expire it
        raw = "test_raw_token_expired_123456"
        from auth import _hash_token
        token = PasswordResetToken(
            user_id=user.id,
            token_hash=_hash_token(raw),
            expires_at=int(time.time()) - 60,  # already expired
        )
        db.session.add(token)
        db.session.commit()

    r = client.post("/auth/reset-password", json={"token": raw, "password": "newpass4567"})
    assert r.status_code == 400
