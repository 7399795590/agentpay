"""AgentPay — Email verification tests (Task 18)."""
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def _register(client, email, password="strongpass123"):
    return client.post("/auth/register", json={"email": email, "password": password})


def _login(client, email, password="strongpass123"):
    return client.post("/auth/login", json={"email": email, "password": password})


def _register_and_login(client, email, password="strongpass123"):
    _register(client, email, password)
    _login(client, email, password)


# ═══════════════════════════════════════════════════════
# /auth/verify-email/send
# ═══════════════════════════════════════════════════════

def test_send_verification_requires_auth(client):
    """Without login, sending verification email fails."""
    r = client.post("/auth/verify-email/send")
    assert r.status_code == 401


def test_send_verification_creates_token(client):
    """After login, sending verification creates a token."""
    from app import app as _app
    from models import EmailVerificationToken

    _register_and_login(client, "user@example.com")

    with _app.app_context():
        before = EmailVerificationToken.query.count()

    r = client.post("/auth/verify-email/send")
    assert r.status_code == 200
    data = r.get_json()
    assert "message" in data

    with _app.app_context():
        after = EmailVerificationToken.query.count()
    assert after == before + 1


def test_send_verification_when_already_verified(client):
    """If already verified, returns success without creating a new token."""
    from app import app as _app
    from models import EmailVerificationToken, User, db

    _register_and_login(client, "user@example.com")

    # Manually mark as verified
    with _app.app_context():
        user = User.query.filter_by(email="user@example.com").first()
        user.email_verified = True
        db.session.commit()

    with _app.app_context():
        before = EmailVerificationToken.query.count()

    r = client.post("/auth/verify-email/send")
    assert r.status_code == 200
    data = r.get_json()
    assert data.get("email_verified") is True

    with _app.app_context():
        after = EmailVerificationToken.query.count()
    assert after == before  # no new token


# ═══════════════════════════════════════════════════════
# /auth/verify-email/confirm
# ═══════════════════════════════════════════════════════

def test_confirm_email_with_valid_token(client):
    """Valid token marks email_verified=True."""
    from app import app as _app
    import auth
    from models import User, db

    _register(client, "user@example.com")

    with _app.app_context():
        user = User.query.filter_by(email="user@example.com").first()
        raw = auth.generate_verification_token(user.id, user.email)

    r = client.post("/auth/verify-email/confirm", json={"token": raw})
    assert r.status_code == 200
    assert r.get_json()["email_verified"] is True

    with _app.app_context():
        user = User.query.filter_by(email="user@example.com").first()
        assert user.email_verified is True


def test_confirm_email_invalid_token(client):
    """Invalid token is rejected."""
    r = client.post("/auth/verify-email/confirm", json={"token": "invalid_xyz"})
    assert r.status_code == 400


def test_confirm_email_missing_token(client):
    """Missing token returns 400."""
    r = client.post("/auth/verify-email/confirm", json={})
    assert r.status_code == 400


def test_confirm_email_token_single_use(client):
    """Same token cannot be reused."""
    from app import app as _app
    import auth
    from models import User

    _register(client, "user@example.com")

    with _app.app_context():
        user = User.query.filter_by(email="user@example.com").first()
        raw = auth.generate_verification_token(user.id, user.email)

    # First use: OK
    r1 = client.post("/auth/verify-email/confirm", json={"token": raw})
    assert r1.status_code == 200

    # Second use: FAIL
    r2 = client.post("/auth/verify-email/confirm", json={"token": raw})
    assert r2.status_code == 400


def test_confirm_email_expired_token(client):
    """Expired tokens are rejected."""
    from app import app as _app
    import auth
    from models import User, EmailVerificationToken, db

    _register(client, "user@example.com")

    with _app.app_context():
        user = User.query.filter_by(email="user@example.com").first()
        raw = "expired_token_raw_xyz_123"
        from auth import _hash_token
        token = EmailVerificationToken(
            user_id=user.id,
            email=user.email,
            token_hash=_hash_token(raw),
            expires_at=int(time.time()) - 60,
        )
        db.session.add(token)
        db.session.commit()

    r = client.post("/auth/verify-email/confirm", json={"token": raw})
    assert r.status_code == 400


def test_confirm_email_wrong_user_email_mismatch(client):
    """If the email on the token does not match current user email, reject."""
    from app import app as _app
    import auth
    from models import User, db

    _register(client, "user@example.com")

    with _app.app_context():
        user = User.query.filter_by(email="user@example.com").first()
        raw = auth.generate_verification_token(user.id, "old@example.com")  # mismatched

    r = client.post("/auth/verify-email/confirm", json={"token": raw})
    assert r.status_code == 400
    assert "match" in r.get_json()["error"].lower() or "invalid" in r.get_json()["error"].lower()


# ═══════════════════════════════════════════════════════
# Token lifecycle
# ═══════════════════════════════════════════════════════

def test_email_verified_defaults_false(client):
    """New user starts with email_verified=False."""
    from app import app as _app
    from models import User

    _register(client, "user@example.com")
    with _app.app_context():
        user = User.query.filter_by(email="user@example.com").first()
        assert user.email_verified is False


def test_email_verified_reset_on_email_change(client):
    """Changing email sets email_verified back to False."""
    from app import app as _app
    from models import User, db

    _register_and_login(client, "user@example.com")

    # Manually verify
    with _app.app_context():
        user = User.query.filter_by(email="user@example.com").first()
        user.email_verified = True
        db.session.commit()

    # Change email
    r = client.post("/auth/change-email", json={
        "password": "strongpass123",
        "new_email": "newemail@example.com",
    })
    assert r.status_code == 200

    with _app.app_context():
        user = User.query.filter_by(email="newemail@example.com").first()
        assert user.email_verified is False
