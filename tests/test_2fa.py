"""AgentPay — 2FA / TOTP tests (Task 19)."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pyotp
import totp as totp_mod


# ═══════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════

def _register(client, email, password, expect_admin=False):
    """Register a user (first becomes admin)."""
    r = client.post("/auth/register", json={"email": email, "password": password})
    return r


def _login(client, email, password, totp_code=None, recovery_code=None):
    """Login with optional 2FA."""
    payload = {"email": email, "password": password}
    if totp_code:
        payload["totp_code"] = totp_code
    if recovery_code:
        payload["recovery_code"] = recovery_code
    return client.post("/auth/login", json=payload)


def _setup_2fa_for(client, email, password):
    """Full flow: register, login, setup 2FA, enable, return secret + recovery codes."""
    _register(client, email, password)
    _login(client, email, password)  # get session
    r = client.post("/auth/2fa/setup")
    assert r.status_code == 200, r.get_json()
    secret = r.get_json()["secret"]
    # Generate current code
    code = pyotp.TOTP(secret).now()
    r = client.post("/auth/2fa/enable", json={"code": code})
    assert r.status_code == 200, r.get_json()
    recovery_codes = r.get_json()["recovery_codes"]
    # Logout to clear session
    client.post("/auth/logout")
    return secret, recovery_codes


# ═══════════════════════════════════════════════════════
# /auth/2fa/status
# ═══════════════════════════════════════════════════════

def test_2fa_status_requires_auth(client):
    """Without session, 2FA status is unauthorized."""
    r = client.get("/auth/2fa/status")
    assert r.status_code == 401


def test_2fa_status_disabled_initially(client):
    """Fresh user has 2FA disabled."""
    _register(client, "user@example.com", "strongpass123")
    _login(client, "user@example.com", "strongpass123")
    r = client.get("/auth/2fa/status")
    assert r.status_code == 200
    data = r.get_json()
    assert data["totp_enabled"] is False
    assert data["recovery_codes_remaining"] == 0


# ═══════════════════════════════════════════════════════
# /auth/2fa/setup
# ═══════════════════════════════════════════════════════

def test_2fa_setup_returns_secret_and_qr(client):
    """Setup returns secret, provisioning URI, and QR data URL."""
    _register(client, "user@example.com", "strongpass123")
    _login(client, "user@example.com", "strongpass123")

    r = client.post("/auth/2fa/setup")
    assert r.status_code == 200
    data = r.get_json()
    assert "secret" in data
    assert len(data["secret"]) >= 16  # base32 secrets are long
    assert data["provisioning_uri"].startswith("otpauth://totp/")
    assert data["qr_data_url"].startswith("data:image/svg+xml;base64,")


def test_2fa_setup_does_not_enable_yet(client):
    """Setup alone does not enable 2FA — must verify code first."""
    _register(client, "user@example.com", "strongpass123")
    _login(client, "user@example.com", "strongpass123")

    client.post("/auth/2fa/setup")
    r = client.get("/auth/2fa/status")
    assert r.get_json()["totp_enabled"] is False


def test_2fa_setup_requires_auth(client):
    r = client.post("/auth/2fa/setup")
    assert r.status_code == 401


# ═══════════════════════════════════════════════════════
# /auth/2fa/enable
# ═══════════════════════════════════════════════════════

def test_2fa_enable_with_valid_code(client):
    """Valid TOTP code enables 2FA and returns recovery codes."""
    _register(client, "user@example.com", "strongpass123")
    _login(client, "user@example.com", "strongpass123")

    r = client.post("/auth/2fa/setup")
    secret = r.get_json()["secret"]
    code = pyotp.TOTP(secret).now()

    r = client.post("/auth/2fa/enable", json={"code": code})
    assert r.status_code == 200
    data = r.get_json()
    assert data["totp_enabled"] is True
    assert len(data["recovery_codes"]) == 10
    assert "warning" in data


def test_2fa_enable_with_invalid_code(client):
    """Wrong TOTP code does not enable 2FA."""
    _register(client, "user@example.com", "strongpass123")
    _login(client, "user@example.com", "strongpass123")

    client.post("/auth/2fa/setup")
    r = client.post("/auth/2fa/enable", json={"code": "000000"})
    assert r.status_code == 401
    assert "Invalid" in r.get_json()["error"]


def test_2fa_enable_without_setup(client):
    """Enable without prior setup fails."""
    _register(client, "user@example.com", "strongpass123")
    _login(client, "user@example.com", "strongpass123")

    r = client.post("/auth/2fa/enable", json={"code": "123456"})
    assert r.status_code == 400


def test_2fa_enable_twice_fails(client):
    """Cannot re-enable when already enabled."""
    _register(client, "user@example.com", "strongpass123")
    _login(client, "user@example.com", "strongpass123")

    r = client.post("/auth/2fa/setup")
    secret = r.get_json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/auth/2fa/enable", json={"code": code})

    r = client.post("/auth/2fa/enable", json={"code": code})
    assert r.status_code == 400


# ═══════════════════════════════════════════════════════
# Login flow with 2FA
# ═══════════════════════════════════════════════════════

def test_login_requires_2fa_when_enabled(client):
    """After enabling 2FA, login without code returns requires_2fa."""
    _setup_2fa_for(client, "user@example.com", "strongpass123")
    r = _login(client, "user@example.com", "strongpass123")
    assert r.status_code == 401
    data = r.get_json()
    assert data.get("requires_2fa") is True


def test_login_with_valid_totp_code(client):
    """Login with valid TOTP code succeeds."""
    secret, _ = _setup_2fa_for(client, "user@example.com", "strongpass123")
    code = pyotp.TOTP(secret).now()
    r = _login(client, "user@example.com", "strongpass123", totp_code=code)
    assert r.status_code == 200
    assert r.get_json()["ok"] is True


def test_login_with_invalid_totp_code(client):
    """Login with wrong TOTP code fails."""
    _setup_2fa_for(client, "user@example.com", "strongpass123")
    r = _login(client, "user@example.com", "strongpass123", totp_code="000000")
    assert r.status_code == 401


def test_login_with_recovery_code(client):
    """Login with a valid recovery code succeeds and consumes it."""
    secret, recovery_codes = _setup_2fa_for(client, "user@example.com", "strongpass123")
    r = _login(client, "user@example.com", "strongpass123", recovery_code=recovery_codes[0])
    assert r.status_code == 200
    assert r.get_json()["ok"] is True


def test_recovery_code_is_single_use(client):
    """The same recovery code cannot be used twice."""
    secret, recovery_codes = _setup_2fa_for(client, "user@example.com", "strongpass123")
    code = recovery_codes[0]

    # First use: OK
    r = _login(client, "user@example.com", "strongpass123", recovery_code=code)
    assert r.status_code == 200
    client.post("/auth/logout")

    # Second use: FAIL
    r = _login(client, "user@example.com", "strongpass123", recovery_code=code)
    assert r.status_code == 401


def test_recovery_code_count_decreases(client):
    """After using a recovery code, the count drops by 1."""
    secret, recovery_codes = _setup_2fa_for(client, "user@example.com", "strongpass123")

    # Login with code
    r = _login(client, "user@example.com", "strongpass123", recovery_code=recovery_codes[0])
    assert r.status_code == 200

    # Check status
    r = client.get("/auth/2fa/status")
    assert r.get_json()["recovery_codes_remaining"] == 9


# ═══════════════════════════════════════════════════════
# /auth/2fa/disable
# ═══════════════════════════════════════════════════════

def test_2fa_disable_with_totp_code(client):
    """Disable 2FA with password + valid TOTP code."""
    secret, _ = _setup_2fa_for(client, "user@example.com", "strongpass123")
    # Login (with 2FA)
    code = pyotp.TOTP(secret).now()
    _login(client, "user@example.com", "strongpass123", totp_code=code)

    # Disable
    r = client.post("/auth/2fa/disable", json={
        "password": "strongpass123",
        "code": pyotp.TOTP(secret).now(),
    })
    assert r.status_code == 200
    assert r.get_json()["totp_enabled"] is False


def test_2fa_disable_wrong_password(client):
    """Disable fails with wrong password."""
    secret, _ = _setup_2fa_for(client, "user@example.com", "strongpass123")
    code = pyotp.TOTP(secret).now()
    _login(client, "user@example.com", "strongpass123", totp_code=code)

    r = client.post("/auth/2fa/disable", json={
        "password": "wrongpass",
        "code": pyotp.TOTP(secret).now(),
    })
    assert r.status_code == 401


def test_2fa_disable_wrong_code(client):
    """Disable fails with wrong TOTP code."""
    secret, _ = _setup_2fa_for(client, "user@example.com", "strongpass123")
    code = pyotp.TOTP(secret).now()
    _login(client, "user@example.com", "strongpass123", totp_code=code)

    r = client.post("/auth/2fa/disable", json={
        "password": "strongpass123",
        "code": "000000",
    })
    assert r.status_code == 401


# ═══════════════════════════════════════════════════════
# /auth/2fa/recovery/regenerate
# ═══════════════════════════════════════════════════════

def test_2fa_recovery_regenerate(client):
    """Regenerate recovery codes returns 10 new codes."""
    secret, old_codes = _setup_2fa_for(client, "user@example.com", "strongpass123")
    code = pyotp.TOTP(secret).now()
    _login(client, "user@example.com", "strongpass123", totp_code=code)

    r = client.post("/auth/2fa/recovery/regenerate", json={
        "password": "strongpass123",
        "code": pyotp.TOTP(secret).now(),
    })
    assert r.status_code == 200
    new_codes = r.get_json()["recovery_codes"]
    assert len(new_codes) == 10
    # Old codes should be invalid
    assert old_codes[0] not in new_codes


def test_2fa_recovery_regenerate_requires_2fa(client):
    """Cannot regenerate recovery codes when 2FA is disabled."""
    _register(client, "user@example.com", "strongpass123")
    _login(client, "user@example.com", "strongpass123")

    r = client.post("/auth/2fa/recovery/regenerate", json={
        "password": "strongpass123",
        "code": "123456",
    })
    assert r.status_code == 400


# ═══════════════════════════════════════════════════════
# Unit tests for totp module
# ═══════════════════════════════════════════════════════

def test_totp_generate_secret():
    s1 = totp_mod.generate_secret()
    s2 = totp_mod.generate_secret()
    assert s1 != s2
    assert len(s1) >= 16


def test_totp_verify_code():
    secret = totp_mod.generate_secret()
    code = pyotp.TOTP(secret).now()
    assert totp_mod.verify_code(secret, code) is True
    assert totp_mod.verify_code(secret, "000000") is False
    assert totp_mod.verify_code(secret, "abcdef") is False
    assert totp_mod.verify_code("", code) is False


def test_totp_recovery_codes_hash_and_verify():
    codes = totp_mod.generate_recovery_codes()
    assert len(codes) == 10
    hashed = totp_mod.hash_recovery_codes(codes)

    # Verify first code
    ok, remaining_json = totp_mod.verify_recovery_code(hashed, codes[0])
    assert ok is True

    # Verify it was removed
    ok2, _ = totp_mod.verify_recovery_code(remaining_json, codes[0])
    assert ok2 is False

    # Verify a different code still works
    ok3, _ = totp_mod.verify_recovery_code(remaining_json, codes[1])
    assert ok3 is True


def test_totp_count_remaining_recovery_codes():
    codes = totp_mod.generate_recovery_codes()
    hashed = totp_mod.hash_recovery_codes(codes)
    assert totp_mod.count_remaining_recovery_codes(hashed) == 10

    ok, remaining = totp_mod.verify_recovery_code(hashed, codes[0])
    assert totp_mod.count_remaining_recovery_codes(remaining) == 9
