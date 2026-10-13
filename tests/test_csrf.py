"""AgentPay — CSRF protection tests (bypass TESTING mode).

These tests directly test the CSRF logic without relying on the test
bypass that require_csrf uses in TESTING mode.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from csrf import generate_csrf_token, check_csrf, CSRF_COOKIE_NAME, CSRF_HEADER_NAME


# ===== Unit tests on check_csrf =====

def test_check_csrf_allows_safe_methods(app_ctx):
    """GET/HEAD/OPTIONS are always allowed."""
    from flask import request
    # Simulate via request context
    with app_ctx.test_request_context("/", method="GET"):
        assert check_csrf() is True


def test_check_csrf_blocks_post_without_tokens(app_ctx):
    with app_ctx.test_request_context("/", method="POST"):
        assert check_csrf() is False


def test_check_csrf_blocks_post_with_only_cookie(app_ctx):
    token = generate_csrf_token()
    with app_ctx.test_request_context("/", method="POST"):
        from flask import request
        request.cookies = {CSRF_COOKIE_NAME: token}
        # No header
        assert check_csrf() is False


def test_check_csrf_blocks_post_with_mismatched_tokens(app_ctx):
    token1 = generate_csrf_token()
    token2 = generate_csrf_token()
    with app_ctx.test_request_context(
        "/",
        method="POST",
        headers={CSRF_HEADER_NAME: token2},
    ):
        from flask import request
        request.cookies = {CSRF_COOKIE_NAME: token1}
        assert check_csrf() is False


def test_check_csrf_allows_post_with_matching_tokens(app_ctx):
    token = generate_csrf_token()
    with app_ctx.test_request_context(
        "/",
        method="POST",
        headers={CSRF_HEADER_NAME: token},
    ):
        from flask import request
        request.cookies = {CSRF_COOKIE_NAME: token}
        assert check_csrf() is True


# ===== Token generation =====

def test_generate_csrf_token_is_random():
    t1 = generate_csrf_token()
    t2 = generate_csrf_token()
    assert t1 != t2
    assert len(t1) >= 32


# ===== Login/Logout set/clear CSRF cookie =====

def test_login_sets_csrf_cookie(client):
    client.post("/auth/register", json={
        "email": "csrftest@example.com",
        "password": "strongpass123"
    })
    r = client.post("/auth/login", json={
        "email": "csrftest@example.com",
        "password": "strongpass123"
    })
    assert r.status_code == 200
    # Multiple Set-Cookie headers: use getlist
    all_cookies = r.headers.getlist("Set-Cookie")
    combined = " ".join(all_cookies)
    assert CSRF_COOKIE_NAME in combined, f"CSRF cookie not found in: {all_cookies}"


def test_logout_clears_csrf_cookie(client):
    client.post("/auth/register", json={
        "email": "csrflogout@example.com",
        "password": "strongpass123"
    })
    client.post("/auth/login", json={
        "email": "csrflogout@example.com",
        "password": "strongpass123"
    })
    r = client.post("/auth/logout")
    assert r.status_code == 200
    all_cookies = r.headers.getlist("Set-Cookie")
    combined = " ".join(all_cookies)
    assert CSRF_COOKIE_NAME in combined, f"CSRF cookie not cleared in: {all_cookies}"
