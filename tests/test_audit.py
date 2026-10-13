"""AgentPay — Audit log security tests.

Covers:
- Hash chain creation and verification
- Sanitization of sensitive fields
- Tamper detection
- Pagination and filters
- Access control
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from database import db
from models import AuditLog, sanitize_metadata
import audit


# ===== Sanitization =====

def test_sanitize_removes_password_fields():
    data = {"password": "secret123", "new_password": "new456", "email": "a@b.com"}
    clean = sanitize_metadata(data)
    assert clean["password"] == "[REDACTED]"
    assert clean["new_password"] == "[REDACTED]"
    assert clean["email"] == "a@b.com"


def test_sanitize_removes_api_key_and_token():
    data = {"api_key": "ap_secret", "token": "tok_abc", "user_id": "u1"}
    clean = sanitize_metadata(data)
    assert clean["api_key"] == "[REDACTED]"
    assert clean["token"] == "[REDACTED]"
    assert clean["user_id"] == "u1"


def test_sanitize_nested_dicts():
    data = {"outer": {"password": "x", "keep": "y"}}
    clean = sanitize_metadata(data)
    assert clean["outer"]["password"] == "[REDACTED]"
    assert clean["outer"]["keep"] == "y"


def test_sanitize_case_insensitive():
    data = {"PASSWORD": "x", "Api_Key": "y", "Csrf_Token": "z"}
    clean = sanitize_metadata(data)
    assert clean["PASSWORD"] == "[REDACTED]"
    assert clean["Api_Key"] == "[REDACTED]"
    assert clean["Csrf_Token"] == "[REDACTED]"


# ===== canonical_json =====

def test_canonical_json_sorts_keys():
    a = audit.canonical_json({"b": 2, "a": 1})
    b = audit.canonical_json({"a": 1, "b": 2})
    assert a == b == '{"a":1,"b":2}'


# ===== Hash chain =====

def test_write_audit_secure_creates_hash(app_ctx):
    with app_ctx.app_context():
        entry = audit.write_audit_secure(
            "test.action",
            actor="test@example.com",
            data="hello",
        )
        db.session.commit()
        assert entry.record_hash is not None
        assert len(entry.record_hash) == 64  # SHA-256 hex
        # First entry has no prev_hash
        assert entry.prev_hash is None


def test_hash_chain_links_entries(app_ctx):
    with app_ctx.app_context():
        # Create first
        e1 = audit.write_audit_secure("test.first", actor="a@b.com")
        db.session.commit()
        h1 = e1.record_hash

        # Create second
        e2 = audit.write_audit_secure("test.second", actor="a@b.com")
        db.session.commit()

        assert e2.prev_hash == h1
        assert e2.record_hash != h1


def test_verify_chain_ok(app_ctx):
    with app_ctx.app_context():
        for i in range(5):
            audit.write_audit_secure(f"test.event.{i}", actor="a@b.com")
        db.session.commit()

        result = audit.verify_audit_chain()
        assert result["ok"] is True
        assert result["checked"] >= 5
        assert result["broken_at"] is None


def test_verify_chain_detects_tampering(app_ctx):
    with app_ctx.app_context():
        for i in range(3):
            audit.write_audit_secure(f"test.tamper.{i}", actor="a@b.com")
        db.session.commit()

        # Tamper: modify an action
        entry = AuditLog.query.filter_by(action="test.tamper.1").first()
        entry.action = "test.tamper.1.MODIFIED"
        db.session.commit()

        result = audit.verify_audit_chain()
        assert result["ok"] is False
        assert "mismatch" in result["reason"].lower()


def test_verify_chain_detects_deletion(app_ctx):
    with app_ctx.app_context():
        # Create 4, delete middle
        for i in range(4):
            audit.write_audit_secure(f"test.delete.{i}", actor="a@b.com")
        db.session.commit()

        # Delete entry 2 (in the middle)
        entry = AuditLog.query.filter_by(action="test.delete.2").first()
        db.session.delete(entry)
        db.session.commit()

        result = audit.verify_audit_chain()
        # Chain should break because prev_hash pointers won't match
        assert result["ok"] is False


# ===== Checkpoint =====

def test_checkpoint_returns_last_hash(app_ctx):
    with app_ctx.app_context():
        audit.write_audit_secure("test.checkpoint", actor="a@b.com")
        db.session.commit()

        cp = audit.get_chain_checkpoint()
        assert cp["last_id"] is not None
        assert cp["last_hash"] is not None
        assert cp["total"] >= 1


# ===== Sanitization on write =====

def test_write_secure_sanitizes_metadata(app_ctx):
    with app_ctx.app_context():
        entry = audit.write_audit_secure(
            "test.sensitive",
            actor="a@b.com",
            password="should_be_redacted",
            api_key="ap_secret",
            safe_field="visible",
        )
        db.session.commit()

        import json
        meta = json.loads(entry.metadata_json)
        assert meta["password"] == "[REDACTED]"
        assert meta["api_key"] == "[REDACTED]"
        assert meta["safe_field"] == "visible"


# ===== Endpoint: /admin/audit =====

def _register_login(client, email="admin@test.com", password="strongpass123"):
    client.post("/auth/register", json={"email": email, "password": password})
    client.post("/auth/login", json={"email": email, "password": password})


def test_admin_audit_requires_auth(client):
    r = client.get("/admin/audit")
    assert r.status_code == 401


def test_admin_audit_returns_entries(client):
    _register_login(client)
    r = client.get("/admin/audit")
    assert r.status_code == 200
    data = r.get_json()
    assert "entries" in data
    assert "total" in data
    assert "limit" in data


def test_admin_audit_pagination(client):
    _register_login(client)
    r = client.get("/admin/audit?limit=5&offset=0")
    assert r.status_code == 200
    data = r.get_json()
    assert data["limit"] == 5
    assert data["offset"] == 0


def test_admin_audit_rejects_bad_limit(client):
    _register_login(client)
    r = client.get("/admin/audit?limit=abc")
    assert r.status_code == 400


def test_admin_audit_caps_limit_at_200(client):
    _register_login(client)
    r = client.get("/admin/audit?limit=99999")
    assert r.status_code == 200
    assert r.get_json()["limit"] == 200


def test_admin_audit_filter_by_action(client):
    _register_login(client)
    r = client.get("/admin/audit?action=auth.login.success")
    assert r.status_code == 200


def test_admin_audit_filter_bad_status(client):
    _register_login(client)
    r = client.get("/admin/audit?status=invalid")
    assert r.status_code == 400


def test_admin_audit_filter_bad_since(client):
    _register_login(client)
    r = client.get("/admin/audit?since=notanumber")
    assert r.status_code == 400


# ===== Endpoint: /admin/audit/verify =====

def test_admin_audit_verify_requires_auth(client):
    r = client.get("/admin/audit/verify")
    assert r.status_code == 401


def test_admin_audit_verify_ok(client):
    _register_login(client)
    r = client.get("/admin/audit/verify")
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert data["broken_at"] is None


# ===== Endpoint: /admin/audit/checkpoint =====

def test_admin_audit_checkpoint(client):
    _register_login(client)
    r = client.get("/admin/audit/checkpoint")
    assert r.status_code == 200
    data = r.get_json()
    assert "last_id" in data
    assert "last_hash" in data
    assert "total" in data


# ===== Privacy =====

def test_audit_never_stores_password(client, app_ctx):
    """Registering + login must never store the password in audit."""
    _register_login(client)
    # Inspect DB inside app context
    from models import AuditLog
    with app_ctx.app_context():
        entries = AuditLog.query.all()
        for e in entries:
            if e.metadata_json:
                assert "strongpass123" not in e.metadata_json
