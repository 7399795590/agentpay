"""AgentPay — Encryption tests (task 6)."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# Ensure encryption key is set for tests
os.environ.setdefault(
    "WEBHOOK_ENCRYPTION_KEY",
    "kL9-xQ2_vB8#pR5nW3&cM7zT4!yF6-aaaaaaaa",  # 44 chars test key
)


def test_encrypt_decrypt_roundtrip():
    import crypto
    plaintext = "https://example.com/webhook?token=secret"
    enc = crypto.encrypt(plaintext)
    assert enc != plaintext
    assert crypto.decrypt(enc) == plaintext


def test_encrypt_empty():
    import crypto
    assert crypto.encrypt("") == ""
    assert crypto.decrypt("") == ""


def test_encrypt_none():
    import crypto
    assert crypto.encrypt_webhook_url(None) is None
    assert crypto.decrypt_webhook_url(None) is None


def test_decrypt_legacy_plain_prefix():
    import crypto
    assert crypto.decrypt("plain:hello") == "hello"


def test_encrypt_produces_different_ciphertext():
    """Each encryption produces different token (due to IV)."""
    import crypto
    text = "same-text"
    e1 = crypto.encrypt(text)
    e2 = crypto.encrypt(text)
    assert e1 != e2
    # But both decrypt to same
    assert crypto.decrypt(e1) == crypto.decrypt(e2) == text


def test_decrypt_invalid_token():
    import crypto
    result = crypto.decrypt("not-a-valid-token-xyz")
    assert result == ""


def test_agent_webhook_url_encrypted_at_rest(client, app_ctx):
    """Creating an agent with webhook_url stores it encrypted in DB."""
    from app import app
    from database import db
    from models import Agent

    # Register + login
    client.post("/auth/register", json={"email": "enc@test.com", "password": "strongpass123"})
    client.post("/auth/login", json={"email": "enc@test.com", "password": "strongpass123"})

    csrf = client.get_cookie("ap_csrf")
    url = "https://example.com/webhook?secret=abc123"

    r = client.post(
        "/me/agents",
        json={"name": "encrypted-agent", "webhook_url": url},
        headers={"X-CSRF-Token": csrf.value if csrf else ""},
    )
    assert r.status_code == 201, r.get_json()
    agent_id = r.get_json()["agent"]["id"]

    # Check DB stores encrypted
    with app_ctx.app_context():
        agent = db.session.get(Agent, agent_id)
        assert agent.webhook_url is not None
        assert agent.webhook_url != url  # encrypted!
        assert agent.webhook_url.startswith("gAAAAA")  # Fernet prefix

    # Check API returns plaintext
    r = client.get(f"/agents/{agent_id}")
    assert r.status_code == 200
    returned_url = r.get_json()["agent"]["webhook_url"]
    assert returned_url == url  # decrypts correctly


def test_agent_no_webhook_url_stays_none(client, app_ctx):
    from app import app
    from database import db
    from models import Agent

    client.post("/auth/register", json={"email": "noenc@test.com", "password": "strongpass123"})
    client.post("/auth/login", json={"email": "noenc@test.com", "password": "strongpass123"})

    csrf = client.get_cookie("ap_csrf")
    r = client.post(
        "/me/agents",
        json={"name": "no-webhook"},
        headers={"X-CSRF-Token": csrf.value if csrf else ""},
    )
    assert r.status_code == 201
    agent_id = r.get_json()["agent"]["id"]

    with app_ctx.app_context():
        agent = db.session.get(Agent, agent_id)
        assert agent.webhook_url is None

    r = client.get(f"/agents/{agent_id}")
    assert r.get_json()["agent"]["webhook_url"] is None
