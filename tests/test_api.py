"""AgentPay — API tests."""
import os
import sys
import tempfile
from pathlib import Path

_tmpdir = tempfile.mkdtemp(prefix="agentpay_test_")
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import app
from database import db


client = None


def setup_module():
    global client
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + _tmpdir + "/test.db"
    with app.app_context():
        db.drop_all()
        db.create_all()
    client = app.test_client()


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert data["service"] == "agentpay"


def test_create_agent():
    r = client.post("/agents/create", json={"name": "test-agent"})
    assert r.status_code == 201
    data = r.get_json()
    assert data["ok"] is True
    assert "agent" in data
    assert "api_key" in data
    assert data["agent"]["name"] == "test-agent"
    assert data["agent"]["balance"] == 0
    assert data["api_key"].startswith("ap_")


def test_create_agent_invalid_name():
    r = client.post("/agents/create", json={"name": ""})
    assert r.status_code == 400
    r = client.post("/agents/create", json={})
    assert r.status_code == 400


def test_full_cycle():
    r = client.post("/agents/create", json={"name": "cycle-agent"})
    agent_id = r.get_json()["agent"]["id"]

    r = client.get("/agents/" + agent_id)
    assert r.get_json()["agent"]["balance"] == 0

    r = client.post("/agents/" + agent_id + "/topup", json={"amount": 500})
    assert r.status_code == 200
    assert r.get_json()["agent"]["balance"] == 500

    r = client.post("/agents/" + agent_id + "/charge", json={"amount": 30})
    assert r.status_code == 200
    assert r.get_json()["agent"]["balance"] == 470

    r = client.get("/agents/" + agent_id + "/transactions")
    data = r.get_json()
    assert data["count"] == 2
    types = [t["type"] for t in data["transactions"]]
    assert "topup" in types
    assert "charge" in types


def test_insufficient_balance():
    r = client.post("/agents/create", json={"name": "poor-agent"})
    agent_id = r.get_json()["agent"]["id"]

    r = client.post("/agents/" + agent_id + "/charge", json={"amount": 100})
    assert r.status_code == 402
    assert "Insufficient" in r.get_json()["error"]


def test_agent_not_found():
    r = client.get("/agents/nonexistent")
    assert r.status_code == 404


def test_invalid_amount():
    r = client.post("/agents/create", json={"name": "bad-amount"})
    agent_id = r.get_json()["agent"]["id"]

    r = client.post("/agents/" + agent_id + "/topup", json={"amount": -10})
    assert r.status_code == 400

    r = client.post("/agents/" + agent_id + "/topup", json={"amount": 0})
    assert r.status_code == 400

    r = client.post("/agents/" + agent_id + "/topup", json={"amount": "100"})
    assert r.status_code == 400
