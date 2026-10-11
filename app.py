"""AgentPay — Main Flask app."""
import time
from flask import Flask, request, jsonify
from flask_cors import CORS

from database import db, init_db
from models import Agent, Transaction
from webhooks import fire_webhook

app = Flask(__name__)
CORS(app)
init_db(app)


# ===== Helpers =====

def error(msg, code=400):
    return jsonify({"ok": False, "error": msg}), code


def success(data=None, code=200):
    return jsonify({"ok": True, **(data or {})}), code


def find_agent(agent_id):
    return db.session.get(Agent, agent_id)


def require_api_key(view_func):
    """Decorator: verifies Bearer token matches the agent in the URL."""
    from functools import wraps
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return error("Missing or invalid Authorization header (use: Bearer ap_...)", 401)
        token = auth[7:].strip()
        if not token.startswith("ap_"):
            return error("Invalid API key format", 401)
        agent_id = kwargs.get("agent_id")
        agent = find_agent(agent_id)
        if not agent:
            return error("Agent not found", 404)
        if agent.api_key != token:
            return error("API key does not match this agent", 403)
        return view_func(*args, **kwargs)
    return wrapper


# ===== Routes =====

@app.route("/health")
def health():
    return success({"service": "agentpay", "version": "0.1.0", "time": int(time.time())})


@app.route("/agents/create", methods=["POST"])
def create_agent():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name or len(name) > 100:
        return error("Invalid name (required, max 100 chars)")
    webhook_url = (data.get("webhook_url") or "").strip() or None
    if webhook_url and not webhook_url.startswith(("http://", "https://")):
        return error("webhook_url must start with http:// or https://")
    agent = Agent(name=name, webhook_url=webhook_url)
    db.session.add(agent)
    db.session.commit()
    return success({"agent": agent.to_dict(), "api_key": agent.api_key}, 201)


@app.route("/agents/<agent_id>")
def get_agent(agent_id):
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    return success({"agent": agent.to_dict()})


@app.route("/agents/<agent_id>/topup", methods=["POST"])
@require_api_key
def topup(agent_id):
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    data = request.get_json(silent=True) or {}
    amount = data.get("amount")
    if not isinstance(amount, int) or amount <= 0 or amount > 1_000_000:
        return error("Invalid amount (must be positive integer in cents, max 1,000,000)")
    agent.balance += amount
    tx = Transaction(agent_id=agent.id, type="topup", amount=amount,
                     description=data.get("description", "Top-up"))
    db.session.add(tx)
    db.session.commit()
    fire_webhook(agent, "topup", tx)
    return success({"agent": agent.to_dict(), "transaction": tx.to_dict()})


@app.route("/agents/<agent_id>/charge", methods=["POST"])
@require_api_key
def charge(agent_id):
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    data = request.get_json(silent=True) or {}
    amount = data.get("amount")
    if not isinstance(amount, int) or amount <= 0 or amount > 1_000_000:
        return error("Invalid amount (must be positive integer in cents, max 1,000,000)")
    if agent.balance < amount:
        return error(f"Insufficient balance ({agent.balance} < {amount})", 402)
    agent.balance -= amount
    tx = Transaction(agent_id=agent.id, type="charge", amount=amount,
                     description=data.get("description", "Charge"))
    db.session.add(tx)
    db.session.commit()
    fire_webhook(agent, "charge", tx)
    return success({"agent": agent.to_dict(), "transaction": tx.to_dict()})


@app.route("/agents/<agent_id>/transactions")
@require_api_key
def list_transactions(agent_id):
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    limit = min(int(request.args.get("limit", 20)), 100)
    txs = Transaction.query.filter_by(agent_id=agent.id).order_by(Transaction.id.desc()).limit(limit).all()
    return success({"agent_id": agent.id, "transactions": [t.to_dict() for t in txs], "count": len(txs)})


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    print(f"AgentPay starting on port {port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
