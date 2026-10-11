"""AgentPay — Main Flask app."""
import time
from flask import Flask, request, jsonify
from flask_cors import CORS

from database import db, init_db
from models import Agent, Transaction

app = Flask(__name__)
CORS(app)
init_db(app)


# ===== Helpers =====

def error(msg, code=400):
    return jsonify({"ok": False, "error": msg}), code


def success(data=None, code=200):
    return jsonify({"ok": True, **(data or {})}), code


def find_agent(agent_id):
    return Agent.query.get(agent_id)


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
    agent = Agent(name=name)
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
    return success({"agent": agent.to_dict(), "transaction": tx.to_dict()})


@app.route("/agents/<agent_id>/charge", methods=["POST"])
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
    return success({"agent": agent.to_dict(), "transaction": tx.to_dict()})


@app.route("/agents/<agent_id>/transactions")
def list_transactions(agent_id):
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    limit = min(int(request.args.get("limit", 20)), 100)
    txs = Transaction.query.filter_by(agent_id=agent.id).order_by(Transaction.id.desc()).limit(limit).all()
    return success({"agent_id": agent.id, "transactions": [t.to_dict() for t in txs], "count": len(txs)})


if __name__ == "__main__":
    print("AgentPay starting on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
