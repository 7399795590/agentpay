"""AgentPay — Main Flask app."""
import time
from flask import Flask, request, jsonify
from flask_cors import CORS

from database import db, init_db
from models import Agent, Transaction
from webhooks import fire_webhook
from ratelimit import limit, limiter
from logging_utils import setup_logging, generate_request_id
import stripe_integration

app = Flask(__name__)
CORS(app)
init_db(app)

# Setup structured logging
setup_logging(app)


# ===== Request ID + Error Handlers =====

@app.before_request
def before_request():
    """Generate a request ID and store it in g."""
    from flask import g
    g.request_id = generate_request_id()


@app.after_request
def after_request(response):
    """Add request ID to response headers."""
    from flask import g
    if hasattr(g, "request_id"):
        response.headers["X-Request-ID"] = g.request_id
    return response


@app.errorhandler(400)
def handle_400(e):
    return jsonify({"ok": False, "error": "Bad request", "detail": str(e)}), 400


@app.errorhandler(401)
def handle_401(e):
    return jsonify({"ok": False, "error": "Unauthorized"}), 401


@app.errorhandler(403)
def handle_403(e):
    return jsonify({"ok": False, "error": "Forbidden"}), 403


@app.errorhandler(404)
def handle_404(e):
    return jsonify({"ok": False, "error": "Not found"}), 404


@app.errorhandler(405)
def handle_405(e):
    return jsonify({"ok": False, "error": "Method not allowed"}), 405


@app.errorhandler(429)
def handle_429(e):
    return jsonify({"ok": False, "error": "Too many requests"}), 429


@app.errorhandler(500)
def handle_500(e):
    from flask import g
    app.logger.error(f"Internal error: {e}", exc_info=True)
    return jsonify({
        "ok": False,
        "error": "Internal server error",
        "request_id": getattr(g, "request_id", None),
    }), 500


@app.errorhandler(Exception)
def handle_unexpected(e):
    from flask import g
    app.logger.error(f"Unexpected error: {e}", exc_info=True)
    return jsonify({
        "ok": False,
        "error": "Internal server error",
        "request_id": getattr(g, "request_id", None),
    }), 500


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


def key_ip(request, **kwargs):
    """Rate limit key: by client IP."""
    return f"ip:{request.remote_addr}"


def key_agent(request, **kwargs):
    """Rate limit key: by agent_id."""
    return f"agent:{kwargs.get('agent_id', 'unknown')}"


# ===== Routes =====

@app.route("/health")
def health():
    return success({"service": "agentpay", "version": "0.1.0", "time": int(time.time())})


@app.route("/agents/create", methods=["POST"])
@limit(key_ip, "create")
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
@limit(key_ip, "get_agent")
def get_agent(agent_id):
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    return success({"agent": agent.to_dict()})


@app.route("/agents/<agent_id>/topup", methods=["POST"])
@limit(key_agent, "topup")
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
@limit(key_agent, "charge")
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
@limit(key_agent, "transactions")
@require_api_key
def list_transactions(agent_id):
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    limit = min(int(request.args.get("limit", 20)), 100)
    txs = Transaction.query.filter_by(agent_id=agent.id).order_by(Transaction.id.desc()).limit(limit).all()
    return success({"agent_id": agent.id, "transactions": [t.to_dict() for t in txs], "count": len(txs)})


# ===== Stripe Endpoints =====

@app.route("/agents/<agent_id>/stripe/checkout", methods=["POST"])
@limit(key_agent, "topup")
@require_api_key
def stripe_checkout(agent_id):
    """Create a Stripe Checkout session to top up the agent."""
    if not stripe_integration.is_configured():
        return error("Stripe not configured on server", 503)
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    data = request.get_json(silent=True) or {}
    amount_cents = data.get("amount_cents")
    if not isinstance(amount_cents, int):
        return error("amount_cents must be an integer (USD cents, min 100)")
    success_url = data.get("success_url") or "https://agentpay-pearl.vercel.app/?stripe=success"
    cancel_url = data.get("cancel_url") or "https://agentpay-pearl.vercel.app/?stripe=cancel"
    try:
        session = stripe_integration.create_checkout_session(
            agent, amount_cents, success_url, cancel_url
        )
    except (ValueError, RuntimeError) as e:
        return error(str(e), 400)
    except Exception as e:
        app.logger.error(f"Stripe error: {e}", exc_info=True)
        return error("Stripe error", 500)
    return success({"checkout": session})


@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    """Handle Stripe webhook events."""
    if not stripe_integration.is_configured():
        return error("Stripe not configured", 503)
    payload = request.get_data()
    sig = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe_integration.verify_webhook(payload, sig)
    except Exception as e:
        app.logger.warning(f"Stripe webhook signature failed: {e}")
        return error("Invalid signature", 400)
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        ok, msg, tx = stripe_integration.credit_agent_from_checkout(session)
        if ok:
            app.logger.info(f"Stripe webhook OK: {msg}")
        else:
            app.logger.warning(f"Stripe webhook failed: {msg}")
    return success({"received": True})


@app.route("/stripe/config")
def stripe_config():
    """Return Stripe publishable key (for frontend) or 'not configured'."""
    import os
    pk = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
    return success({
        "configured": stripe_integration.is_configured(),
        "publishable_key": pk if pk else None,
    })


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    print(f"AgentPay starting on port {port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
