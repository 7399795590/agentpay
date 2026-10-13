"""AgentPay — Main Flask app."""
import time
from flask import Flask, request, jsonify
from flask_cors import CORS

from database import db, init_db
from models import Agent, Transaction, Subscription, AuditLog, write_audit
from webhooks import fire_webhook
from ratelimit import limit, limiter
from logging_utils import setup_logging, generate_request_id
import stripe_integration
from security import safe_compare, get_allowed_origins, apply_security_headers

app = Flask(__name__)

# Restricted CORS: only known origins
CORS(app, resources={r"/*": {"origins": get_allowed_origins()}},
     supports_credentials=False,
     allow_headers=["Content-Type", "Authorization", "Idempotency-Key", "Stripe-Signature"],
     methods=["GET", "POST", "DELETE", "OPTIONS"])

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
    """Add request ID + security headers to every response."""
    from flask import g
    if hasattr(g, "request_id"):
        response.headers["X-Request-ID"] = g.request_id
    # Apply security headers (HSTS, X-Frame-Options, etc.)
    apply_security_headers(response)
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
        if not safe_compare(agent.api_key, token):
            return error("API key does not match this agent", 403)
        return view_func(*args, **kwargs)
    return wrapper


def key_ip(request, **kwargs):
    """Rate limit key: by client IP."""
    return f"ip:{request.remote_addr}"


def require_admin(view_func):
    """Decorator: requires ADMIN_API_KEY in Authorization header."""
    from functools import wraps
    import os
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        admin_key = os.environ.get("ADMIN_API_KEY", "")
        if not admin_key:
            return error("Admin API is disabled (ADMIN_API_KEY not set)", 503)
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return error("Missing Authorization (use: Bearer <ADMIN_API_KEY>)", 401)
        token = auth[7:].strip()
        if not safe_compare(token, admin_key):
            # Log failed admin attempts (security signal)
            try:
                from models import write_audit
                write_audit(
                    "admin.auth.fail",
                    actor="unknown",
                    ip=request.remote_addr,
                    user_agent=request.headers.get("User-Agent", "")[:200],
                    status="error",
                    path=request.path,
                )
                db.session.commit()
            except Exception:
                db.session.rollback()
            return error("Invalid admin key", 403)
        return view_func(*args, **kwargs)
    return wrapper


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
    currency = (data.get("currency") or "USD").upper()
    from models import SUPPORTED_CURRENCIES
    if currency not in SUPPORTED_CURRENCIES:
        return error(f"Unsupported currency. Choose from: {SUPPORTED_CURRENCIES}")
    agent = Agent(name=name, webhook_url=webhook_url, currency=currency)
    db.session.add(agent)
    db.session.flush()
    write_audit("agent.create", agent_id=agent.id, ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "")[:200],
                name=name, currency=currency, webhook_url=webhook_url or None)
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
    db.session.flush()
    write_audit("topup", agent_id=agent.id, ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "")[:200],
                actor=agent.api_key[:10] + "...",
                amount=amount, tx_id=tx.id, description=tx.description)
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
    db.session.flush()
    write_audit("charge", agent_id=agent.id, ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "")[:200],
                actor=agent.api_key[:10] + "...",
                amount=amount, tx_id=tx.id, description=tx.description)
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


# ===== API Documentation =====

@app.route("/openapi.json")
def openapi_spec():
    """Serve OpenAPI 3.0 spec."""
    from pathlib import Path
    spec_path = Path(__file__).parent / "openapi.json"
    if not spec_path.exists():
        return error("OpenAPI spec not found", 404)
    return app.response_class(
        response=spec_path.read_text(encoding="utf-8"),
        status=200,
        mimetype="application/json",
    )


@app.route("/docs")
def swagger_ui():
    """Swagger UI — interactive API docs."""
    html = """<!DOCTYPE html>
<html>
<head>
  <title>AgentPay API — Docs</title>
  <meta charset="UTF-8">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
window.onload = () => {
  window.ui = SwaggerUIBundle({
    url: "/openapi.json",
    dom_id: "#swagger-ui",
    deepLinking: true,
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
    layout: "BaseLayout",
  });
};
</script>
</body>
</html>"""
    return app.response_class(response=html, status=200, mimetype="text/html")


@app.route("/redoc")
def redoc_ui():
    """ReDoc — alternative API docs."""
    html = """<!DOCTYPE html>
<html>
<head>
  <title>AgentPay API — ReDoc</title>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
  <redoc spec-url="/openapi.json"></redoc>
  <script src="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"></script>
</body>
</html>"""
    return app.response_class(response=html, status=200, mimetype="text/html")


# ===== Admin API =====

@app.route("/admin/stats")
@require_admin
def admin_stats():
    """Get overall system stats."""
    total_agents = Agent.query.count()
    total_txs = Transaction.query.count()
    total_subs = Subscription.query.count()
    active_subs = Subscription.query.filter_by(status="active").count()
    # Sum balances grouped by currency
    balances = {}
    for agent in Agent.query.all():
        cur = agent.currency
        balances[cur] = balances.get(cur, 0) + agent.balance
    # Sum by transaction type
    tx_by_type = {}
    for tx in Transaction.query.all():
        tx_by_type[tx.type] = tx_by_type.get(tx.type, 0) + tx.amount
    return success({
        "agents": {"total": total_agents},
        "transactions": {"total": total_txs, "by_type": tx_by_type},
        "subscriptions": {"total": total_subs, "active": active_subs},
        "balances": balances,
    })


@app.route("/admin/agents")
@require_admin
def admin_list_agents():
    """List all agents (with optional search)."""
    q = request.args.get("q", "").strip()
    try:
        limit_n = min(int(request.args.get("limit", 50)), 500)
    except ValueError:
        return error("Invalid limit")
    query = Agent.query
    if q:
        query = query.filter(Agent.name.like(f"%{q}%"))
    agents = query.order_by(Agent.created_at.desc()).limit(limit_n).all()
    return success({"agents": [a.to_dict() for a in agents], "count": len(agents)})


@app.route("/admin/agents/<agent_id>", methods=["DELETE"])
@require_admin
def admin_delete_agent(agent_id):
    """Delete an agent and all its transactions/subscriptions."""
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    Subscription.query.filter_by(agent_id=agent.id).delete()
    Transaction.query.filter_by(agent_id=agent.id).delete()
    db.session.delete(agent)
    write_audit("admin.agent.delete", agent_id=agent_id,
                ip=request.remote_addr,
                actor="admin")
    db.session.commit()
    return success({"deleted": agent_id})


@app.route("/admin/agents/<agent_id>/balance", methods=["POST"])
@require_admin
def admin_set_balance(agent_id):
    """Set an agent's balance directly (admin override)."""
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    data = request.get_json(silent=True) or {}
    new_balance = data.get("balance")
    if not isinstance(new_balance, int) or new_balance < 0:
        return error("balance must be a non-negative integer (in smallest unit)")
    old_balance = agent.balance
    diff = new_balance - old_balance
    agent.balance = new_balance
    tx = Transaction(
        agent_id=agent.id,
        type="admin_adjust" if diff >= 0 else "admin_adjust",
        amount=abs(diff),
        description=f"Admin: {old_balance} -> {new_balance}",
    )
    db.session.add(tx)
    db.session.flush()
    write_audit("admin.balance.set", agent_id=agent.id,
                ip=request.remote_addr, actor="admin",
                old_balance=old_balance, new_balance=new_balance,
                tx_id=tx.id)
    db.session.commit()
    return success({"agent": agent.to_dict(), "transaction": tx.to_dict()})


# ===== Audit Log =====

@app.route("/admin/audit")
@require_admin
@limit(key_ip, "transactions")
def list_audit():
    """List recent audit log entries. Admin-only in production."""
    try:
        limit_n = min(int(request.args.get("limit", 50)), 500)
    except ValueError:
        return error("Invalid limit")
    action = request.args.get("action")
    agent_id = request.args.get("agent_id")
    q = AuditLog.query
    if action:
        q = q.filter_by(action=action)
    if agent_id:
        q = q.filter_by(agent_id=agent_id)
    entries = q.order_by(AuditLog.id.desc()).limit(limit_n).all()
    return success({"entries": [e.to_dict() for e in entries], "count": len(entries)})


# ===== Refunds =====

@app.route("/agents/<agent_id>/refund", methods=["POST"])
@limit(key_agent, "topup")
@require_api_key
def refund_transaction(agent_id):
    """Refund a previous charge by creating a reverse transaction."""
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    data = request.get_json(silent=True) or {}
    tx_id = data.get("transaction_id")
    if not isinstance(tx_id, int):
        return error("transaction_id (integer) is required")
    reason = (data.get("reason") or "").strip()[:200]

    original = db.session.get(Transaction, tx_id)
    if not original or original.agent_id != agent.id:
        return error("Transaction not found for this agent", 404)
    if original.type != "charge":
        return error("Only 'charge' transactions can be refunded")
    # Prevent double refunds (check by prefix "Refund:{id}")
    prefix = f"Refund:{original.id}"
    already = Transaction.query.filter(
        Transaction.agent_id == agent.id,
        Transaction.type == "refund",
        Transaction.description.like(prefix + "%"),
    ).first()
    if already:
        return error("Already refunded", 409)

    agent.balance += original.amount
    refund = Transaction(
        agent_id=agent.id,
        type="refund",
        amount=original.amount,
        description=f"Refund:{original.id}" + (f" ({reason})" if reason else ""),
    )
    db.session.add(refund)
    db.session.flush()  # get refund.id without committing
    write_audit("refund", agent_id=agent.id, ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "")[:200],
                metadata={"refund_tx_id": refund.id, "original_tx_id": original.id,
                          "amount": original.amount, "reason": reason})
    db.session.commit()
    return success({"agent": agent.to_dict(), "refund": refund.to_dict(), "original_tx_id": original.id})


# ===== Subscriptions =====

INTERVALS = {
    "daily": 86400,
    "weekly": 604800,
    "monthly": 2592000,
    "yearly": 31536000,
}


@app.route("/agents/<agent_id>/subscriptions/create", methods=["POST"])
@limit(key_agent, "topup")
@require_api_key
def create_subscription(agent_id):
    """Create a recurring subscription for an agent."""
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name or len(name) > 100:
        return error("Invalid name (required, max 100 chars)")
    amount = data.get("amount")
    if not isinstance(amount, int) or amount <= 0 or amount > 1_000_000:
        return error("Invalid amount (positive integer, max 1,000,000)")
    interval_key = (data.get("interval") or "monthly").lower()
    if interval_key not in INTERVALS:
        return error(f"Invalid interval. Choose from: {list(INTERVALS.keys())}")
    interval_seconds = INTERVALS[interval_key]
    now = int(time.time())
    sub = Subscription(
        agent_id=agent.id,
        name=name,
        amount=amount,
        interval_seconds=interval_seconds,
        next_charge_at=now + interval_seconds,
    )
    db.session.add(sub)
    db.session.flush()  # get sub.id without committing
    write_audit("subscription.create", agent_id=agent.id, ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "")[:200],
                metadata={"sub_id": sub.id, "name": name, "amount": amount,
                          "interval_seconds": interval_seconds})
    db.session.commit()
    return success({"subscription": sub.to_dict()}, 201)


@app.route("/agents/<agent_id>/subscriptions")
@limit(key_agent, "transactions")
@require_api_key
def list_subscriptions(agent_id):
    """List agent's subscriptions."""
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    subs = Subscription.query.filter_by(agent_id=agent.id).order_by(Subscription.id.desc()).all()
    return success({"subscriptions": [x.to_dict() for x in subs], "count": len(subs)})


@app.route("/agents/<agent_id>/subscriptions/<int:sub_id>/cancel", methods=["POST"])
@limit(key_agent, "topup")
@require_api_key
def cancel_subscription(agent_id, sub_id):
    """Cancel a subscription."""
    agent = find_agent(agent_id)
    if not agent:
        return error("Agent not found", 404)
    sub = db.session.get(Subscription, sub_id)
    if not sub or sub.agent_id != agent.id:
        return error("Subscription not found", 404)
    if sub.status == "cancelled":
        return success({"subscription": sub.to_dict(), "message": "Already cancelled"})
    sub.status = "cancelled"
    sub.cancelled_at = int(time.time())
    write_audit("subscription.cancel", agent_id=agent.id, ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", "")[:200],
                metadata={"sub_id": sub.id, "name": sub.name, "amount": sub.amount})
    db.session.commit()
    return success({"subscription": sub.to_dict()})


@app.route("/admin/run-billing", methods=["POST"])
@require_admin
def run_billing():
    """Run billing for all due subscriptions. Admin-only in production."""
    now = int(time.time())
    due = Subscription.query.filter(
        Subscription.status == "active",
        Subscription.next_charge_at <= now,
    ).all()
    processed = []
    failed = []
    for sub in due:
        agent = db.session.get(Agent, sub.agent_id)
        if not agent:
            sub.status = "cancelled"
            db.session.commit()
            failed.append({"sub_id": sub.id, "reason": "agent_missing"})
            continue
        if agent.balance < sub.amount:
            failed.append({"sub_id": sub.id, "reason": "insufficient_balance"})
            continue
        agent.balance -= sub.amount
        tx = Transaction(
            agent_id=agent.id,
            type="charge",
            amount=sub.amount,
            description=f"Subscription: {sub.name} (#{sub.id})",
        )
        sub.next_charge_at = now + sub.interval_seconds
        db.session.add(tx)
        db.session.flush()  # get tx.id without committing
        write_audit("subscription.billing", agent_id=agent.id,
                    metadata={"sub_id": sub.id, "name": sub.name,
                              "amount": sub.amount, "tx_id": tx.id})
        db.session.commit()
        processed.append({"sub_id": sub.id, "amount": sub.amount, "tx_id": tx.id})
    return success({"processed": processed, "failed": failed, "total": len(due)})


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
