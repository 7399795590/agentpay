"""AgentPay — Stripe integration.

Handles:
- Creating Stripe Checkout sessions for top-ups
- Verifying Stripe webhook signatures
- Adding balance to agents upon successful payment
"""
import os
import stripe
import logging

from database import db
from models import Agent, Transaction

log = logging.getLogger(__name__)

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_CURRENCY = "usd"

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY


def is_configured() -> bool:
    """Is Stripe configured?"""
    return bool(STRIPE_SECRET_KEY)


def create_checkout_session(agent, amount_cents: int, success_url: str, cancel_url: str) -> dict:
    """Create a Stripe Checkout session for topping up an agent's balance.

    Returns the session dict (includes 'url' for redirect).
    """
    if not is_configured():
        raise RuntimeError("Stripe is not configured (STRIPE_SECRET_KEY missing)")
    if not isinstance(amount_cents, int) or amount_cents < 100:
        raise ValueError("Minimum top-up is $1.00 (100 cents)")
    if amount_cents > 1_000_000:
        raise ValueError("Maximum top-up is $10,000 (1,000,000 cents)")

    session = stripe.checkout.Session.create(
        mode="payment",
        line_items=[{
            "price_data": {
                "currency": STRIPE_CURRENCY,
                "product_data": {
                    "name": f"AgentPay top-up ({agent.name})",
                    "description": f"Add ${amount_cents / 100:.2f} to agent {agent.id}",
                },
                "unit_amount": amount_cents,
            },
            "quantity": 1,
        }],
        success_url=success_url,
        cancel_url=cancel_url,
        client_reference_id=agent.id,
        metadata={
            "agent_id": agent.id,
            "amount_cents": str(amount_cents),
        },
    )
    return {
        "id": session.id,
        "url": session.url,
        "amount_cents": amount_cents,
    }


def verify_webhook(payload: bytes, signature: str) -> dict:
    """Verify a Stripe webhook signature and return the event dict."""
    if not STRIPE_WEBHOOK_SECRET:
        raise RuntimeError("STRIPE_WEBHOOK_SECRET not set")
    event = stripe.Webhook.construct_event(
        payload, signature, STRIPE_WEBHOOK_SECRET
    )
    return event


def credit_agent_from_checkout(session) -> tuple:
    """Credit the agent's balance from a successful checkout session.

    Accepts Stripe Session object OR dict.
    Returns (success, message, transaction_or_none).
    """
    # Convert Stripe object → dict (SDK v7+ returns objects, not dicts)
    if not isinstance(session, dict):
        session = session.to_dict() if hasattr(session, "to_dict") else dict(session)

    metadata = session.get("metadata") or {}
    agent_id = metadata.get("agent_id")
    amount_str = metadata.get("amount_cents")

    if not agent_id or not amount_str:
        return False, "Missing metadata", None

    try:
        amount_cents = int(amount_str)
    except ValueError:
        return False, "Invalid amount", None

    # Idempotency: check if this session was already credited
    session_id = session.get("id")
    existing = Transaction.query.filter_by(
        description=f"Stripe:{session_id}"
    ).first()
    if existing:
        return True, "Already credited", existing

    agent = db.session.get(Agent, agent_id)
    if not agent:
        return False, f"Agent {agent_id} not found", None

    agent.balance += amount_cents
    tx = Transaction(
        agent_id=agent.id,
        type="topup",
        amount=amount_cents,
        description=f"Stripe:{session_id}",
    )
    db.session.add(tx)
    db.session.commit()
    log.info(f"Credited agent {agent_id} with {amount_cents} cents (Stripe)")
    return True, "Credited", tx
