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
    """Credit the agent's balance from a successful Stripe checkout.

    Security checks (task-5):
    1. Validate payment_status == "paid"  (Stripe is source of truth)
    2. Cross-check metadata.amount_cents with session.amount_total
    3. Cross-check currency with STRIPE_CURRENCY
    4. Use topup_helpers.perform_topup (daily limit + audit + idempotency)
    5. Idempotency via stripe_session_id (unique) + Idempotency-Key

    Accepts Stripe Session object OR dict.
    Returns (success: bool, message: str, transaction_or_none).
    """
    # ===== 1. Normalize session =====
    if not isinstance(session, dict):
        session = session.to_dict() if hasattr(session, "to_dict") else dict(session)

    session_id = session.get("id")
    if not session_id:
        return False, "Missing session id", None

    # ===== 2. Verify payment_status =====
    payment_status = session.get("payment_status")
    if payment_status != "paid":
        log.warning(f"Stripe {session_id}: payment_status={payment_status}, skipping")
        return False, f"payment_status is {payment_status}, not paid", None

    # ===== 3. Verify amount_total (source of truth) =====
    session_amount_total = session.get("amount_total")
    session_currency = (session.get("currency") or "").lower()

    if not isinstance(session_amount_total, int) or session_amount_total <= 0:
        return False, "Invalid session amount_total", None

    if session_currency != STRIPE_CURRENCY.lower():
        return False, f"Currency mismatch: {session_currency} != {STRIPE_CURRENCY}", None

    # ===== 4. Cross-check metadata =====
    metadata = session.get("metadata") or {}
    agent_id = metadata.get("agent_id")
    amount_str = metadata.get("amount_cents")

    if not agent_id or not amount_str:
        return False, "Missing metadata (agent_id/amount_cents)", None

    try:
        meta_amount = int(amount_str)
    except (ValueError, TypeError):
        return False, f"Invalid metadata amount: {amount_str}", None

    # Critical: metadata must match Stripe's source of truth
    if meta_amount != session_amount_total:
        log.error(
            f"Stripe {session_id}: metadata amount ({meta_amount}) "
            f"!= session.amount_total ({session_amount_total})"
        )
        return False, "Metadata amount does not match paid amount", None

    # ===== 5. Call topup_helpers (single source of truth for balance) =====
    try:
        import topup_helpers
        result = topup_helpers.perform_topup(
            agent_id=agent_id,
            amount_cents=session_amount_total,
            source="stripe",
            currency=session_currency.upper(),
            actor_user=None,
            actor_email=None,
            reason=f"Stripe checkout {session_id[:20]}",
            idempotency_key=f"stripe:{session_id}",
            stripe_session_id=session_id,
        )
    except Exception as e:
        log.exception(f"Stripe {session_id}: topup_helpers failed: {e}")
        return False, f"Internal error: {e}", None

    if not result.get("ok"):
        if result.get("replay"):
            log.info(f"Stripe {session_id}: already credited (replay)")
            return True, "Already credited", None
        log.warning(f"Stripe {session_id}: topup rejected: {result.get('error')}")
        return False, result.get("error", "topup rejected"), None

    log.info(
        f"Stripe {session_id}: credited agent {agent_id} "
        f"with {session_amount_total} cents ({session_currency})"
    )
    return True, "Credited", result.get("transaction")

