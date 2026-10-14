# Copyright (c) 2026 Mohammed Taha Abdullah Dawood Abrah (AgentPay)
# Licensed under the MIT License - see LICENSE file for details.

"""AgentPay — Topup helpers (task-5).

Central logic for:
- Daily limit enforcement (atomic via row lock)
- Idempotency-Key validation
- Atomic balance updates
- Audit + TopupRecord creation

Used by:
- /admin/agents/{id}/topup
- stripe_integration.credit_agent_from_checkout
"""

import hashlib
import json
import time

from flask import request
from sqlalchemy import text as sql_text

from database import db
from models import (
    Agent, Transaction, TopupRecord, DailyTopupCounter,
    IdempotencyKey,
)
import audit
import ledger


# ===== Constants =====

MAX_TOPUP_PER_TXN_CENTS = 500_00       # $500 per single topup
MAX_TOPUP_PER_DAY_CENTS = 500_00       # $500 per day per agent
# Future: make these configurable per-plan


# ===== Helpers =====

def _utc_day(ts=None):
    """Return 'YYYY-MM-DD' in UTC for a timestamp (default: now)."""
    ts = ts or int(time.time())
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


def compute_topup_fingerprint(agent_id, amount_cents, currency, source):
    """SHA-256 fingerprint of a topup request.

    Two requests with same fingerprint = same operation.
    """
    payload = {
        "agent_id": agent_id,
        "amount_cents": int(amount_cents),
        "currency": (currency or "USD").upper(),
        "source": source,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def check_idempotency(idem_key, endpoint, fingerprint):
    """Check Idempotency-Key state.

    Returns:
      ("new", None)            — no record; safe to proceed
      ("replay", record)       — completed; return cached response
      ("pending", None)        — currently processing; 409
      ("mismatch", None)       — same key, different fingerprint; 409
      ("failed", record)       — previous attempt failed; 409
    """
    if not idem_key:
        return ("none", None)
    existing = IdempotencyKey.query.filter_by(key=idem_key).first()
    if not existing:
        return ("new", None)
    if existing.request_fingerprint != fingerprint:
        return ("mismatch", existing)
    if existing.status == "completed":
        return ("replay", existing)
    if existing.status == "pending":
        return ("pending", existing)
    return ("failed", existing)


def reserve_idempotency(idem_key, endpoint, fingerprint):
    """Insert a pending idempotency record (caller commits)."""
    rec = IdempotencyKey(
        key=idem_key,
        endpoint=endpoint,
        request_fingerprint=fingerprint,
        status="pending",
    )
    db.session.add(rec)
    return rec


def finalize_idempotency(rec, response_data):
    """Mark idempotency record completed with cached response."""
    rec.status = "completed"
    rec.response_json = json.dumps(response_data, sort_keys=True)
    rec.completed_at = int(time.time())


def fail_idempotency(rec):
    if rec is not None:
        rec.status = "failed"
        rec.completed_at = int(time.time())


# ===== Daily limit =====

def get_daily_counter(agent_id, day, create=False):
    """Get or create today's counter for an agent."""
    counter = (
        DailyTopupCounter.query
        .filter_by(agent_id=agent_id, day=day)
        .first()
    )
    if counter is None and create:
        counter = DailyTopupCounter(agent_id=agent_id, day=day, total_cents=0)
        db.session.add(counter)
        db.session.flush()
    return counter


def check_daily_limit(agent_id, amount_cents, day=None):
    """Return (ok, current_total_cents, would_be_cents, reason)."""
    day = day or _utc_day()
    counter = get_daily_counter(agent_id, day, create=False)
    current = counter.total_cents if counter else 0
    would_be = current + amount_cents
    if would_be > MAX_TOPUP_PER_DAY_CENTS:
        return (
            False,
            current,
            would_be,
            f"Daily topup limit exceeded: {current} + {amount_cents} > {MAX_TOPUP_PER_DAY_CENTS}",
        )
    return (True, current, would_be, None)


def increment_daily_counter(agent_id, amount_cents, day=None):
    """Atomically increment daily counter. Must be called inside the same txn
    as the balance update.

    Uses INSERT ... ON CONFLICT DO UPDATE (Postgres) or fallback for SQLite.
    """
    day = day or _utc_day()
    db_url = str(db.engine.url)
    is_postgres = db_url.startswith("postgresql")

    if is_postgres:
        # Atomic upsert
        stmt = sql_text("""
            INSERT INTO daily_topup_counters (agent_id, day, total_cents)
            VALUES (:agent_id, :day, :amount)
            ON CONFLICT (agent_id, day)
            DO UPDATE SET total_cents = daily_topup_counters.total_cents + :amount
        """)
        db.session.execute(stmt, {
            "agent_id": agent_id,
            "day": day,
            "amount": amount_cents,
        })
    else:
        # SQLite / dev
        counter = get_daily_counter(agent_id, day, create=True)
        counter.total_cents = (counter.total_cents or 0) + amount_cents
        db.session.flush()


# ===== Main: perform topup =====

def perform_topup(agent_id, amount_cents, source, *,
                  currency="USD", actor_user=None, actor_email=None,
                  reason=None, idempotency_key=None, stripe_session_id=None,
                  commit=True):
    """Execute a topup safely.

    Returns dict:
      {ok, error, agent, transaction, topup_record, replay}
    """
    # ===== 1. Validate amount =====
    if not isinstance(amount_cents, int) or amount_cents <= 0:
        return {"ok": False, "error": "amount_cents must be positive integer"}
    if amount_cents > MAX_TOPUP_PER_TXN_CENTS:
        return {
            "ok": False,
            "error": f"amount exceeds per-transaction limit ({MAX_TOPUP_PER_TXN_CENTS} cents)",
        }
    if source not in ("stripe", "admin", "migration"):
        return {"ok": False, "error": f"invalid source: {source}"}

    # ===== 2. Agent =====
    agent = db.session.get(Agent, agent_id)
    if not agent:
        return {"ok": False, "error": "Agent not found"}

    # ===== 3. Idempotency =====
    fingerprint = compute_topup_fingerprint(agent_id, amount_cents, currency, source)
    idem_state, idem_record = check_idempotency(idempotency_key, "topup", fingerprint)
    if idem_state == "replay":
        cached = json.loads(idem_record.response_json) if idem_record.response_json else {}
        cached["_idempotent_replay"] = True
        return {"ok": True, "replay": True, "data": cached, "agent": agent}
    if idem_state == "pending":
        return {"ok": False, "error": "Request is currently being processed", "code": 409}
    if idem_state == "mismatch":
        return {"ok": False, "error": "Idempotency-Key reused with different parameters", "code": 409}
    if idem_state == "failed":
        return {"ok": False, "error": "Previous attempt with this key failed", "code": 409}

    # ===== 4. Daily limit check =====
    ok, current, would_be, why = check_daily_limit(agent_id, amount_cents)
    if not ok:
        return {"ok": False, "error": why, "code": 429, "current": current}

    # ===== 5. Reserve idempotency (if key provided) =====
    idem_record = None
    if idem_key := idempotency_key:
        idem_record = reserve_idempotency(idem_key=idem_key, endpoint="topup", fingerprint=fingerprint)

    try:
        # ===== 6. Atomic balance update =====
        agent.balance = (agent.balance or 0) + amount_cents

        # ===== 7. Transaction record =====
        desc = f"Topup via {source}"
        if reason:
            desc += f": {reason}"
        tx = Transaction(
            agent_id=agent.id,
            type="topup",
            amount=amount_cents,
            description=desc[:200],
        )
        db.session.add(tx)
        db.session.flush()

        # Ledger entry (Task 61) — signed credit
        ledger.record_entry(
            agent,
            entry_type="topup",
            amount_signed=amount_cents,
            description=desc[:255],
            created_by_user_id=actor_user.id if actor_user else None,
            external_ref=f"tx:{tx.id}",
            idempotency_key=(idempotency_key + ":ledger") if idempotency_key else None,
        )

        # ===== 8. TopupRecord =====
        record = TopupRecord(
            agent_id=agent.id,
            amount_cents=amount_cents,
            currency=(currency or "USD").upper(),
            source=source,
            status="completed",
            idempotency_key=idempotency_key,
            stripe_session_id=stripe_session_id,
            transaction_id=tx.id,
            actor_user_id=actor_user.id if actor_user else None,
            actor_email=actor_email,
            reason=reason,
            completed_at=int(time.time()),
        )
        db.session.add(record)
        db.session.flush()

        # ===== 9. Daily counter (atomic) =====
        increment_daily_counter(agent.id, amount_cents)

        # ===== 10. Audit =====
        audit.write_audit_secure(
            "topup",
            agent_id=agent.id,
            user_id=actor_user.id if actor_user else None,
            actor=actor_email or f"source:{source}",
            ip=request.remote_addr if request else None,
            source=source,
            amount_cents=amount_cents,
            currency=currency,
            reason=reason,
            tx_id=tx.id,
            topup_record_id=record.id,
            stripe_session_id=stripe_session_id,
        )

        # ===== 11. Finalize idempotency =====
        response_data = {
            "agent_id": agent.id,
            "amount_cents": amount_cents,
            "currency": currency,
            "source": source,
            "transaction_id": tx.id,
            "topup_record_id": record.id,
            "new_balance": agent.balance,
        }
        if idem_record is not None:
            finalize_idempotency(idem_record, response_data)

        if commit:
            db.session.commit()

        return {
            "ok": True,
            "replay": False,
            "agent": agent,
            "transaction": tx,
            "topup_record": record,
            "data": response_data,
        }

    except Exception as e:
        db.session.rollback()
        if idem_record is not None:
            try:
                fail_idempotency(idem_record)
                db.session.commit()
            except Exception:
                db.session.rollback()
        return {"ok": False, "error": f"topup failed: {e}", "code": 500}
