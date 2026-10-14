"""AgentPay — Ledger system (Task 61 + 64 + 65 + 70).

Provides:
- LedgerEntry model: immutable, append-only ledger of every money movement
- record_entry(): atomic helper that inserts a ledger row
- reconcile_agent(): verify agent.balance == sum(ledger entries)
- reconcile_all(): verify all agents

Design (lightweight double-entry):
- Every balance-changing operation creates a LedgerEntry
- Entries are IMMUTABLE (no updates/deletes — enforced by convention + audit)
- Each entry has: entry_id (UUID), agent_id, type, amount_signed,
  balance_after, related_entry_id, created_by_user_id, description, created_at
- balance_after is computed at insert time (atomic with the balance update)
- Sum(amount_signed) for an agent MUST equal agent.balance

Types:
- topup        : +amount
- charge       : -amount
- refund       : +amount (references original charge via related_entry_id)
- admin_adjust : ±amount (forced set by admin)
- subscription : -amount (recurring billing)
"""
import time
import secrets
from typing import Optional, List, Dict, Any

from database import db


def _gen_entry_id() -> str:
    """Generate a short unique entry ID (e.g. 'le_a1b2c3d4e5f6g7h8')."""
    return "le_" + secrets.token_hex(8)


class LedgerEntry(db.Model):
    """Immutable, append-only ledger entry.

    Each row records a single money movement with:
    - amount_signed: positive for credits (+), negative for debits (-)
    - balance_after: the agent's balance immediately after this entry
    - related_entry_id: for refunds, points to the original charge
    """
    __tablename__ = "ledger_entries"

    id = db.Column(db.String(32), primary_key=True, default=_gen_entry_id)
    agent_id = db.Column(db.String(32), db.ForeignKey("agents.id"), nullable=False, index=True)

    # Type: topup | charge | refund | admin_adjust | subscription
    type = db.Column(db.String(30), nullable=False, index=True)

    # Signed amount in cents (+ for credit, - for debit)
    amount_signed = db.Column(db.Integer, nullable=False)

    # Balance snapshot AFTER this entry
    balance_after = db.Column(db.Integer, nullable=False)

    # Currency at time of entry
    currency = db.Column(db.String(3), nullable=False, default="USD")

    # Reference to related entry (e.g. refund → original charge)
    related_entry_id = db.Column(db.String(32), db.ForeignKey("ledger_entries.id"), nullable=True, index=True)

    # Which user triggered this (NULL for API-key / system)
    created_by_user_id = db.Column(db.String(32), db.ForeignKey("users.id"), nullable=True, index=True)

    # Description / reason
    description = db.Column(db.String(255), default="")

    # External reference (e.g. Stripe session ID, transaction ID)
    external_ref = db.Column(db.String(255), nullable=True, index=True)

    # Idempotency: prevent duplicate ledger entries for the same operation
    idempotency_key = db.Column(db.String(128), nullable=True, unique=True, index=True)

    # Timestamp
    created_at = db.Column(db.Integer, default=lambda: int(time.time()), nullable=False, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "type": self.type,
            "amount_signed": self.amount_signed,
            "balance_after": self.balance_after,
            "currency": self.currency,
            "related_entry_id": self.related_entry_id,
            "created_by_user_id": self.created_by_user_id,
            "description": self.description,
            "external_ref": self.external_ref,
            "created_at": self.created_at,
        }


# ═══════════════════════════════════════════════════════
# Recording
# ═══════════════════════════════════════════════════════

def record_entry(
    agent,
    entry_type: str,
    amount_signed: int,
    description: str = "",
    related_entry_id: Optional[str] = None,
    created_by_user_id: Optional[str] = None,
    external_ref: Optional[str] = None,
    idempotency_key: Optional[str] = None,
) -> LedgerEntry:
    """Record a ledger entry. MUST be called in the same transaction as the
    balance update.

    Important:
    - Caller must update agent.balance BEFORE calling this, or pass the new
      balance explicitly. This function reads agent.balance as balance_after.
    - Caller is responsible for db.session.commit().

    Returns the LedgerEntry (not yet committed).
    """
    # Idempotency: if key exists, return existing entry (no duplicate)
    if idempotency_key:
        existing = LedgerEntry.query.filter_by(idempotency_key=idempotency_key).first()
        if existing:
            return existing

    entry = LedgerEntry(
        agent_id=agent.id,
        type=entry_type,
        amount_signed=amount_signed,
        balance_after=agent.balance,
        currency=agent.currency or "USD",
        related_entry_id=related_entry_id,
        created_by_user_id=created_by_user_id,
        description=(description or "")[:255],
        external_ref=external_ref,
        idempotency_key=idempotency_key,
    )
    db.session.add(entry)
    return entry


# ═══════════════════════════════════════════════════════
# Reconciliation
# ═══════════════════════════════════════════════════════

def reconcile_agent(agent) -> Dict[str, Any]:
    """Verify that sum(ledger entries) == agent.balance.

    Returns a dict:
    {
      "agent_id": str,
      "balance": int,
      "ledger_sum": int,
      "entry_count": int,
      "matches": bool,
      "discrepancy": int,   # balance - ledger_sum
    }
    """
    from sqlalchemy import func

    result = db.session.query(
        func.coalesce(func.sum(LedgerEntry.amount_signed), 0),
        func.count(LedgerEntry.id),
    ).filter(LedgerEntry.agent_id == agent.id).first()

    ledger_sum = int(result[0] or 0)
    entry_count = int(result[1] or 0)
    balance = int(agent.balance or 0)

    return {
        "agent_id": agent.id,
        "balance": balance,
        "ledger_sum": ledger_sum,
        "entry_count": entry_count,
        "matches": balance == ledger_sum,
        "discrepancy": balance - ledger_sum,
    }


def reconcile_all() -> Dict[str, Any]:
    """Verify all agents. Returns a summary + list of mismatches."""
    from models import Agent

    agents = Agent.query.all()
    mismatches = []
    total = 0
    matched = 0

    for agent in agents:
        total += 1
        r = reconcile_agent(agent)
        if r["matches"]:
            matched += 1
        else:
            mismatches.append(r)

    return {
        "total_agents": total,
        "matched": matched,
        "mismatched": len(mismatches),
        "mismatches": mismatches,
    }
