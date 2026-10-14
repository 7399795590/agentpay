"""Backfill ledger_entries from existing transactions.

Run once after deploying the ledger system to record historical
transactions that happened before LedgerEntry existed.

Usage:
    python3 backfill_ledger.py

Idempotent: skips agents whose ledger_sum already matches balance.
"""
import os
os.environ.setdefault("AUTO_CREATE_TABLES", "0")

from app import app
from database import db
from models import Agent, Transaction
from ledger import LedgerEntry
import time


# Map transaction types to ledger types
TX_TYPE_TO_LEDGER = {
    "topup": "topup",
    "charge": "charge",
    "refund": "refund",
    "admin_adjust": "admin_adjust",
    "subscription": "subscription",
}


def _tx_amount_signed(tx):
    """Determine sign for a transaction based on its type."""
    if tx.type in ("topup", "refund"):
        return abs(tx.amount)
    elif tx.type in ("charge",):
        return -abs(tx.amount)
    elif tx.type == "admin_adjust":
        # admin_adjust may be + or -, but legacy rows don't record sign.
        # Best effort: assume positive if it matches balance increase.
        # Since we can't know for sure, treat as positive.
        return abs(tx.amount)
    elif tx.type == "subscription":
        return -abs(tx.amount)
    return 0


def backfill():
    with app.app_context():
        agents = Agent.query.all()
        total_created = 0
        total_skipped = 0
        total_failed = 0

        for agent in agents:
            # Compute current ledger sum
            from sqlalchemy import func
            ledger_sum = db.session.query(
                func.coalesce(func.sum(LedgerEntry.amount_signed), 0)
            ).filter(LedgerEntry.agent_id == agent.id).scalar() or 0

            balance = agent.balance or 0

            if ledger_sum == balance:
                total_skipped += 1
                continue

            # Fetch transactions, ordered by creation
            txns = Transaction.query.filter_by(agent_id=agent.id).order_by(Transaction.created_at.asc()).all()
            if not txns:
                total_skipped += 1
                continue

            # Build running balance from 0
            running = 0
            for tx in txns:
                amount_signed = _tx_amount_signed(tx)
                if amount_signed == 0:
                    continue
                running += amount_signed

                entry = LedgerEntry(
                    agent_id=agent.id,
                    type=TX_TYPE_TO_LEDGER.get(tx.type, tx.type),
                    amount_signed=amount_signed,
                    balance_after=running,
                    currency=agent.currency or "USD",
                    description=f"[backfill] {tx.description or ''}"[:255],
                    external_ref=f"tx:{tx.id}",
                    created_at=tx.created_at or int(time.time()),
                )
                # Use idempotency key to prevent duplicates
                entry.idempotency_key = f"backfill:tx:{tx.id}"
                db.session.add(entry)
                total_created += 1

            try:
                db.session.commit()
                print(f"  ✅ {agent.id[:12]}... → {len(txns)} txns → ledger_sum={running}, balance={balance}")
            except Exception as e:
                db.session.rollback()
                total_failed += 1
                print(f"  ❌ {agent.id[:12]}... → {e}")

        print()
        print(f"Summary:")
        print(f"  Created: {total_created} entries")
        print(f"  Skipped: {total_skipped} agents (already matched)")
        print(f"  Failed:  {total_failed}")


if __name__ == "__main__":
    backfill()
