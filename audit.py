"""AgentPay — Secure audit logging.

Features:
- Sanitizes sensitive fields (password_hash, totp_secret, api_key, ...)
- SHA-256 hash chain: each record includes hash of previous record
- verify_audit_chain() detects tampering or reordering
- Low-level direct write to avoid audit-of-audit recursion
"""
import hashlib
import json
import time

from database import db
from models import AuditLog, sanitize_metadata  # reuse single sanitizer


# ===== Hash computation =====

def canonical_json(data) -> str:
    """Deterministic JSON string: sorted keys, no spaces, UTF-8 safe."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_record_hash(entry: AuditLog) -> str:
    """Compute SHA-256 of a record's essential fields + prev_hash.

    Fields included:
    - id, timestamp, action, agent_id, user_id, actor, ip, status
    - metadata_json
    - prev_hash

    This is the canonical tamper-evidence string.
    """
    payload = {
        "id": entry.id,
        "timestamp": entry.timestamp,
        "action": entry.action,
        "agent_id": entry.agent_id,
        "user_id": entry.user_id,
        "actor": entry.actor,
        "ip": entry.ip,
        "status": entry.status,
        "metadata_json": entry.metadata_json or "",
        "prev_hash": entry.prev_hash or "",
    }
    canonical = canonical_json(payload)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def get_last_audit_hash():
    """Return the record_hash of the most recent hashed audit entry.

    Ignores entries with record_hash IS NULL (legacy records).
    """
    entry = (
        AuditLog.query
        .filter(AuditLog.record_hash.isnot(None))
        .order_by(AuditLog.id.desc())
        .first()
    )
    return entry.record_hash if entry else None


# ===== Secure write =====

def _write_audit_direct(action, agent_id=None, user_id=None, actor=None,
                        ip=None, user_agent=None, status="ok", **metadata):
    """Low-level audit write. Does NOT compute hash chain.

    Used internally by write_audit_secure() to avoid recursion when logging
    audit reads/writes themselves.
    """
    clean = sanitize_metadata(metadata) if metadata else None
    entry = AuditLog(
        action=action,
        agent_id=agent_id,
        user_id=user_id,
        actor=actor,
        ip=ip,
        user_agent=(user_agent or "")[:200] or None,
        status=status,
        metadata_json=canonical_json(clean) if clean else None,
    )
    db.session.add(entry)
    db.session.flush()  # get entry.id
    return entry


def write_audit_secure(action, agent_id=None, user_id=None, actor=None,
                       ip=None, user_agent=None, status="ok", **metadata):
    """Write an audit entry with hash chain. Caller must commit.

    Returns the AuditLog entry.
    """
    entry = _write_audit_direct(
        action=action,
        agent_id=agent_id,
        user_id=user_id,
        actor=actor,
        ip=ip,
        user_agent=user_agent,
        status=status,
        **metadata,
    )
    # Compute chain
    entry.prev_hash = get_last_audit_hash()
    entry.record_hash = compute_record_hash(entry)
    db.session.flush()
    return entry


# ===== Verification =====

def verify_audit_chain(start_id=None, limit=1000):
    """Walk the audit chain and verify every record_hash.

    Returns dict:
      {
        "ok": bool,
        "checked": int,
        "broken_at": int | None,
        "reason": str | None,
      }
    """
    q = AuditLog.query.filter(AuditLog.record_hash.isnot(None)).order_by(AuditLog.id.asc())
    if start_id:
        q = q.filter(AuditLog.id >= start_id)
    entries = q.limit(limit).all()

    prev_hash = None
    for i, entry in enumerate(entries):
        # Recompute expected hash
        expected = compute_record_hash(entry)
        if expected != entry.record_hash:
            return {
                "ok": False,
                "checked": i + 1,
                "broken_at": entry.id,
                "reason": f"record_hash mismatch at id={entry.id}",
            }
        # Check chain linkage
        if prev_hash is not None and entry.prev_hash != prev_hash:
            return {
                "ok": False,
                "checked": i + 1,
                "broken_at": entry.id,
                "reason": f"prev_hash mismatch at id={entry.id}",
            }
        prev_hash = entry.record_hash

    return {
        "ok": True,
        "checked": len(entries),
        "broken_at": None,
        "reason": None,
    }


def get_chain_checkpoint():
    """Return a compact checkpoint of the chain (for external storage).

    Store this output elsewhere (off-site) to make tampering detectable
    even if the DB is fully compromised.
    """
    last = (
        AuditLog.query
        .filter(AuditLog.record_hash.isnot(None))
        .order_by(AuditLog.id.desc())
        .first()
    )
    total = AuditLog.query.count()
    if not last:
        return {"last_id": None, "last_hash": None, "total": total, "at": int(time.time())}
    return {
        "last_id": last.id,
        "last_hash": last.record_hash,
        "total": total,
        "at": int(time.time()),
    }
