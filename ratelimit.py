"""AgentPay — Rate limiter (DB-backed sliding window, multi-worker safe).

Uses the `rate_limit_buckets` table (PostgreSQL / SQLite) to store
request timestamps per key. This makes limits consistent across:
- Multiple gunicorn workers
- Multiple app instances
- Process restarts

Fallback: if DB is unavailable or TESTING mode, use in-memory buckets.

⚠️ Compatibility: In TESTING mode, rate limiting is BYPASSED
(so tests can focus on business logic).
"""
import time
import threading
from functools import wraps
from flask import request, jsonify, current_app


# ─── Rate limits per endpoint name ───
RATE_LIMITS = {
    "create": 5,          # per IP (agent creation, login, register, etc.)
    "topup": 30,          # per agent
    "charge": 60,         # per agent
    "transactions": 120,  # per agent
    "get_agent": 60,      # per IP
    "health": 300,        # per IP
}


# ─── In-memory fallback (used if DB unavailable) ───
class _InMemoryRateLimiter:
    def __init__(self, window_seconds: int = 60):
        self.window = window_seconds
        self.buckets = {}
        self.lock = threading.Lock()

    def check(self, key, limit):
        now = time.time()
        cutoff = now - self.window
        with self.lock:
            timestamps = [t for t in self.buckets.get(key, []) if t > cutoff]
            if len(timestamps) >= limit:
                retry_after = int(self.window - (now - timestamps[0])) + 1
                return False, 0, max(1, retry_after)
            timestamps.append(now)
            self.buckets[key] = timestamps
            return True, limit - len(timestamps), 0


_fallback = _InMemoryRateLimiter(window_seconds=60)


# ─── DB-backed implementation ───
def _db_check(key: str, limit: int, window: int = 60) -> tuple:
    """Atomic DB-backed sliding-window check.

    Returns (allowed, remaining, retry_after).

    Uses SELECT ... FOR UPDATE on PostgreSQL to prevent races.
    On SQLite (dev), the UPDATE is serialized by SQLite itself.
    """
    from database import db
    from models import RateLimitBucket
    from sqlalchemy import text

    now = time.time()
    cutoff = now - window

    try:
        is_postgres = db.engine.url.drivername.startswith("postgresql")

        # Lock the row (PostgreSQL)
        if is_postgres:
            row = db.session.query(RateLimitBucket).filter_by(key=key).with_for_update().first()
        else:
            row = db.session.query(RateLimitBucket).filter_by(key=key).first()

        # Parse existing timestamps
        if row and row.timestamps:
            timestamps = []
            for t in row.timestamps.split(","):
                try:
                    ts = float(t)
                    if ts > cutoff:
                        timestamps.append(ts)
                except ValueError:
                    pass
        else:
            timestamps = []

        # Enforce limit
        if len(timestamps) >= limit:
            retry_after = int(window - (now - timestamps[0])) + 1
            # Make sure session doesn't hold a lock
            db.session.commit()
            return False, 0, max(1, retry_after)

        # Append and persist
        timestamps.append(now)
        new_ts_str = ",".join(f"{t:.3f}" for t in timestamps)

        if row:
            row.timestamps = new_ts_str
            row.updated_at = int(now)
        else:
            row = RateLimitBucket(key=key, timestamps=new_ts_str, updated_at=int(now))
            db.session.add(row)

        db.session.commit()
        return True, limit - len(timestamps), 0

    except Exception as e:
        # Fallback to in-memory on any DB failure
        current_app.logger.warning(f"DB rate limit failed, using fallback: {e}")
        try:
            db.session.rollback()
        except Exception:
            pass
        return _fallback.check(key, limit)


# ─── Key functions ───
def key_ip(request, **kwargs):
    """Rate limit key: by client IP."""
    return f"ip:{request.remote_addr}"


def key_agent(request, **kwargs):
    """Rate limit key: by agent ID (from URL) or IP fallback."""
    agent_id = kwargs.get("agent_id") or "unknown"
    return f"agent:{agent_id}"


# ─── Decorator ───
def limit(key_func, limit_name: str):
    """Decorator: rate limit a view.

    key_func(request, **kwargs) -> str  : builds the bucket key
    limit_name                          : key into RATE_LIMITS
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            # Skip in TESTING mode
            if current_app.config.get("TESTING"):
                return view_func(*args, **kwargs)

            limit_value = RATE_LIMITS.get(limit_name, 60)
            key = key_func(request, **kwargs)

            allowed, remaining, retry_after = _db_check(key, limit_value)

            if not allowed:
                response = jsonify({
                    "ok": False,
                    "error": "Rate limit exceeded",
                    "retry_after": retry_after,
                    "limit": limit_value,
                })
                response.status_code = 429
                response.headers["Retry-After"] = str(retry_after)
                response.headers["X-RateLimit-Limit"] = str(limit_value)
                response.headers["X-RateLimit-Remaining"] = "0"
                return response

            result = view_func(*args, **kwargs)
            return result

        return wrapper
    return decorator


# ─── Cleanup helper ───
def cleanup_stale_buckets(older_than_seconds: int = 3600) -> int:
    """Delete buckets not updated recently. Safe to call from cron."""
    from database import db
    from models import RateLimitBucket
    cutoff = int(time.time()) - older_than_seconds
    count = RateLimitBucket.query.filter(RateLimitBucket.updated_at < cutoff).delete(
        synchronize_session=False
    )
    db.session.commit()
    return count


# ─── Backward compatibility alias ───
# Old code imported `limiter` for custom checks.
# New implementation uses `_db_check` directly, but keep an alias
# so existing imports don't break.
limiter = _fallback
