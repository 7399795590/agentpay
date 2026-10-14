# Copyright (c) 2026 Mohammed Taha Abdullah Dawood Abrah (AgentPay)
# Licensed under the MIT License - see LICENSE file for details.

"""AgentPay — Health check recording & uptime computation (Task 9).

Records periodic health checks into `health_checks` table.
Provides uptime + latency percentiles for the /status page.
"""

import time
from datetime import datetime, timezone

from sqlalchemy import func, and_

from database import db
from models import HealthCheck


def record_health_check(service: str, ok: bool, latency_ms: int = None, error: str = None) -> HealthCheck:
    """Insert a single health check row. Caller must commit."""
    hc = HealthCheck(
        service=service,
        ok=ok,
        latency_ms=latency_ms,
        error=(error or "")[:255] if error else None,
    )
    db.session.add(hc)
    return hc


def prune_old_checks(days: int = 90) -> int:
    """Delete health checks older than `days`. Returns count deleted."""
    cutoff = int(time.time()) - (days * 86400)
    count = HealthCheck.query.filter(HealthCheck.created_at < cutoff).delete(synchronize_session=False)
    return count


def _percentile(values, pct):
    """Compute percentile from a sorted list of numbers."""
    if not values:
        return None
    k = int(round((len(values) - 1) * pct))
    return values[k]


def compute_uptime(period_seconds: int, service: str = "api"):
    """Compute uptime & latency metrics for a service over a period.

    Returns dict:
    {
      "period_seconds": N,
      "from": unix_ts,
      "to": unix_ts,
      "total_checks": N,
      "failed_checks": N,
      "uptime_pct": 100.0,
      "p50_latency_ms": N or None,
      "p95_latency_ms": N or None,
      "p99_latency_ms": N or None,
      "daily": [
         {"date": "2026-10-14", "total": 288, "failed": 0, "uptime_pct": 100.0}
      ]
    }
    """
    now = int(time.time())
    since = now - period_seconds

    base_q = HealthCheck.query.filter(
        HealthCheck.service == service,
        HealthCheck.created_at >= since,
    )

    total = base_q.count()
    failed = base_q.filter(HealthCheck.ok.is_(False)).count()
    uptime_pct = round((total - failed) / total * 100, 2) if total else 100.0

    # Latency percentiles (only successful checks)
    latencies = [
        row[0] for row in db.session.query(HealthCheck.latency_ms)
        .filter(
            HealthCheck.service == service,
            HealthCheck.created_at >= since,
            HealthCheck.ok.is_(True),
            HealthCheck.latency_ms.isnot(None),
        )
        .all()
    ]
    latencies.sort()
    p50 = _percentile(latencies, 0.50)
    p95 = _percentile(latencies, 0.95)
    p99 = _percentile(latencies, 0.99)

    # Daily breakdown
    daily = []
    try:
        rows = db.session.query(
            func.date_trunc('day', func.to_timestamp(HealthCheck.created_at)).label('day'),
            func.count(HealthCheck.id),
            func.sum(func.cast(~HealthCheck.ok, db.Integer)),
        ).filter(
            HealthCheck.service == service,
            HealthCheck.created_at >= since,
        ).group_by('day').order_by('day').all()

        for day, cnt, fails in rows:
            cnt = int(cnt or 0)
            fails = int(fails or 0)
            daily.append({
                "date": day.strftime("%Y-%m-%d") if day else None,
                "total": cnt,
                "failed": fails,
                "uptime_pct": round((cnt - fails) / cnt * 100, 2) if cnt else 100.0,
            })
    except Exception:
        # SQLite fallback: date_trunc/to_timestamp may not work
        daily = []

    return {
        "period_seconds": period_seconds,
        "from": since,
        "to": now,
        "total_checks": total,
        "failed_checks": failed,
        "uptime_pct": uptime_pct,
        "p50_latency_ms": p50,
        "p95_latency_ms": p95,
        "p99_latency_ms": p99,
        "daily": daily,
    }
