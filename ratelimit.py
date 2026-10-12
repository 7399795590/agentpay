"""AgentPay — In-memory rate limiter (sliding window)."""
import time
import threading
from functools import wraps
from flask import request, jsonify, current_app


class RateLimiter:
    """Simple in-memory sliding-window rate limiter."""

    def __init__(self, window_seconds: int = 60):
        self.window = window_seconds
        self.buckets: dict = {}
        self.lock = threading.Lock()

    def check(self, key: str, limit: int) -> tuple:
        """Returns (allowed: bool, remaining: int, retry_after: int)."""
        now = time.time()
        cutoff = now - self.window
        with self.lock:
            timestamps = self.buckets.get(key, [])
            timestamps = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= limit:
                retry_after = int(self.window - (now - timestamps[0])) + 1
                return False, 0, max(1, retry_after)
            timestamps.append(now)
            self.buckets[key] = timestamps
            remaining = limit - len(timestamps)
            return True, remaining, 0

    def cleanup(self) -> int:
        """Remove empty buckets."""
        now = time.time()
        cutoff = now - self.window
        removed = 0
        with self.lock:
            for key in list(self.buckets.keys()):
                self.buckets[key] = [t for t in self.buckets[key] if t > cutoff]
                if not self.buckets[key]:
                    del self.buckets[key]
                    removed += 1
        return removed


# Global limiter
limiter = RateLimiter(window_seconds=60)

# Limits per endpoint
RATE_LIMITS = {
    "create": 5,       # per IP
    "topup": 30,       # per agent
    "charge": 60,      # per agent
    "transactions": 120,  # per agent
    "get_agent": 60,   # per IP
    "health": 300,     # per IP
}


def limit(key_func, limit_name: str):
    """Decorator: rate limit a view. key_func(request, **kwargs) -> str."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            # Skip rate limiting when running tests
            if current_app.config.get("TESTING"):
                return view_func(*args, **kwargs)
            limit_value = RATE_LIMITS.get(limit_name, 60)
            key = key_func(request, **kwargs)
            allowed, remaining, retry_after = limiter.check(key, limit_value)
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
            # Add headers to successful responses by wrapping
            result = view_func(*args, **kwargs)
            return result
        return wrapper
    return decorator
