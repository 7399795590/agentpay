"""AgentPay — Webhook dispatcher with signatures + retries."""
import hashlib
import hmac
import json
import os
import threading
import time
import urllib.request
import urllib.error


MAX_RETRIES = 3
RETRY_DELAYS = [1, 5, 15]  # seconds (exponential-ish)
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")


def sign_payload(payload: dict, secret: str) -> str:
    """Generate HMAC-SHA256 signature of JSON payload."""
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def _send_once(url: str, payload: dict, timeout: float = 5.0) -> tuple:
    """One attempt to POST. Returns (success, status_code, error)."""
    try:
        body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "AgentPay-Webhook/0.2",
            "X-AgentPay-Event": payload.get("event", "unknown"),
            "X-AgentPay-Delivery": payload.get("delivery_id", ""),
        }
        if WEBHOOK_SECRET:
            headers["X-AgentPay-Signature"] = sign_payload(payload, WEBHOOK_SECRET)
        req = urllib.request.Request(url, data=body_bytes, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return True, response.status, None
    except urllib.error.HTTPError as e:
        return False, e.code, str(e)
    except urllib.error.URLError as e:
        return False, 0, str(e.reason)
    except Exception as e:
        return False, 0, str(e)


def _send_with_retry(url: str, payload: dict) -> tuple:
    """Attempt with retries + backoff. Returns (success, attempts, last_error)."""
    last_err = None
    for attempt in range(MAX_RETRIES):
        ok, code, err = _send_once(url, payload)
        if ok and code < 400:
            return True, attempt + 1, None
        last_err = f"attempt={attempt+1} code={code} err={err}"
        if attempt < MAX_RETRIES - 1:
            time.sleep(RETRY_DELAYS[attempt])
    return False, MAX_RETRIES, last_err


def _fire_async(url: str, payload: dict) -> None:
    """Fire webhook in background thread (non-blocking)."""
    def worker():
        success, attempts, err = _send_with_retry(url, payload)
        if success:
            print(f"[webhook] sent url={url} attempts={attempts}")
        else:
            print(f"[webhook] failed url={url} attempts={attempts} err={err}")
    t = threading.Thread(target=worker, daemon=True)
    t.start()


def fire_webhook(agent, event: str, transaction=None) -> None:
    """Fire webhook for an agent event (topup, charge, etc.)."""
    if not agent.webhook_url:
        return
    import uuid
    payload = {
        "event": event,
        "delivery_id": uuid.uuid4().hex,
        "agent_id": agent.id,
        "agent_name": agent.name,
        "currency": agent.currency,
        "balance_after": agent.balance,
        "balance_display": f"{(agent.currency=='USD' and '$') or (agent.currency=='EUR' and chr(8364)) or (agent.currency=='GBP' and chr(163)) or ''}{agent.balance / 100:.2f}",
        "timestamp": int(time.time()),
    }
    if transaction:
        payload["transaction"] = {
            "id": transaction.id,
            "type": transaction.type,
            "amount": transaction.amount,
            "amount_display": f"{abs(transaction.amount) / 100:.2f}",
            "description": transaction.description,
        }
    _fire_async(agent.webhook_url, payload)
