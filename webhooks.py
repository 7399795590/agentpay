"""AgentPay — Webhook dispatcher."""
import json
import threading
import time
import urllib.request
import urllib.error


def _send(url: str, payload: dict, timeout: float = 5.0) -> tuple:
    """Send POST to webhook URL. Returns (success, status_code, error)."""
    try:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "AgentPay-Webhook/0.1",
                "X-AgentPay-Event": payload.get("event", "unknown"),
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return True, response.status, None
    except urllib.error.HTTPError as e:
        return False, e.code, str(e)
    except urllib.error.URLError as e:
        return False, 0, str(e.reason)
    except Exception as e:
        return False, 0, str(e)


def _fire_async(url: str, payload: dict) -> None:
    """Fire webhook in background thread (non-blocking)."""
    def worker():
        success, code, err = _send(url, payload)
        if not success:
            print(f"[webhook] failed url={url} code={code} err={err}")
        else:
            print(f"[webhook] sent url={url} code={code}")
    t = threading.Thread(target=worker, daemon=True)
    t.start()


def fire_webhook(agent, event: str, transaction=None) -> None:
    """Fire webhook for an agent event (topup, charge, etc.)."""
    if not agent.webhook_url:
        return
    payload = {
        "event": event,
        "agent_id": agent.id,
        "agent_name": agent.name,
        "balance_after": agent.balance,
        "balance_display": f"${agent.balance / 100:.2f}",
        "timestamp": int(time.time()),
    }
    if transaction:
        payload["transaction"] = {
            "id": transaction.id,
            "type": transaction.type,
            "amount": transaction.amount,
            "amount_display": f"${abs(transaction.amount) / 100:.2f}",
            "description": transaction.description,
        }
    _fire_async(agent.webhook_url, payload)
