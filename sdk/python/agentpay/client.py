"""AgentPay Python SDK — Official client.

Usage:
    from agentpay import AgentPayClient

    client = AgentPayClient(api_key="ap_...", agent_id="...")
    client.charge(amount_cents=30, description="API call")
    print(client.get_balance())
"""
import json
import urllib.request
import urllib.error
from typing import Optional


__version__ = "0.1.0"


class AgentPayError(Exception):
    """Base exception for AgentPay errors."""
    def __init__(self, message, status_code=0, response=None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response or {}


class AgentPayClient:
    """Client for AgentPay API."""

    DEFAULT_BASE_URL = "http://127.0.0.1:5000"

    def __init__(self, api_key, agent_id, base_url=None, timeout=10.0):
        if not api_key or not api_key.startswith("ap_"):
            raise ValueError("api_key must start with 'ap_'")
        if not agent_id:
            raise ValueError("agent_id is required")
        self.api_key = api_key
        self.agent_id = agent_id
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout

    def _request(self, method, path, body=None, auth=True):
        url = self.base_url + path
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = "Bearer " + self.api_key
        data = json.dumps(body).encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8")
            try:
                payload = json.loads(raw)
            except Exception:
                payload = {"error": raw}
            raise AgentPayError(
                payload.get("error", "HTTP " + str(e.code)),
                status_code=e.code,
                response=payload,
            ) from e
        except urllib.error.URLError as e:
            raise AgentPayError("Network error: " + str(e.reason)) from e

    def get_agent(self):
        r = self._request("GET", "/agents/" + self.agent_id)
        return r["agent"]

    def get_balance(self):
        a = self.get_agent()
        return {
            "balance_cents": a["balance"],
            "balance_display": a["balance_display"],
        }

    def charge(self, amount_cents, description=""):
        if not isinstance(amount_cents, int) or amount_cents <= 0:
            raise ValueError("amount_cents must be a positive integer")
        body = {"amount": amount_cents}
        if description:
            body["description"] = description
        r = self._request("POST", "/agents/" + self.agent_id + "/charge", body)
        return r["transaction"]

    def topup(self, amount_cents, description=""):
        if not isinstance(amount_cents, int) or amount_cents <= 0:
            raise ValueError("amount_cents must be a positive integer")
        body = {"amount": amount_cents}
        if description:
            body["description"] = description
        r = self._request("POST", "/agents/" + self.agent_id + "/topup", body)
        return r["transaction"]

    def list_transactions(self, limit=20):
        r = self._request("GET", "/agents/" + self.agent_id + "/transactions?limit=" + str(limit))
        return r["transactions"]
