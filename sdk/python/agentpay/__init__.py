"""AgentPay Python SDK.

Usage:
    from agentpay import AgentPayClient

    client = AgentPayClient(api_key="ap_...", agent_id="...")
    client.charge(amount_cents=30, description="API call")
    print(client.get_balance())
"""
from .client import AgentPayClient, AgentPayError

__version__ = "0.1.0"
__all__ = ["AgentPayClient", "AgentPayError"]
