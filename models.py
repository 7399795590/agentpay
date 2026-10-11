"""AgentPay — Database models."""
import secrets
import time
from database import db


CURRENCY_SYMBOLS = {"USD": "$", "EUR": "€", "GBP": "£"}
SUPPORTED_CURRENCIES = list(CURRENCY_SYMBOLS.keys())


def format_balance(amount_cents: int, currency: str = "USD") -> str:
    """Format balance with currency symbol."""
    symbol = CURRENCY_SYMBOLS.get(currency, currency + " ")
    return f"{symbol}{amount_cents / 100:.2f}"


def generate_api_key():
    """Generate a secure API key."""
    return "ap_" + secrets.token_hex(24)


class Agent(db.Model):
    """An AI agent that can make payments."""
    __tablename__ = "agents"

    id = db.Column(db.String(32), primary_key=True, default=lambda: secrets.token_hex(8))
    name = db.Column(db.String(100), nullable=False)
    api_key = db.Column(db.String(64), unique=True, nullable=False, default=generate_api_key)
    balance = db.Column(db.Integer, default=0)  # in smallest unit
    currency = db.Column(db.String(3), default="USD")  # USD, EUR, GBP
    webhook_url = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.Integer, default=lambda: int(time.time()))

    transactions = db.relationship("Transaction", backref="agent", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "balance": self.balance,
            "currency": self.currency,
            "balance_display": format_balance(self.balance, self.currency),
            "webhook_url": self.webhook_url,
            "created_at": self.created_at,
        }


class Transaction(db.Model):
    """A charge or topup for an agent."""
    __tablename__ = "transactions"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_id = db.Column(db.String(32), db.ForeignKey("agents.id"), nullable=False)
    type = db.Column(db.String(10), nullable=False)  # "topup" or "charge"
    amount = db.Column(db.Integer, nullable=False)  # in cents
    description = db.Column(db.String(200), default="")
    status = db.Column(db.String(20), default="completed")  # completed, failed
    created_at = db.Column(db.Integer, default=lambda: int(time.time()))

    def to_dict(self):
        cur = self.agent.currency if self.agent else "USD"
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "type": self.type,
            "amount": self.amount,
            "amount_display": format_balance(abs(self.amount), cur),
            "description": self.description,
            "status": self.status,
            "created_at": self.created_at,
        }
