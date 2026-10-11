# AgentPay

> Payment infrastructure for AI agents. Microtransactions without credit cards.

## The Problem

AI agents (like Claude Code, Cursor, AutoGPT) are increasingly autonomous.
But they can't pay for services — credit cards require human intervention,
and traditional payment gateways (Stripe, PayPal) are designed for humans.

**The market need:** 176M+ AI agent transactions worth $73M in the past year.
Most are under $0.30 — too small for credit cards.

## The Solution

AgentPay gives AI agents a simple API to:
- Hold a balance (in USD cents)
- Pay for services autonomously
- Log every transaction

## Quick Start

### 1. Install

    pip install -r requirements.txt

### 2. Run

    python app.py

Server starts on http://127.0.0.1:5000

### 3. Test

Create an agent:

    curl -X POST http://127.0.0.1:5000/agents/create \
      -H "Content-Type: application/json" \
      -d '{"name": "my-agent"}'

Top up $5 (500 cents):

    curl -X POST http://127.0.0.1:5000/agents/YOUR_ID/topup \
      -H "Content-Type: application/json" \
      -d '{"amount": 500}'

Charge $0.30 (30 cents):

    curl -X POST http://127.0.0.1:5000/agents/YOUR_ID/charge \
      -H "Content-Type: application/json" \
      -d '{"amount": 30, "description": "API fee"}'

Get transactions:

    curl http://127.0.0.1:5000/agents/YOUR_ID/transactions

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | /health | Service health check |
| POST | /agents/create | Create new agent |
| GET | /agents/{id} | Get agent details |
| POST | /agents/{id}/topup | Add balance |
| POST | /agents/{id}/charge | Deduct balance |
| GET | /agents/{id}/transactions | List transactions |

### Amounts

All amounts are integers in USD cents:
- $5.00 = 500
- $0.30 = 30
- $0.01 = 1

### Error Codes

- 400: Invalid request
- 402: Insufficient balance
- 404: Agent not found
- 500: Server error

## Architecture

    agentpay/
    ├── app.py           Flask app + routes
    ├── database.py      SQLAlchemy setup
    ├── models.py        Agent + Transaction
    ├── requirements.txt
    └── agentpay.db      SQLite (auto-created)

## Roadmap

- [x] Core API (create, topup, charge, transactions)
- [ ] API key authentication
- [ ] Python SDK (pip install agentpay)
- [ ] JavaScript SDK
- [ ] Web dashboard
- [ ] Stripe integration for real top-ups
- [ ] Multi-currency support
- [ ] Webhooks for events

## Why AgentPay?

Existing solutions aren't built for agents:

| Solution | Problem |
|---|---|
| Stripe | Requires human + credit card |
| PayPal | Same |
| Blockchain | Complex, slow, volatile |
| AgentPay | Simple API + prepaid balance |

## License

MIT
