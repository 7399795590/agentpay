# AgentPay

> Payment infrastructure for AI agents. Microtransactions without credit cards.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)]()
[![CI](https://github.com/7399795590/agentpay/actions/workflows/test.yml/badge.svg)](https://github.com/7399795590/agentpay/actions/workflows/test.yml)

## The Problem

AI agents can't use credit cards. Stripe wasn't built for autonomous software.
Traditional payment gateways require human approval.

**Market:** 176M+ AI agent transactions worth $73M annually. Most under $0.30.

## The Solution

AgentPay gives AI agents a simple API to:
- Hold a prepaid balance (USD, EUR, GBP)
- Pay for services autonomously
- Support subscriptions + refunds
- Send webhooks with HMAC signatures

## Quick Start

### 1. Run with Docker

    git clone https://github.com/7399795590/agentpay.git
    cd agentpay
    docker-compose up

### 2. Or run locally

    pip install -r requirements.txt
    python app.py

Server: http://127.0.0.1:5000
Docs: http://127.0.0.1:5000/docs

## Features (15/15 completed)

### Core
- [x] REST API (12 endpoints)
- [x] SQLite / PostgreSQL
- [x] API key authentication
- [x] Rate limiting (per IP + per agent)
- [x] Structured JSON logging
- [x] Unified error handlers

### Payments
- [x] Multi-currency (USD, EUR, GBP)
- [x] Stripe Checkout integration
- [x] Recurring subscriptions (daily/weekly/monthly/yearly)
- [x] Refunds (with double-refund protection)
- [x] Webhooks with HMAC-SHA256 signatures + retry

### Developer Experience
- [x] Python SDK (`pip install agentpay-sdk`)
- [x] OpenAPI 3.0 spec + Swagger UI at /docs
- [x] Docker + docker-compose
- [x] Web dashboard
- [x] Admin API (stats, list, delete, set-balance)
- [x] Audit log (every sensitive operation)

## API Overview

| Method | Endpoint | Description |
|---|---|---|
| GET | /health | Service health |
| GET | /docs | Swagger UI |
| GET | /openapi.json | OpenAPI spec |
| POST | /agents/create | Create agent |
| GET | /agents/{id} | Get agent |
| POST | /agents/{id}/topup | Add balance |
| POST | /agents/{id}/charge | Deduct |
| GET | /agents/{id}/transactions | List transactions |
| POST | /agents/{id}/refund | Refund a charge |
| POST | /agents/{id}/subscriptions/create | New subscription |
| GET | /agents/{id}/subscriptions | List subscriptions |
| POST | /agents/{id}/stripe/checkout | Stripe checkout |
| GET | /admin/stats | Admin: system stats |
| GET | /admin/audit | Admin: audit log |

See [openapi.json](openapi.json) for full spec.

## Amounts

All amounts are **integers in smallest currency unit** (cents):
- $5.00 = `500`
- €0.30 = `30`
- £1.00 = `100`

## Python SDK

    pip install git+https://github.com/7399795590/agentpay.git#subdirectory=sdk/python

    from agentpay import AgentPayClient

    client = AgentPayClient(api_key="ap_...", agent_id="...")
    client.charge(amount_cents=30, description="API call")
    print(client.get_balance())

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | No | PostgreSQL URL (defaults to SQLite) |
| `STRIPE_SECRET_KEY` | For Stripe | `sk_test_...` or `sk_live_...` |
| `STRIPE_PUBLISHABLE_KEY` | For Stripe | `pk_test_...` |
| `STRIPE_WEBHOOK_SECRET` | For Stripe webhooks | `whsec_...` |
| `WEBHOOK_SECRET` | No | HMAC secret for outgoing webhooks |
| `ADMIN_API_KEY` | For admin | Secret for `/admin/*` endpoints |

## Architecture

    agentpay/
    ├── app.py                    Flask app + all routes
    ├── models.py                 SQLAlchemy: Agent, Transaction, Subscription, AuditLog
    ├── database.py               DB setup (SQLite/Postgres)
    ├── ratelimit.py              Sliding-window rate limiter
    ├── webhooks.py               HMAC-signed webhooks with retry
    ├── stripe_integration.py     Stripe Checkout
    ├── logging_utils.py          Structured JSON logs
    ├── openapi.json              OpenAPI 3.0 spec
    ├── dashboard.html            Web dashboard
    ├── index.html                Landing page
    ├── sdk/python/               Python SDK
    ├── tests/                    pytest suite
    ├── Dockerfile
    ├── docker-compose.yml
    └── Procfile                  For Railway/Heroku

## Testing

    pip install pytest
    python -m pytest tests/ -v

## License

MIT

## Contact

GitHub: https://github.com/7399795590/agentpay
Live: https://agentpay-pearl.vercel.app
