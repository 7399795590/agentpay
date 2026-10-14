# Security Policy

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report them privately:

📧 **Email:** mhmdthbrh@gmail.com
📧 **Backup:** hoaam100@gmail.com

**Please include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

**Response time:** We aim to respond within 48 hours.

## What We Cover

### Supported Versions
The `main` branch is actively supported with security updates.

### Security Features

**Authentication:**
- Passwords hashed with scrypt
- Session cookies: HttpOnly, Secure, SameSite=Lax
- TOTP 2FA for admin accounts
- Account lockout after repeated failed logins

**Authorization:**
- Role-based access (admin / developer / viewer)
- IDOR protection on all agent-scoped endpoints
- Constant-time comparison for API keys and admin keys
- 404 (not 403) on unauthorized access (no existence leak)

**API Security:**
- Bearer token authentication (`ap_...`)
- Per-IP and per-agent rate limiting (DB-backed)
- HMAC-SHA256 signed webhooks
- Idempotency keys for money-moving operations

**Data Protection:**
- Sensitive fields encrypted at rest (Fernet / AES-128-CBC + HMAC)
- No secrets in logs (audit sanitizes sensitive fields)
- Audit log with hash chain (tamper detection)
- Full ledger with reconciliation

**Payments:**
- Stripe Checkout (no card data touches our servers)
- Webhook signature verification
- Amount and currency cross-check
- Daily and per-transaction limits

**Infrastructure:**
- All traffic over HTTPS
- Database connections over TLS
- Secrets in environment variables (never committed)

## Known Limitations

See `ratelimit.py` docstring for multi-worker considerations.

## Scope

**In scope:**
- The API at `web-production-32de5.up.railway.app`
- The website at `agentpay-pearl.vercel.app`
- The source code in this repository

**Out of scope:**
- Third-party services (Stripe, Neon, Railway, Vercel)
- Social engineering
- DoS/DDoS attacks
- Issues requiring physical access

## Recognition

We'll credit researchers who report valid vulnerabilities (with their permission) in our security acknowledgments.

## Bug Bounty

We currently do not offer a monetary bug bounty. However, we deeply appreciate responsible disclosure and will publicly acknowledge your contribution.

---

**Thank you for helping keep AgentPay safe.**
