# Copyright (c) 2026 Mohammed Taha Abdullah Dawood Abrah (AgentPay)
# Licensed under the MIT License - see LICENSE file for details.

"""AgentPay — Email sending via Resend.

Provides:
- send_password_reset(to, token)      — password reset email
- send_email_verification(to, token)  — email verification email

Design:
- Gracefully degrades if RESEND_API_KEY not set (logs warning, returns False)
- HTML + plaintext fallback
- Never raises to the caller (returns bool)
- Uses MAIL_FROM env var (fallback: onboarding@resend.dev)
- All emails include a plaintext version
"""

import os
import logging

try:
    import resend
    _RESEND_AVAILABLE = True
except ImportError:
    _RESEND_AVAILABLE = False
    resend = None


log = logging.getLogger(__name__)


# ─── Configuration ─────────────────────────────────────────
def _is_configured() -> bool:
    """Return True if Resend is configured (API key + library available)."""
    if not _RESEND_AVAILABLE:
        return False
    return bool(os.environ.get("RESEND_API_KEY"))


def _get_api_key() -> str:
    return os.environ.get("RESEND_API_KEY", "")


def _get_from() -> str:
    """Return the From header (env override or default)."""
    return os.environ.get("MAIL_FROM", "AgentPay <onboarding@resend.dev>")


def _get_base_url() -> str:
    """Base URL for links in emails (landing page)."""
    return os.environ.get("APP_BASE_URL", "https://agentpay-pearl.vercel.app")


# ─── Core send ─────────────────────────────────────────────
def _send(to: str, subject: str, html: str, text: str) -> bool:
    """Send an email via Resend. Returns True on success, False otherwise.

    Never raises — logs errors instead.
    """
    if not _is_configured():
        log.warning("Email not sent (Resend not configured): to=%s subject=%s", to, subject)
        return False

    try:
        resend.api_key = _get_api_key()
        params = {
            "from": _get_from(),
            "to": [to],
            "subject": subject,
            "html": html,
            "text": text,
        }
        resend.Emails.send(params)
        log.info("Email sent: to=%s subject=%s", to, subject)
        return True
    except Exception as e:
        log.error("Email send failed: to=%s subject=%s error=%s", to, subject, str(e))
        return False


# ─── Templates ─────────────────────────────────────────────
def _base_html(title: str, body_html: str) -> str:
    """Wrap body in a consistent branded HTML shell."""
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
</head>
<body style="margin:0;padding:0;background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#0f172a;border-radius:12px;border:1px solid #1e293b;overflow:hidden;">
          <!-- Header -->
          <tr>
            <td style="padding:28px 32px;border-bottom:1px solid #1e293b;">
              <table cellpadding="0" cellspacing="0">
                <tr>
                  <td style="font-size:20px;font-weight:700;color:#ffffff;">
                    <span style="color:#3b82f6;">⚡</span> AgentPay
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <!-- Body -->
          <tr>
            <td style="padding:32px;">
              {body_html}
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="padding:20px 32px;border-top:1px solid #1e293b;font-size:12px;color:#64748b;">
              <div>Payment infrastructure for AI agents.</div>
              <div style="margin-top:6px;">
                <a href="{_get_base_url()}" style="color:#3b82f6;text-decoration:none;">agentpay-pearl.vercel.app</a>
                ·
                <a href="https://github.com/7399795590/agentpay" style="color:#3b82f6;text-decoration:none;">GitHub</a>
              </div>
              <div style="margin-top:10px;color:#475569;">Built in Yemen 🇾🇪</div>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def _button_html(url: str, label: str) -> str:
    """Render a branded CTA button."""
    return f'''<table cellpadding="0" cellspacing="0" style="margin:24px 0;">
  <tr>
    <td style="background:#3b82f6;border-radius:8px;">
      <a href="{url}" style="display:inline-block;padding:14px 28px;color:#ffffff;font-weight:600;text-decoration:none;font-size:15px;">{label}</a>
    </td>
  </tr>
</table>'''


# ─── Public senders ────────────────────────────────────────
def send_password_reset(to: str, token: str) -> bool:
    """Send a password reset email containing a reset link."""
    link = f"{_get_base_url()}/reset-password.html?token={token}"
    subject = "Reset your AgentPay password"

    body_html = f"""
      <h1 style="margin:0 0 12px 0;font-size:22px;color:#ffffff;">Reset your password</h1>
      <p style="margin:0 0 16px 0;color:#94a3b8;font-size:15px;line-height:1.6;">
        We received a request to reset your AgentPay password.
        Click the button below to choose a new one.
      </p>
      {_button_html(link, 'Reset password')}
      <p style="margin:16px 0 0 0;color:#64748b;font-size:13px;line-height:1.6;">
        This link expires in 1 hour. If you didn't request a reset, you can safely ignore this email.
      </p>
      <p style="margin:16px 0 0 0;color:#475569;font-size:12px;word-break:break-all;">
        Or paste this URL in your browser:<br>
        <span style="color:#64748b;">{link}</span>
      </p>
    """

    text = f"""Reset your AgentPay password

We received a request to reset your password.

Open this link to choose a new password:
{link}

This link expires in 1 hour. If you didn't request a reset, ignore this email.
"""

    return _send(to, subject, _base_html(subject, body_html), text)


def send_email_verification(to: str, token: str) -> bool:
    """Send an email verification link."""
    link = f"{_get_base_url()}/verify-email.html?token={token}"
    subject = "Verify your AgentPay email"

    body_html = f"""
      <h1 style="margin:0 0 12px 0;font-size:22px;color:#ffffff;">Verify your email</h1>
      <p style="margin:0 0 16px 0;color:#94a3b8;font-size:15px;line-height:1.6;">
        Welcome to AgentPay! Confirm your email address to activate your account.
      </p>
      {_button_html(link, 'Verify email')}
      <p style="margin:16px 0 0 0;color:#64748b;font-size:13px;line-height:1.6;">
        This link expires in 24 hours. If you didn't sign up, you can ignore this email.
      </p>
      <p style="margin:16px 0 0 0;color:#475569;font-size:12px;word-break:break-all;">
        Or paste this URL in your browser:<br>
        <span style="color:#64748b;">{link}</span>
      </p>
    """

    text = f"""Verify your AgentPay email

Welcome to AgentPay! Confirm your email address:

{link}

This link expires in 24 hours. If you didn't sign up, ignore this email.
"""

    return _send(to, subject, _base_html(subject, body_html), text)
