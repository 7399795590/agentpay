"""One-time migration: encrypt existing agent.webhook_url values.

Run: python3 encrypt_existing_webhooks.py
"""
import os
import sys

# Set DATABASE_URL first
if not os.environ.get("DATABASE_URL"):
    try:
        with open(os.path.expanduser("~/.agentpay_db_url_railway")) as f:
            os.environ["DATABASE_URL"] = f.read().strip()
    except FileNotFoundError:
        print("❌ DATABASE_URL not set and backup file not found")
        sys.exit(1)

# Set encryption key
if not os.environ.get("WEBHOOK_ENCRYPTION_KEY"):
    try:
        with open(os.path.expanduser("~/.agentpay_env")) as f:
            for line in f:
                if line.startswith("WEBHOOK_ENCRYPTION_KEY="):
                    os.environ["WEBHOOK_ENCRYPTION_KEY"] = line.split("=", 1)[1].strip()
                    break
    except FileNotFoundError:
        pass

from app import app
from database import db
from models import Agent
import crypto


def main():
    if not crypto.is_enabled():
        print("❌ crypto not enabled — check WEBHOOK_ENCRYPTION_KEY")
        sys.exit(1)

    with app.app_context():
        agents = Agent.query.all()
        print(f"Found {len(agents)} agents")

        encrypted_count = 0
        skipped_count = 0
        failed_count = 0

        for agent in agents:
            url = agent.webhook_url
            if not url:
                skipped_count += 1
                continue

            # Already encrypted?
            if url.startswith("gAAAAA"):  # Fernet token prefix
                skipped_count += 1
                continue

            # Encrypt
            try:
                encrypted = crypto.encrypt_webhook_url(url)
                agent.webhook_url = encrypted
                encrypted_count += 1
                print(f"  ✅ Agent {agent.id[:8]}: encrypted ({len(url)} chars → {len(encrypted)} chars)")
            except Exception as e:
                failed_count += 1
                print(f"  ❌ Agent {agent.id[:8]}: {e}")

        db.session.commit()
        print(f"\n=== Summary ===")
        print(f"  Encrypted: {encrypted_count}")
        print(f"  Skipped (no url or already encrypted): {skipped_count}")
        print(f"  Failed: {failed_count}")


if __name__ == "__main__":
    main()
