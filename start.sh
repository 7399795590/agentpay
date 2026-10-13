#!/bin/sh
set -e

# Fallback chain: PORT -> 5000
if [ -z "$PORT" ]; then
  PORT=5000
fi

# Trim any whitespace/newlines from PORT
PORT=$(echo "$PORT" | tr -d '[:space:]')

# Validate PORT is numeric
case "$PORT" in
  ''|*[!0-9]*)
    echo "Invalid PORT='$PORT', falling back to 5000"
    PORT=5000
    ;;
esac

# Ensure FLASK_APP is set for flask CLI
export FLASK_APP=app.py

# Apply database migrations (idempotent — safe to run every deploy)
if [ -n "$DATABASE_URL" ]; then
  echo "→ Running database migrations..."
  if ! flask db upgrade; then
    echo "⚠️  Migration failed — aborting startup to prevent schema drift"
    exit 1
  fi
  echo "→ Migrations OK"
else
  echo "⚠️  DATABASE_URL not set — skipping migrations"
fi

echo "Starting AgentPay on port $PORT"

exec gunicorn app:app \
  --bind "0.0.0.0:${PORT}" \
  --workers 2 \
  --timeout 60 \
  --access-logfile - \
  --error-logfile -
