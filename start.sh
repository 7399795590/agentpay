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

echo "Starting AgentPay on port $PORT"

exec gunicorn app:app \
  --bind "0.0.0.0:${PORT}" \
  --workers 2 \
  --timeout 60 \
  --access-logfile - \
  --error-logfile -
