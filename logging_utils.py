"""AgentPay — Structured logging + request IDs."""
import json
import logging
import sys
import time
import uuid
from flask import request, g


class JSONFormatter(logging.Formatter):
    """Format log records as JSON lines."""

    def format(self, record):
        log_entry = {
            "timestamp": int(time.time()),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Add request context if available
        if hasattr(g, "request_id"):
            log_entry["request_id"] = g.request_id
        if hasattr(g, "agent_id"):
            log_entry["agent_id"] = g.agent_id
        if request:
            log_entry["method"] = request.method
            log_entry["path"] = request.path
            log_entry["remote_addr"] = request.remote_addr
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False)


def setup_logging(app):
    """Configure structured logging for the app."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    handler.setLevel(logging.INFO)

    # Root logger
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)

    # Flask's own logger
    app.logger.handlers = [handler]
    app.logger.setLevel(logging.INFO)

    # Disable Werkzeug default logger (access logs)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


def generate_request_id():
    """Generate short request ID."""
    return uuid.uuid4().hex[:12]
