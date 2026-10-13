"""AgentPay — Database setup.

Supports:
- SQLite (local dev, default)
- PostgreSQL (production, via DATABASE_URL env var)
"""
import os
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def get_database_url():
    """Get DB URL from env (Postgres) or default to SQLite."""
    url = os.environ.get("DATABASE_URL")
    if url:
        # Railway/Heroku may give "postgres://" instead of "postgresql://"
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        # psycopg2 2.9 cannot handle channel_binding=require (Neon default)
        url = url.replace("&channel_binding=require", "")
        url = url.replace("?channel_binding=require&", "?")
        url = url.replace("?channel_binding=require", "")
        return url
    return "sqlite:///agentpay.db"


def init_db(app):
    """Initialize database with app."""
    app.config["SQLALCHEMY_DATABASE_URI"] = get_database_url()
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }
    db.init_app(app)
    with app.app_context():
        db.create_all()
