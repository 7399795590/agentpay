"""AgentPay — Database setup (SQLite via SQLAlchemy)."""
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def init_db(app):
    """Initialize database with app."""
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///agentpay.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    with app.app_context():
        db.create_all()
