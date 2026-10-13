"""Pytest fixtures — isolates tests from production.

CRITICAL: This file MUST be loaded before any app/database import.
It:
- Forces TESTING=1
- Removes DATABASE_URL so tests use SQLite in-memory
- Sets AUTO_CREATE_TABLES=1 to create schema on the fly
- Provides a shared client fixture
"""
import os
import sys
from pathlib import Path

# ⚠️ MUST run BEFORE importing app or database
os.environ.pop("DATABASE_URL", None)
os.environ["TESTING"] = "1"
os.environ["AUTO_CREATE_TABLES"] = "1"
os.environ["FLASK_DEBUG"] = "0"

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from app import app as flask_app
from database import db


@pytest.fixture(scope="session", autouse=True)
def _setup_testing_environment():
    """Configure app for testing once per session."""
    flask_app.config["TESTING"] = True
    flask_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    flask_app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {}
    with flask_app.app_context():
        db.drop_all()
        db.create_all()
    yield
    with flask_app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client():
    """Return a test client."""
    return flask_app.test_client()


@pytest.fixture(autouse=True)
def _clean_db():
    """Wipe all data before each test (keep schema)."""
    with flask_app.app_context():
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        db.session.commit()
    yield
