"""task-9: add health_checks table

Revision ID: manual_health_check
Revises: manual_17_18_61
Create Date: 2026-10-14

Adds health_checks table for uptime and latency tracking.
"""
from alembic import op
import sqlalchemy as sa


revision = 'manual_health_check'
down_revision = 'manual_17_18_61'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing = set(inspector.get_table_names())

    if 'health_checks' not in existing:
        op.create_table(
            'health_checks',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('service', sa.String(length=32), nullable=False, server_default='api'),
            sa.Column('ok', sa.Boolean(), nullable=False),
            sa.Column('latency_ms', sa.Integer(), nullable=True),
            sa.Column('error', sa.String(length=255), nullable=True),
            sa.Column('created_at', sa.Integer(), nullable=False),
        )
        op.create_index('ix_health_checks_service', 'health_checks', ['service'])
        op.create_index('ix_health_checks_ok', 'health_checks', ['ok'])
        op.create_index('ix_health_checks_created_at', 'health_checks', ['created_at'])
        op.create_index('ix_health_service_time', 'health_checks', ['service', 'created_at'])


def downgrade():
    op.drop_table('health_checks')
