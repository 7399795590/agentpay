"""rate limiting: add rate_limit_buckets table (multi-worker safe)

Revision ID: manual_rate_limit
Revises: manual_health_check
Create Date: 2026-10-14
"""
from alembic import op
import sqlalchemy as sa


revision = 'manual_rate_limit'
down_revision = 'manual_health_check'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing = set(inspector.get_table_names())

    if 'rate_limit_buckets' not in existing:
        op.create_table(
            'rate_limit_buckets',
            sa.Column('key', sa.String(length=200), primary_key=True),
            sa.Column('timestamps', sa.Text(), nullable=False, server_default=''),
            sa.Column('updated_at', sa.Integer(), nullable=False),
        )
        op.create_index('ix_rate_limit_updated', 'rate_limit_buckets', ['updated_at'])


def downgrade():
    op.drop_table('rate_limit_buckets')
