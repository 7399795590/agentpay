"""task-17+18+61: add ledger + password_reset + email_verification tables

Revision ID: manual_17_18_61
Revises: e4492df90f33
Create Date: 2026-10-14

Manually written because flask db migrate had issues with baseline schema.
Uses CREATE TABLE IF NOT EXISTS to be idempotent.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'manual_17_18_61'
down_revision = 'e4492df90f33'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing = set(inspector.get_table_names())

    # ─── password_reset_tokens (task 17) ───
    if 'password_reset_tokens' not in existing:
        op.create_table(
            'password_reset_tokens',
            sa.Column('id', sa.String(length=32), primary_key=True),
            sa.Column('user_id', sa.String(length=32), sa.ForeignKey('users.id'), nullable=False, index=True),
            sa.Column('token_hash', sa.String(length=128), nullable=False, unique=True, index=True),
            sa.Column('created_at', sa.Integer(), nullable=False),
            sa.Column('expires_at', sa.Integer(), nullable=False, index=True),
            sa.Column('used_at', sa.Integer(), nullable=True),
            sa.Column('ip', sa.String(length=45), nullable=True),
            sa.Column('user_agent', sa.String(length=255), nullable=True),
        )

    # ─── email_verification_tokens (task 18) ───
    if 'email_verification_tokens' not in existing:
        op.create_table(
            'email_verification_tokens',
            sa.Column('id', sa.String(length=32), primary_key=True),
            sa.Column('user_id', sa.String(length=32), sa.ForeignKey('users.id'), nullable=False, index=True),
            sa.Column('email', sa.String(length=255), nullable=False),
            sa.Column('token_hash', sa.String(length=128), nullable=False, unique=True, index=True),
            sa.Column('created_at', sa.Integer(), nullable=False),
            sa.Column('expires_at', sa.Integer(), nullable=False, index=True),
            sa.Column('used_at', sa.Integer(), nullable=True),
            sa.Column('ip', sa.String(length=45), nullable=True),
            sa.Column('user_agent', sa.String(length=255), nullable=True),
        )

    # ─── ledger_entries (task 61+70) ───
    if 'ledger_entries' not in existing:
        op.create_table(
            'ledger_entries',
            sa.Column('id', sa.String(length=32), primary_key=True),
            sa.Column('agent_id', sa.String(length=32), sa.ForeignKey('agents.id'), nullable=False, index=True),
            sa.Column('type', sa.String(length=30), nullable=False, index=True),
            sa.Column('amount_signed', sa.Integer(), nullable=False),
            sa.Column('balance_after', sa.Integer(), nullable=False),
            sa.Column('currency', sa.String(length=3), nullable=False, server_default='USD'),
            sa.Column('related_entry_id', sa.String(length=32), sa.ForeignKey('ledger_entries.id'), nullable=True, index=True),
            sa.Column('created_by_user_id', sa.String(length=32), sa.ForeignKey('users.id'), nullable=True, index=True),
            sa.Column('description', sa.String(length=255), nullable=True),
            sa.Column('external_ref', sa.String(length=255), nullable=True, index=True),
            sa.Column('idempotency_key', sa.String(length=128), nullable=True, unique=True, index=True),
            sa.Column('created_at', sa.Integer(), nullable=False, index=True),
        )


def downgrade():
    op.drop_table('ledger_entries')
    op.drop_table('email_verification_tokens')
    op.drop_table('password_reset_tokens')
