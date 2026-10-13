"""task-2: users, sessions, organizations + agent ownership

Revision ID: b380e7607d3d
Revises: 657870e00180
Create Date: 2026-10-13 15:46:38.015056

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b380e7607d3d'
down_revision = '657870e00180'
branch_labels = None
depends_on = None


def upgrade():
    # ===== Organizations =====
    op.create_table('organizations',
        sa.Column('id', sa.String(length=32), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('created_at', sa.Integer(), nullable=True),
        sa.Column('updated_at', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    # ===== Users =====
    op.create_table('users',
        sa.Column('id', sa.String(length=32), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=20), nullable=False, server_default='developer'),
        sa.Column('organization_id', sa.String(length=32), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('email_verified', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('totp_secret', sa.String(length=64), nullable=True),
        sa.Column('totp_enabled', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('recovery_codes_hash', sa.Text(), nullable=True),
        sa.Column('failed_logins', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('locked_until', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.Integer(), nullable=True),
        sa.Column('updated_at', sa.Integer(), nullable=True),
        sa.Column('last_login_at', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email')
    )
    op.create_index('ix_users_email', 'users', ['email'])

    # ===== Sessions =====
    op.create_table('sessions',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.Integer(), nullable=True),
        sa.Column('expires_at', sa.Integer(), nullable=False),
        sa.Column('ip', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=255), nullable=True),
        sa.Column('revoked_at', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_sessions_user_id', 'sessions', ['user_id'])
    op.create_index('ix_sessions_expires_at', 'sessions', ['expires_at'])

    # ===== Add owner_id + organization_id to agents =====
    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('owner_id', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('organization_id', sa.String(length=32), nullable=True))
        batch_op.create_index('ix_agents_owner_id', ['owner_id'])
        batch_op.create_index('ix_agents_organization_id', ['organization_id'])

    # ===== Add user_id to audit_logs =====
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('user_id', sa.String(length=32), nullable=True))
        batch_op.create_index('ix_audit_logs_user_id', ['user_id'])


def downgrade():
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.drop_index('ix_audit_logs_user_id')
        batch_op.drop_column('user_id')

    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.drop_index('ix_agents_organization_id')
        batch_op.drop_index('ix_agents_owner_id')
        batch_op.drop_column('organization_id')
        batch_op.drop_column('owner_id')

    op.drop_index('ix_sessions_expires_at', table_name='sessions')
    op.drop_index('ix_sessions_user_id', table_name='sessions')
    op.drop_table('sessions')
    op.drop_index('ix_users_email', table_name='users')
    op.drop_table('users')
    op.drop_table('organizations')
