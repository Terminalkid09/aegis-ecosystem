"""add outbox

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-15 00:00:00.000000
"""
import sqlalchemy as sa

from alembic import op

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'outbox',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('event_id', sa.String(64), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(16), nullable=False, server_default='pending'),
        sa.Column('attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('next_attempt_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column('claimed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index('ix_outbox_event_id', 'outbox', ['event_id'], unique=True)
    op.create_index('ix_outbox_status', 'outbox', ['status'])
    op.create_index('ix_outbox_next_attempt_at', 'outbox', ['next_attempt_at'])
    op.create_index('ix_outbox_due', 'outbox', ['status', 'next_attempt_at'])


def downgrade() -> None:
    op.drop_index('ix_outbox_due', table_name='outbox')
    op.drop_index('ix_outbox_next_attempt_at', table_name='outbox')
    op.drop_index('ix_outbox_status', table_name='outbox')
    op.drop_index('ix_outbox_event_id', table_name='outbox')
    op.drop_table('outbox')
