"""add parent_pid, parent_process_name, thread_count, network_connections to alerts

Revision ID: 0006
Revises: 0005
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0006'
down_revision: Union[str, None] = '0005'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('alerts', sa.Column('parent_pid', sa.BigInteger(), nullable=True))
    op.add_column('alerts', sa.Column('parent_process_name', sa.String(255), nullable=True))
    op.add_column('alerts', sa.Column('thread_count', sa.Integer(), nullable=True))
    op.add_column('alerts', sa.Column('network_connections', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('alerts', 'network_connections')
    op.drop_column('alerts', 'thread_count')
    op.drop_column('alerts', 'parent_process_name')
    op.drop_column('alerts', 'parent_pid')
