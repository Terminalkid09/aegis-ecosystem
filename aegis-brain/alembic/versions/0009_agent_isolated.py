"""Track host isolation state (contain/release) on agents.

Revision ID: 0009_agent_isolated
Revises: 0008_edr_hardening
Create Date: 2026-09-05
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0009_agent_isolated"
down_revision: Union[str, None] = "0008_edr_hardening"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    cols = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("agents")} \
        if sa.inspect(op.get_bind()).has_table("agents") else set()
    if "isolated" not in cols:
        op.add_column("agents", sa.Column("isolated", sa.Boolean(), nullable=False, server_default="0"))


def downgrade() -> None:
    try:
        op.drop_column("agents", "isolated")
    except Exception:
        pass
