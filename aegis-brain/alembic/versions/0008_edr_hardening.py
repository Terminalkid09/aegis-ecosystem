"""EDR hardening: agent version/capabilities for OTA + fleet management.

Revision ID: 0008_edr_hardening
Revises: 0007_modern_deploy_total
Create Date: 2026-09-05
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0008_edr_hardening"
down_revision: Union[str, None] = "0007_modern_deploy_total"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns(table_name: str) -> set[str]:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table(table_name):
        return set()
    return {c["name"] for c in insp.get_columns(table_name)}


def _add(table: str, col: sa.Column) -> None:
    if col.name not in _columns(table):
        op.add_column(table, col)


def upgrade() -> None:
    _add("agents", sa.Column("agent_version", sa.String(length=50), nullable=True))
    _add("agents", sa.Column("capabilities", sa.JSON(), nullable=True))


def downgrade() -> None:
    for col in ("capabilities", "agent_version"):
        try:
            op.drop_column("agents", col)
        except Exception:
            pass
