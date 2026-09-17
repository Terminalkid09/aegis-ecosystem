"""YARA rules gestite dal SOC

Revision ID: 0015_yara_rules
Revises: 0014_integration_settings
Create Date: 2026-09-17

Le regole vivono in DB: devono viaggiare sul canale comandi verso gli
agenti e avere ciclo di vita (attiva/disattiva, audit, autore).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0015_yara_rules"
down_revision: Union[str, None] = "0014_integration_settings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(table_name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(table_name)


def upgrade() -> None:
    if _has_table("yara_rules"):
        return
    op.create_table(
        "yara_rules",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(128), nullable=False, index=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("yara_rules")
