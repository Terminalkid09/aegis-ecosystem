"""app_settings: impostazioni di deployment non segrete, editabili da UI

Revision ID: 0016_app_settings
Revises: 0015_yara_rules
Create Date: 2026-09-17

Perche' una tabella nuova e non `integration_settings`: quella cifra i valori
(chiavi API) e la maschera in UI. Provider AI e modello non sono segreti e
devono restare leggibili (debug, supporto, display in dashboard), quindi
vivono qui in chiaro. Precedenza gestita dal servizio: env esplicito > DB >
default.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0016_app_settings"
down_revision: Union[str, None] = "0015_yara_rules"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(table_name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(table_name)


def upgrade() -> None:
    if _has_table("app_settings"):
        return
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False, server_default=""),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
    )


def downgrade() -> None:
    if _has_table("app_settings"):
        op.drop_table("app_settings")
