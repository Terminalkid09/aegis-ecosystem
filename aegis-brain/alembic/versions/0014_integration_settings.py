"""Integrations settings: chiavi provider cifrate in DB (override da UI)

Revision ID: 0014_integration_settings
Revises: 0013_siem_ingest
Create Date: 2026-09-16

Tabella di servizio (non per-utente): le chiavi sono cifrate con il KEK
globale. Env vince sul DB alla risoluzione, quindi questa tabella e' un
override operativo, non la fonte primaria.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0014_integration_settings"
down_revision: Union[str, None] = "0013_siem_ingest"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(table_name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(table_name)


def upgrade() -> None:
    if _has_table("integration_settings"):
        return
    op.create_table(
        "integration_settings",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value_encrypted", sa.Text(), nullable=False),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
    )


def downgrade() -> None:
    if _has_table("integration_settings"):
        op.drop_table("integration_settings")
