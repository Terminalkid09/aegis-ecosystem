"""Revision ID: 0012_audit_is_test
Revises: 0011_revoked_certs
Create Date: 2026-09-12
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0012_audit_is_test"
down_revision: Union[str, None] = "0011_revoked_certs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.add_column("audit_logs", sa.Column("is_test", sa.Boolean(), nullable=False, server_default="false"))
    op.create_index("ix_audit_logs_is_test", "audit_logs", ["is_test"])
    # Pulisci i vecchi record e2e anonimizzati marcandoli come test
    op.execute("UPDATE audit_logs SET is_test = true WHERE username = '[e2e-removed]' OR username ILIKE '%e2e%' OR username ILIKE '%test%'")

def downgrade() -> None:
    op.drop_index("ix_audit_logs_is_test", table_name="audit_logs")
    op.drop_column("audit_logs", "is_test")
