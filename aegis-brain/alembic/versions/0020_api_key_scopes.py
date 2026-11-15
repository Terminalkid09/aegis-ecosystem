"""API keys per source: name, source, revocation and last use.

Revision ID: 0020_api_key_scopes
Revises: 0019_alert_evidence
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0020_api_key_scopes"
down_revision: Union[str, None] = "0019_alert_evidence"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("api_keys", sa.Column("name", sa.String(length=100), nullable=True))
    op.add_column("api_keys", sa.Column("source", sa.String(length=128), nullable=True))
    op.add_column("api_keys", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("api_keys", sa.Column("last_used", sa.DateTime(timezone=True), nullable=True))
    op.alter_column("api_keys", "user_id", existing_type=sa.Integer(), nullable=True)
    op.create_index("ix_api_keys_hashed_key", "api_keys", ["hashed_key"], unique=True)
    op.create_index("ix_api_keys_source", "api_keys", ["source"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_api_keys_source", table_name="api_keys")
    op.drop_index("ix_api_keys_hashed_key", table_name="api_keys")
    op.alter_column("api_keys", "user_id", existing_type=sa.Integer(), nullable=False)
    op.drop_column("api_keys", "last_used")
    op.drop_column("api_keys", "revoked_at")
    op.drop_column("api_keys", "source")
    op.drop_column("api_keys", "name")
