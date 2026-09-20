"""Tabella remember_devices: token "Mantieni l'accesso" per dispositivo.

Revision ID: 0018_remember_devices
Revises: 0017_enroll_token_install_config
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0018_remember_devices"
down_revision: Union[str, None] = "0017_enroll_token_install_config"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "remember_devices",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("device_label", sa.String(length=255), nullable=True),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_remember_devices_user_id", "remember_devices", ["user_id"])
    op.create_index("ix_remember_devices_token_hash", "remember_devices", ["token_hash"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_remember_devices_token_hash", table_name="remember_devices")
    op.drop_index("ix_remember_devices_user_id", table_name="remember_devices")
    op.drop_table("remember_devices")
