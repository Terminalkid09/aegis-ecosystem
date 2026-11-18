"""governed suppressions with mandatory TTL

Revision ID: 0022
Revises: 0021_deception_sessions
"""
import sqlalchemy as sa
from alembic import op

revision = "0022"
down_revision = "0021_deception_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "suppressions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("suppressed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_suppressed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_suppressions_rule_id", "suppressions", ["rule_id"])
    op.create_index("ix_suppressions_expires_at", "suppressions", ["expires_at"])
    op.create_index("ix_suppressions_active", "suppressions", ["active"])


def downgrade() -> None:
    op.drop_table("suppressions")
