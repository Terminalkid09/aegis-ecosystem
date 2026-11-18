"""Deception session aggregate for Kraken events.

Revision ID: 0021_deception_sessions
Revises: 0020_api_key_scopes
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0021_deception_sessions"
down_revision: Union[str, None] = "0020_api_key_scopes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "deception_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("sensor", sa.String(length=32), nullable=True),
        sa.Column("context", sa.String(length=16), nullable=False, server_default="sensor"),
        sa.Column("src_ip", sa.String(length=45), nullable=True),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("run_id", sa.String(length=64), nullable=True),
        sa.Column("scenario_id", sa.String(length=64), nullable=True),
        sa.Column("topology_id", sa.String(length=64), nullable=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_deception_sessions_session_id", "deception_sessions",
                    ["session_id"], unique=True)
    op.create_index("ix_deception_sessions_sensor", "deception_sessions", ["sensor"])
    op.create_index("ix_deception_sessions_context", "deception_sessions", ["context"])
    op.create_index("ix_deception_sessions_src_ip", "deception_sessions", ["src_ip"])
    op.create_index("ix_deception_sessions_last_seen", "deception_sessions", ["last_seen"])
    op.create_index("ix_deception_sessions_run_id", "deception_sessions", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_deception_sessions_run_id", table_name="deception_sessions")
    op.drop_index("ix_deception_sessions_last_seen", table_name="deception_sessions")
    op.drop_index("ix_deception_sessions_src_ip", table_name="deception_sessions")
    op.drop_index("ix_deception_sessions_context", table_name="deception_sessions")
    op.drop_index("ix_deception_sessions_sensor", table_name="deception_sessions")
    op.drop_index("ix_deception_sessions_session_id", table_name="deception_sessions")
    op.drop_table("deception_sessions")
