"""initial schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-06-25
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("username", sa.String(length=150), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=500), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("encrypted_dek", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    op.create_table(
        "agents",
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("os_type", sa.String(length=50), nullable=True),
        sa.Column("agent_type", sa.String(length=50), nullable=True),
        sa.Column("meta", sa.JSON(), nullable=True),
        sa.Column("device_token_hash", sa.String(length=500), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("agent_id"),
        sa.UniqueConstraint("hostname", "os_type", name="uq_agent_hostname_os"),
    )

    op.create_table(
        "custom_rules",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("target_field", sa.String(length=100), nullable=False),
        sa.Column("pattern", sa.String(length=500), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "osint_reports",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("query", sa.String(length=512), nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("cached_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_osint_reports_query", "osint_reports", ["query"], unique=False)

    op.create_table(
        "ai_threads",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ai_threads_user_id", "ai_threads", ["user_id"], unique=False)

    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("hashed_key", sa.String(length=512), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "notes",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("mood", sa.String(length=20), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_notes_user_id", "notes", ["user_id"], unique=False)

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("process_name", sa.String(length=255), nullable=False),
        sa.Column("process_path", sa.Text(), nullable=True),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("is_resolved", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.agent_id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "telemetry",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("cpu_usage", sa.Float(), nullable=True),
        sa.Column("ram_usage", sa.Float(), nullable=True),
        sa.Column("disk_free", sa.BigInteger(), nullable=True),
        sa.Column("disk_total", sa.BigInteger(), nullable=True),
        sa.Column("network_sent", sa.BigInteger(), nullable=True),
        sa.Column("network_received", sa.BigInteger(), nullable=True),
        sa.Column("processes", sa.JSON(), nullable=True),
        sa.Column("ip_local", sa.String(length=45), nullable=True),
        sa.Column("ip_public", sa.String(length=45), nullable=True),
        sa.Column("geo_country", sa.String(length=100), nullable=True),
        sa.Column("geo_city", sa.String(length=100), nullable=True),
        sa.Column("users", sa.JSON(), nullable=True),
        sa.Column("network_flows", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["device_id"], ["agents.agent_id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_telemetry_device_id", "telemetry", ["device_id"], unique=False)
    op.create_index("ix_telemetry_timestamp", "telemetry", ["timestamp"], unique=False)

    op.create_table(
        "ai_messages",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("thread_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["thread_id"], ["ai_threads.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ai_messages_thread_id", "ai_messages", ["thread_id"], unique=False)
    op.create_index("ix_ai_messages_user_id", "ai_messages", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_table("ai_messages")
    op.drop_index("ix_telemetry_timestamp", table_name="telemetry")
    op.drop_index("ix_telemetry_device_id", table_name="telemetry")
    op.drop_table("telemetry")
    op.drop_table("alerts")
    op.drop_index("ix_notes_user_id", table_name="notes")
    op.drop_table("notes")
    op.drop_table("api_keys")
    op.drop_index("ix_ai_threads_user_id", table_name="ai_threads")
    op.drop_table("ai_threads")
    op.drop_index("ix_osint_reports_query", table_name="osint_reports")
    op.drop_table("osint_reports")
    op.drop_table("custom_rules")
    op.drop_table("agents")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
