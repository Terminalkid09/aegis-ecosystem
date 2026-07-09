"""add is_demo, vendor, guard/nodetrace status, threat_reports

Revision ID: 0003_discovery_agent_status
Revises: 0002_discovery_center
Create Date: 2026-06-27
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0003_discovery_agent_status"
down_revision: Union[str, None] = "0002_discovery_center"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns(table_name: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table(table_name):
        return set()
    return {col["name"] for col in inspector.get_columns(table_name)}


def _add_column_once(table_name: str, column: sa.Column) -> None:
    if column.name not in _columns(table_name):
        op.add_column(table_name, column)


def _has_table(table_name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(table_name)


def upgrade() -> None:
    _add_column_once("agents", sa.Column("is_demo", sa.Boolean(), server_default=sa.text("false"), nullable=False))

    _add_column_once("discovered_hosts", sa.Column("mac_address", sa.String(length=17), nullable=True))
    _add_column_once("discovered_hosts", sa.Column("vendor", sa.String(length=100), nullable=True))
    _add_column_once("discovered_hosts", sa.Column("os_confidence", sa.Integer(), server_default="0", nullable=False))
    _add_column_once("discovered_hosts", sa.Column("guard_status", sa.String(length=30), server_default="not_deployed", nullable=False))
    _add_column_once("discovered_hosts", sa.Column("nodetrace_status", sa.String(length=30), server_default="not_deployed", nullable=False))

    if not _has_table("discovered_hosts") or "agent_status" in _columns("discovered_hosts"):
        if _has_table("discovered_hosts") and "agent_status" in _columns("discovered_hosts"):
            op.drop_column("discovered_hosts", "agent_status")

    _add_column_once("custom_rules", sa.Column("logic_type", sa.String(length=10), nullable=True))

    if not _has_table("threat_reports"):
        op.create_table(
            "threat_reports",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("alert_id", sa.Integer(), nullable=False),
            sa.Column("summary", sa.Text(), nullable=False),
            sa.Column("confidence", sa.String(length=20), nullable=False),
            sa.Column("recommended_actions", sa.JSON(), nullable=True),
            sa.Column("osint_data", sa.JSON(), nullable=True),
            sa.Column("ai_analysis", sa.Text(), nullable=True),
            sa.Column("is_auto_generated", sa.Boolean(), server_default=sa.text("true"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_threat_reports_alert_id", "threat_reports", ["alert_id"], unique=False)


def downgrade() -> None:
    op.drop_table("threat_reports")
    op.drop_column("custom_rules", "logic_type")
    if "agent_status" not in _columns("discovered_hosts"):
        op.add_column("discovered_hosts", sa.Column("agent_status", sa.String(length=30), server_default="not_deployed", nullable=False))
    op.drop_column("discovered_hosts", "nodetrace_status")
    op.drop_column("discovered_hosts", "guard_status")
    op.drop_column("discovered_hosts", "os_confidence")
    op.drop_column("discovered_hosts", "vendor")
    op.drop_column("discovered_hosts", "mac_address")
    op.drop_column("agents", "is_demo")
