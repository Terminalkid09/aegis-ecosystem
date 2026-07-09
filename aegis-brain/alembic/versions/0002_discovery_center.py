"""discovery center and reputation

Revision ID: 0002_discovery_center
Revises: 0001_initial_schema
Create Date: 2026-06-26
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0002_discovery_center"
down_revision: Union[str, None] = "0001_initial_schema"
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
    _add_column_once("custom_rules", sa.Column("mitre_tactic", sa.String(length=100), nullable=True))
    _add_column_once("custom_rules", sa.Column("mitre_technique", sa.String(length=100), nullable=True))
    _add_column_once("custom_rules", sa.Column("mitre_technique_id", sa.String(length=20), nullable=True))
    _add_column_once("custom_rules", sa.Column("conditions", sa.JSON(), nullable=True))
    _add_column_once("custom_rules", sa.Column("whitelist", sa.JSON(), nullable=True))
    _add_column_once("custom_rules", sa.Column("auto_remediation", sa.String(length=50), nullable=True))
    _add_column_once("custom_rules", sa.Column("trigger_count", sa.Integer(), server_default="0", nullable=False))
    _add_column_once("custom_rules", sa.Column("last_triggered", sa.DateTime(timezone=True), nullable=True))

    if not _has_table("remediation_actions"):
        op.create_table(
            "remediation_actions",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("alert_id", sa.Integer(), nullable=False),
            sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("action", sa.String(length=50), nullable=False),
            sa.Column("target", sa.String(length=255), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False),
            sa.Column("executed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("details", sa.Text(), nullable=True),
            sa.ForeignKeyConstraint(["agent_id"], ["agents.agent_id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )

    if not _has_table("discovered_hosts"):
        op.create_table(
            "discovered_hosts",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("ip_address", sa.String(length=45), nullable=False),
            sa.Column("hostname", sa.String(length=255), nullable=True),
            sa.Column("os_guess", sa.String(length=100), nullable=True),
            sa.Column("status", sa.String(length=30), nullable=False),
            sa.Column("open_ports", sa.JSON(), nullable=True),
            sa.Column("agent_status", sa.String(length=30), nullable=False),
            sa.Column("source", sa.String(length=50), nullable=False),
            sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_discovered_hosts_ip_address", "discovered_hosts", ["ip_address"], unique=True)

    if not _has_table("ip_reputations"):
        op.create_table(
            "ip_reputations",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("ip_address", sa.String(length=45), nullable=False),
            sa.Column("label", sa.String(length=30), nullable=False),
            sa.Column("confidence", sa.Integer(), nullable=False),
            sa.Column("source", sa.String(length=100), nullable=False),
            sa.Column("details", sa.JSON(), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_ip_reputations_ip_address", "ip_reputations", ["ip_address"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_ip_reputations_ip_address", table_name="ip_reputations")
    op.drop_table("ip_reputations")
    op.drop_index("ix_discovered_hosts_ip_address", table_name="discovered_hosts")
    op.drop_table("discovered_hosts")
    op.drop_table("remediation_actions")
    op.drop_column("custom_rules", "last_triggered")
    op.drop_column("custom_rules", "trigger_count")
    op.drop_column("custom_rules", "auto_remediation")
    op.drop_column("custom_rules", "whitelist")
    op.drop_column("custom_rules", "conditions")
    op.drop_column("custom_rules", "mitre_technique_id")
    op.drop_column("custom_rules", "mitre_technique")
    op.drop_column("custom_rules", "mitre_tactic")
