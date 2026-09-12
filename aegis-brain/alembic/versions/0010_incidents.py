"""SOC incidents — group alerts, triage status, assignee, timeline.

Revision ID: 0010_incidents
Revises: 0009_agent_isolated
Create Date: 2026-09-05
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0010_incidents"
down_revision: Union[str, None] = "0009_agent_isolated"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(table_name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(table_name)


def upgrade() -> None:
    if not _has_table("incidents"):
        op.create_table(
            "incidents",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("title", sa.String(length=255), nullable=False),
            sa.Column("severity", sa.String(length=20), nullable=False, server_default="MEDIUM"),
            sa.Column("status", sa.String(length=30), nullable=False, server_default="open"),
            sa.Column("assignee_id", sa.Integer(), nullable=True),
            sa.Column("agent_id", sa.String(length=64), nullable=True),
            sa.Column("created_by", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["assignee_id"], ["users.id", ]),
            sa.ForeignKeyConstraint(["created_by"], ["users.id", ]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_incidents_status", "incidents", ["status"])
    if not _has_table("incident_alerts"):
        op.create_table(
            "incident_alerts",
            sa.Column("incident_id", sa.Integer(), nullable=False),
            sa.Column("alert_id", sa.Integer(), nullable=False),
            sa.Column("attached_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("incident_id", "alert_id"),
        )


def downgrade() -> None:
    op.drop_table("incident_alerts")
    op.drop_index("ix_incidents_status", table_name="incidents")
    op.drop_table("incidents")
