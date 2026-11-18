"""campaigns, sensor fleet, topologies and shadow lab runs

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-17 00:00:00.000000
"""
import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "campaigns",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(24), nullable=False, server_default="active"),
        sa.Column("fingerprint", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_campaigns_name", "campaigns", ["name"], unique=True)
    op.create_index("ix_campaigns_status", "campaigns", ["status"])

    op.create_table(
        "sensor_nodes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("node_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("site", sa.String(64), nullable=False, server_default="default"),
        sa.Column("status", sa.String(24), nullable=False, server_default="pending"),
        sa.Column("key_hash", sa.String(128), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("config_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("applied_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_sensor_nodes_node_id", "sensor_nodes", ["node_id"], unique=True)
    op.create_index("ix_sensor_nodes_site", "sensor_nodes", ["site"])
    op.create_index("ix_sensor_nodes_status", "sensor_nodes", ["status"])

    op.create_table(
        "topologies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("spec", sa.JSON(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_topologies_name", "topologies", ["name"], unique=True)

    op.create_table(
        "lab_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.String(64), nullable=False),
        sa.Column("topology_id", sa.Integer(), sa.ForeignKey("topologies.id", ondelete="SET NULL"), nullable=True),
        sa.Column("scenario_id", sa.String(64), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False, server_default="shadow"),
        sa.Column("status", sa.String(24), nullable=False, server_default="running"),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_lab_runs_run_id", "lab_runs", ["run_id"], unique=True)
    op.create_index("ix_lab_runs_scenario_id", "lab_runs", ["scenario_id"])
    op.create_index("ix_lab_runs_status", "lab_runs", ["status"])


def downgrade() -> None:
    op.drop_table("lab_runs")
    op.drop_table("topologies")
    op.drop_table("sensor_nodes")
    op.drop_table("campaigns")
