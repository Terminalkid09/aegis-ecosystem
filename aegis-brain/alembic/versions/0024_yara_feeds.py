"""signed YARA feeds and rule provenance

Revision ID: 0024
Revises: 0023
"""
from alembic import op
import sqlalchemy as sa

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("yara_rules", sa.Column("severity", sa.String(length=20), nullable=False, server_default="high"))
    op.add_column("yara_rules", sa.Column("description", sa.Text(), nullable=True))
    op.add_column("yara_rules", sa.Column("tags", sa.JSON(), nullable=True))
    op.add_column("yara_rules", sa.Column("mitre_technique_id", sa.String(length=20), nullable=True))
    op.add_column("yara_rules", sa.Column("source", sa.String(length=255), nullable=False, server_default="manual"))
    op.add_column("yara_rules", sa.Column("source_version", sa.String(length=100), nullable=True))
    op.add_column("yara_rules", sa.Column("checksum", sa.String(length=64), nullable=True))
    op.add_column("yara_rules", sa.Column("managed", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("yara_rules", sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_yara_rules_source", "yara_rules", ["source"])

    op.create_table(
        "yara_feed_state",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("feed_id", sa.String(length=64), nullable=True),
        sa.Column("key_id", sa.String(length=100), nullable=True),
        sa.Column("etag", sa.String(length=255), nullable=True),
        sa.Column("last_modified", sa.String(length=255), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("bundle_version", sa.String(length=100), nullable=True),
        sa.Column("rules_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_yara_feed_state_url", "yara_feed_state", ["url"], unique=True)
    op.create_index("ix_yara_feed_state_feed_id", "yara_feed_state", ["feed_id"])


def downgrade() -> None:
    op.drop_index("ix_yara_feed_state_feed_id", table_name="yara_feed_state")
    op.drop_index("ix_yara_feed_state_url", table_name="yara_feed_state")
    op.drop_table("yara_feed_state")
    op.drop_index("ix_yara_rules_source", table_name="yara_rules")
    op.drop_column("yara_rules", "last_synced_at")
    op.drop_column("yara_rules", "managed")
    op.drop_column("yara_rules", "checksum")
    op.drop_column("yara_rules", "source_version")
    op.drop_column("yara_rules", "source")
    op.drop_column("yara_rules", "mitre_technique_id")
    op.drop_column("yara_rules", "tags")
    op.drop_column("yara_rules", "description")
    op.drop_column("yara_rules", "severity")
