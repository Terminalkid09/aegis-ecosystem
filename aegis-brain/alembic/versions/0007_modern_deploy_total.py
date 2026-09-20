"""modern deploy jobs + enroll tokens + aegis total

Revision ID: 0007_modern_deploy_total
Revises: 0006
Create Date: 2026-09-05
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0007_modern_deploy_total"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(table_name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(table_name)


def upgrade() -> None:
    if not _has_table("enroll_tokens"):
        op.create_table(
            "enroll_tokens",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("token_hash", sa.String(length=128), nullable=False),
            sa.Column("label", sa.String(length=255), nullable=True),
            sa.Column("agent_type", sa.String(length=50), nullable=False, server_default="aegis-guard"),
            sa.Column("created_by", sa.Integer(), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("used_by_hostname", sa.String(length=255), nullable=True),
            sa.Column("revoked", sa.Boolean(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_enroll_tokens_token_hash", "enroll_tokens", ["token_hash"], unique=True)

    if not _has_table("deploy_jobs"):
        op.create_table(
            "deploy_jobs",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("agent_type", sa.String(length=50), nullable=False, server_default="nodetrace"),
            sa.Column("agent_version", sa.String(length=50), nullable=False, server_default="latest"),
            sa.Column("targets", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("status", sa.String(length=30), nullable=False, server_default="queued"),
            sa.Column("results", sa.JSON(), nullable=True),
            sa.Column("created_by", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    if not _has_table("deploy_credentials"):
        op.create_table(
            "deploy_credentials",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("job_id", sa.Integer(), nullable=False),
            sa.Column("username", sa.String(length=255), nullable=False),
            sa.Column("method", sa.String(length=20), nullable=False, server_default="ssh"),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.ForeignKeyConstraint(["job_id"], ["deploy_jobs.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_deploy_credentials_job_id", "deploy_credentials", ["job_id"])

    if not _has_table("total_reports"):
        op.create_table(
            "total_reports",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("sha256", sa.String(length=64), nullable=False),
            sa.Column("filename", sa.String(length=512), nullable=False),
            sa.Column("kind", sa.String(length=30), nullable=False, server_default="file"),
            sa.Column("score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("verdict", sa.String(length=30), nullable=False, server_default="unknown"),
            sa.Column("engines", sa.JSON(), nullable=True),
            sa.Column("files", sa.JSON(), nullable=True),
            sa.Column("sbom", sa.JSON(), nullable=True),
            sa.Column("ai_summary", sa.Text(), nullable=True),
            sa.Column("disclaimer_accepted_by", sa.Integer(), nullable=True),
            sa.Column("created_by", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
            sa.ForeignKeyConstraint(["disclaimer_accepted_by"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_total_reports_sha256", "total_reports", ["sha256"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_total_reports_sha256", table_name="total_reports")
    op.drop_table("total_reports")
    op.drop_index("ix_deploy_credentials_job_id", table_name="deploy_credentials")
    op.drop_table("deploy_credentials")
    op.drop_table("deploy_jobs")
    op.drop_index("ix_enroll_tokens_token_hash", table_name="enroll_tokens")
    op.drop_table("enroll_tokens")
