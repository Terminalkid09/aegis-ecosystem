"""store SMB NetNTLMv2 response material

Revision ID: 0005
Revises: 0004
"""
import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("credential_attempts", sa.Column("ntlm_hash", sa.String(1024), nullable=True))


def downgrade() -> None:
    op.drop_column("credential_attempts", "ntlm_hash")
