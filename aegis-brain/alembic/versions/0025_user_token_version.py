"""user token version

Revision ID: 0025_user_token_version
Revises: 0024
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0025_user_token_version"
down_revision: Union[str, None] = "0024"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("users", "token_version")
