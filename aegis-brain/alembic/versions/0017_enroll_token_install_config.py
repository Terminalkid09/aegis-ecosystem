"""Allow one enrollment token to install both agents with connection config.

Revision ID: 0017_enroll_token_install_config
Revises: 0016_app_settings
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0017_enroll_token_install_config"
down_revision: Union[str, None] = "0016_app_settings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("enroll_tokens", sa.Column("used_agent_types", sa.JSON(), nullable=True))
    op.add_column("enroll_tokens", sa.Column("install_config", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("enroll_tokens", "install_config")
    op.drop_column("enroll_tokens", "used_agent_types")
