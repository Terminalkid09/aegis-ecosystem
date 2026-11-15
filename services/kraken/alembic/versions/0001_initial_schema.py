"""initial schema

Revision ID: 0001
Revises: 
Create Date: 2024-01-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('username', sa.String(64), nullable=False, unique=True),
        sa.Column('hashed_password', sa.String(256), nullable=False),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('is_admin', sa.Boolean(), default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_users_username', 'users', ['username'])

    op.create_table(
        'attack_events',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('session_id', sa.String(64), nullable=False, unique=True),
        sa.Column('attacker_ip', sa.String(45), nullable=False),
        sa.Column('attacker_port', sa.Integer(), nullable=True),
        sa.Column('sensor_type', sa.String(32), nullable=False),
        sa.Column('sensor_port', sa.Integer(), nullable=True),
        sa.Column('timestamp_start', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('timestamp_end', sa.DateTime(timezone=True), nullable=True),
        sa.Column('country', sa.String(64), nullable=True),
        sa.Column('city', sa.String(64), nullable=True),
        sa.Column('latitude', sa.Float(), nullable=True),
        sa.Column('longitude', sa.Float(), nullable=True),
        sa.Column('asn', sa.String(128), nullable=True),
        sa.Column('isp', sa.String(128), nullable=True),
        sa.Column('is_known_threat', sa.Boolean(), default=False),
        sa.Column('threat_tags', sa.String(256), nullable=True),
    )
    op.create_index('ix_attack_events_session_id', 'attack_events', ['session_id'])
    op.create_index('ix_attack_events_attacker_ip', 'attack_events', ['attacker_ip'])
    op.create_index('ix_attack_events_sensor_type', 'attack_events', ['sensor_type'])
    op.create_index('ix_attack_events_timestamp', 'attack_events', ['timestamp_start'])
    op.create_index('ix_attack_events_ip_sensor', 'attack_events', ['attacker_ip', 'sensor_type'])

    op.create_table(
        'attack_commands',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('event_id', sa.Integer(), sa.ForeignKey('attack_events.id', ondelete='CASCADE'), nullable=False),
        sa.Column('command', sa.Text(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        'credential_attempts',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('event_id', sa.Integer(), sa.ForeignKey('attack_events.id', ondelete='CASCADE'), nullable=False),
        sa.Column('username', sa.String(128), nullable=True),
        sa.Column('password', sa.String(256), nullable=True),
        sa.Column('success', sa.Boolean(), default=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table('credential_attempts')
    op.drop_table('attack_commands')
    op.drop_table('attack_events')
    op.drop_table('users')
