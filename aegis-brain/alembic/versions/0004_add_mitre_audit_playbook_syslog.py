"""add mitre fields to alerts, add audit_log, playbook, syslog tables

Revision ID: 0004
Revises: 0003_discovery_agent_status
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0004'
down_revision: Union[str, None] = '0003_discovery_agent_status'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add MITRE ATT&CK columns to alerts
    op.add_column('alerts', sa.Column('mitre_tactic_id', sa.String(20), nullable=True))
    op.add_column('alerts', sa.Column('mitre_technique_id', sa.String(20), nullable=True))
    op.add_column('alerts', sa.Column('mitre_tactic_name', sa.String(200), nullable=True))
    op.add_column('alerts', sa.Column('mitre_technique_name', sa.String(200), nullable=True))

    # AuditLog table
    op.create_table('audit_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('username', sa.String(150), nullable=True),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('resource', sa.String(255), nullable=False),
        sa.Column('resource_id', sa.String(100), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(500), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])
    op.create_index('ix_audit_logs_created_at', 'audit_logs', ['created_at'])
    op.create_index('ix_audit_logs_user_id', 'audit_logs', ['user_id'])

    # Playbook table
    op.create_table('playbooks',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
        sa.Column('trigger_event_type', sa.String(100), nullable=True),
        sa.Column('trigger_severity', sa.String(20), nullable=True),
        sa.Column('trigger_process_name', sa.String(255), nullable=True),
        sa.Column('trigger_condition', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )

    # PlaybookAction table
    op.create_table('playbook_actions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('playbook_id', sa.Integer(), sa.ForeignKey('playbooks.id', ondelete='CASCADE'), nullable=False),
        sa.Column('action_type', sa.String(50), nullable=False),
        sa.Column('target', sa.String(255), nullable=False),
        sa.Column('params', sa.JSON(), nullable=True),
        sa.Column('order', sa.Integer(), default=0, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )

    # PlaybookExecution table
    op.create_table('playbook_executions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('playbook_id', sa.Integer(), sa.ForeignKey('playbooks.id', ondelete='CASCADE'), nullable=False),
        sa.Column('alert_id', sa.Integer(), sa.ForeignKey('alerts.id', ondelete='SET NULL'), nullable=True),
        sa.Column('triggered_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('status', sa.String(20), default='pending', nullable=False),
        sa.Column('result', sa.JSON(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )

    # SyslogEvent table
    op.create_table('syslog_events',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('facility', sa.Integer(), nullable=True),
        sa.Column('severity', sa.Integer(), nullable=True),
        sa.Column('hostname', sa.String(255), nullable=True),
        sa.Column('app_name', sa.String(255), nullable=True),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('raw', sa.Text(), nullable=True),
        sa.Column('processed', sa.Boolean(), default=False, nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_syslog_events_timestamp', 'syslog_events', ['timestamp'])


def downgrade() -> None:
    op.drop_column('alerts', 'mitre_technique_name')
    op.drop_column('alerts', 'mitre_tactic_name')
    op.drop_column('alerts', 'mitre_technique_id')
    op.drop_column('alerts', 'mitre_tactic_id')
    op.drop_table('syslog_events')
    op.drop_table('playbook_executions')
    op.drop_table('playbook_actions')
    op.drop_table('playbooks')
    op.drop_table('audit_logs')
