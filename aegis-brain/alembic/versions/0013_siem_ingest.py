"""SIEM ingest: event store (RANGE partitioned by month) + log sources

Revision ID: 0013_siem_ingest
Revises: 0012_audit_is_test
Create Date: 2026-09-15

Perché partizionato: la retention di un SIEM elimina milioni di righe come
operazione di routine. Su una tabella piatta è un DELETE lento che gonfia il
WAL e richiede VACUUM; con partizioni mensili è un DROP PARTITION istantaneo.
PostgreSQL richiede che la chiave primaria contenga la chiave di partizione,
quindi la PK è `(id, time)`.

Su dialetti non-PostgreSQL (suite su SQLite) la stessa tabella nasce piatta:
l'applicazione non dipende mai dalla partizione.
"""
from datetime import datetime, timedelta
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0013_siem_ingest"
down_revision: Union[str, None] = "0012_audit_is_test"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(table_name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(table_name)


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


_PARTITIONED_DDL = """
CREATE TABLE siem_events (
    id BIGSERIAL NOT NULL,
    time TIMESTAMPTZ NOT NULL,
    source VARCHAR(128) NOT NULL,
    source_type VARCHAR(64) NOT NULL,
    event_id VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL DEFAULT 'INFO',
    ocsf_class_uid INTEGER NOT NULL DEFAULT 0,
    hostname VARCHAR(255),
    ip VARCHAR(45),
    "user" VARCHAR(255),
    user_domain VARCHAR(255),
    process_name VARCHAR(512),
    pid INTEGER,
    parent_process_name VARCHAR(512),
    parent_pid INTEGER,
    process_path TEXT,
    command_line TEXT,
    file_path TEXT,
    file_name VARCHAR(512),
    file_hash VARCHAR(128),
    src_ip VARCHAR(45),
    src_port INTEGER,
    dst_ip VARCHAR(45),
    dst_port INTEGER,
    protocol VARCHAR(16),
    url TEXT,
    http_method VARCHAR(16),
    http_status INTEGER,
    user_agent TEXT,
    domain VARCHAR(255),
    dns_query VARCHAR(512),
    signature VARCHAR(512),
    signature_id VARCHAR(64),
    category VARCHAR(128),
    message TEXT,
    message_id VARCHAR(64),
    search_text TEXT,
    extra JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, time)
) PARTITION BY RANGE (time)
"""

_SIEM_INDEXES = (
    ("ix_siem_events_time", "(time)"),
    ("ix_siem_events_source", "(source)"),
    ("ix_siem_events_source_type", "(source_type)"),
    ("ix_siem_events_event_id", "(event_id)"),
    ("ix_siem_events_severity", "(severity)"),
    ("ix_siem_events_src_ip", "(src_ip)"),
    ("ix_siem_events_dst_ip", "(dst_ip)"),
    ("ix_siem_events_source_time", "(source, time)"),
)

_FLAT_COLUMNS = (
    sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
    sa.Column("time", sa.DateTime(timezone=True), nullable=False),
    sa.Column("source", sa.String(length=128), nullable=False),
    sa.Column("source_type", sa.String(length=64), nullable=False),
    sa.Column("event_id", sa.String(length=64), nullable=False),
    sa.Column("severity", sa.String(length=16), nullable=False, server_default="INFO"),
    sa.Column("ocsf_class_uid", sa.Integer(), nullable=False, server_default="0"),
    sa.Column("hostname", sa.String(length=255), nullable=True),
    sa.Column("ip", sa.String(length=45), nullable=True),
    sa.Column("user", sa.String(length=255), nullable=True),
    sa.Column("user_domain", sa.String(length=255), nullable=True),
    sa.Column("process_name", sa.String(length=512), nullable=True),
    sa.Column("pid", sa.Integer(), nullable=True),
    sa.Column("parent_process_name", sa.String(length=512), nullable=True),
    sa.Column("parent_pid", sa.Integer(), nullable=True),
    sa.Column("process_path", sa.Text(), nullable=True),
    sa.Column("command_line", sa.Text(), nullable=True),
    sa.Column("file_path", sa.Text(), nullable=True),
    sa.Column("file_name", sa.String(length=512), nullable=True),
    sa.Column("file_hash", sa.String(length=128), nullable=True),
    sa.Column("src_ip", sa.String(length=45), nullable=True),
    sa.Column("src_port", sa.Integer(), nullable=True),
    sa.Column("dst_ip", sa.String(length=45), nullable=True),
    sa.Column("dst_port", sa.Integer(), nullable=True),
    sa.Column("protocol", sa.String(length=16), nullable=True),
    sa.Column("url", sa.Text(), nullable=True),
    sa.Column("http_method", sa.String(length=16), nullable=True),
    sa.Column("http_status", sa.Integer(), nullable=True),
    sa.Column("user_agent", sa.Text(), nullable=True),
    sa.Column("domain", sa.String(length=255), nullable=True),
    sa.Column("dns_query", sa.String(length=512), nullable=True),
    sa.Column("signature", sa.String(length=512), nullable=True),
    sa.Column("signature_id", sa.String(length=64), nullable=True),
    sa.Column("category", sa.String(length=128), nullable=True),
    sa.Column("message", sa.Text(), nullable=True),
    sa.Column("message_id", sa.String(length=64), nullable=True),
    sa.Column("search_text", sa.Text(), nullable=True),
    sa.Column("extra", sa.JSON(), nullable=True),
    sa.Column("created_at", sa.DateTime(timezone=True),
              server_default=sa.text("now()"), nullable=False),
)


def _month_start(moment: datetime) -> datetime:
    return moment.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _next_month(moment: datetime) -> datetime:
    start = _month_start(moment)
    return (start + timedelta(days=32)).replace(day=1)


def _create_month_partition(month_start: datetime) -> None:
    """Partizione mensile `siem_events_YYYY_MM` (idempotente)."""
    name = f"siem_events_{month_start:%Y_%m}"
    end = _next_month(month_start)
    op.execute(
        f"CREATE TABLE IF NOT EXISTS {name} PARTITION OF siem_events "
        f"FOR VALUES FROM ('{month_start:%Y-%m-%d}') TO ('{end:%Y-%m-%d}')"
    )


def upgrade() -> None:
    if not _has_table("siem_events"):
        if _is_postgres():
            op.execute(_PARTITIONED_DDL)
            # Default partition: nessun evento viene rifiutato perché "manca la
            # partizione del mese". Le partizioni dedicate (mese corrente e
            # successivo) servono al query pruning e alla retention.
            op.execute("CREATE TABLE IF NOT EXISTS siem_events_default "
                       "PARTITION OF siem_events DEFAULT")
            now = datetime.utcnow()
            _create_month_partition(_month_start(now))
            _create_month_partition(_next_month(now))
            for name, columns in _SIEM_INDEXES:
                op.execute(f"CREATE INDEX IF NOT EXISTS {name} ON siem_events {columns}")
        else:
            op.create_table("siem_events", *_FLAT_COLUMNS,
                            sa.PrimaryKeyConstraint("id"))
            for name, columns in (
                ("ix_siem_events_time", ["time"]),
                ("ix_siem_events_source", ["source"]),
                ("ix_siem_events_source_type", ["source_type"]),
                ("ix_siem_events_event_id", ["event_id"]),
                ("ix_siem_events_severity", ["severity"]),
                ("ix_siem_events_src_ip", ["src_ip"]),
                ("ix_siem_events_dst_ip", ["dst_ip"]),
            ):
                op.create_index(name, "siem_events", columns)

    if not _has_table("log_sources"):
        op.create_table(
            "log_sources",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("source_type", sa.String(length=64), nullable=False),
            sa.Column("parser", sa.String(length=64), nullable=False),
            sa.Column("description", sa.String(length=255), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
            sa.Column("events_total", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("events_invalid", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.text("now()"), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_log_sources_name", "log_sources", ["name"], unique=True)


def downgrade() -> None:
    if _has_table("siem_events"):
        op.execute("DROP TABLE siem_events CASCADE")
    if _has_table("log_sources"):
        op.drop_index("ix_log_sources_name", table_name="log_sources")
        op.drop_table("log_sources")
