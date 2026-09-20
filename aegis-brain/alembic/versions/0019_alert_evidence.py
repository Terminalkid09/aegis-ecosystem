"""Alert evidence: contesto strutturato per il triage.

Perche' esiste
--------------
Gli alert comportamentali (soprattutto le anomalie NodeTrace) nascevano con
solo il tag nella description: PID/path/utente/network sempre N/A in UI, e
l'IP della connessione finiva nel campo process_name. Con `evidence` (JSON)
ogni alert porta con se' i fatti che lo hanno generato: endpoint remoto,
numero di connessioni, processi possessori, command line, memoria — quello
che un analista si aspetta di vedere nel pannello di dettaglio.

Revision ID: 0019_alert_evidence
Revises: 0018_remember_devices
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0019_alert_evidence"
down_revision: Union[str, None] = "0018_remember_devices"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("alerts", sa.Column("evidence", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("alerts", "evidence")
