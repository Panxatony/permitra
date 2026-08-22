"""audit hash chain and siem outbox

Revision ID: b7e1c4a9d2f0
Revises: fcfd7ac1a97b
Create Date: 2026-08-22 18:40:00.000000

Integrity protection (hash chain) and reliable SIEM delivery (#26).
Existing audit entries are chained retroactively during the upgrade, so that the
chain is verifiable without gaps starting from the first event.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.orm import Session


# revision identifiers, used by Alembic.
revision: str = 'b7e1c4a9d2f0'
down_revision: Union[str, Sequence[str], None] = 'fcfd7ac1a97b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('audit_events', sa.Column('prev_hash', sa.String(length=64), nullable=False, server_default=''))
    op.add_column('audit_events', sa.Column('hash', sa.String(length=64), nullable=False, server_default=''))
    op.add_column('audit_events', sa.Column('siem_status', sa.String(length=12), nullable=False, server_default='skipped'))
    op.add_column('audit_events', sa.Column('siem_attempts', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('audit_events', sa.Column('siem_sent_at', sa.DateTime(timezone=True), nullable=True))
    op.create_index('ix_audit_events_hash', 'audit_events', ['hash'])
    op.create_index('ix_audit_events_siem_status', 'audit_events', ['siem_status'])

    # Chain existing entries in order (identical hash logic as at runtime).
    from app.models import AuditEvent
    from app import audit

    session = Session(bind=op.get_bind())
    prev = audit.GENESIS
    for ev in session.query(AuditEvent).order_by(AuditEvent.id.asc()).all():
        ev.prev_hash = prev
        ev.hash = audit.event_hash(ev.ts, ev.category, ev.event, ev.actor,
                                   ev.object, ev.detail, ev.source_ip, ev.extra, prev)
        ev.siem_status = 'skipped'  # legacy records are not pushed retroactively
        prev = ev.hash
    session.commit()


def downgrade() -> None:
    op.drop_index('ix_audit_events_siem_status', table_name='audit_events')
    op.drop_index('ix_audit_events_hash', table_name='audit_events')
    op.drop_column('audit_events', 'siem_sent_at')
    op.drop_column('audit_events', 'siem_attempts')
    op.drop_column('audit_events', 'siem_status')
    op.drop_column('audit_events', 'hash')
    op.drop_column('audit_events', 'prev_hash')
