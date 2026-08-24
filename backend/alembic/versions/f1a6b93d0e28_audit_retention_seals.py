"""collapse expired audit segments behind a seal, keeping the chain provable

Revision ID: f1a6b93d0e28
Revises: b3f7c28e91d5
Create Date: 2026-08-24 18:00:00.000000

audit_events grew without bound and held usernames and source IPs - personal
data with no retention period and no way to remove it, which GDPR Art. 5(1)(e)
and BSI CON.6 both require. The obstacle was the hash chain: deleting one event
breaks verification from that point forever.

The seal resolves it. A prefix of the chain, once past the retention period and
(when a SIEM is configured) delivered there, is deleted and replaced by one
row recording the boundary hash the first surviving event links back to and how
many events were removed. Verification starts from the newest seal instead of
genesis - provable chain, deleted personal data, evidence externalised to the
SIEM.

No behaviour changes on upgrade: the retention period defaults to 0 (keep
forever). This migration only adds the table; nothing is collapsed until an
admin sets a period.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'f1a6b93d0e28'
down_revision: Union[str, Sequence[str], None] = 'c9d4e82a51f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'audit_retention_seals',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('sealed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('boundary_event_id', sa.Integer(), nullable=False),
        sa.Column('boundary_hash', sa.String(length=64), nullable=False),
        sa.Column('collapsed_count', sa.Integer(), nullable=False),
        sa.Column('delivered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('attempts', sa.Integer(), nullable=False, server_default='0'),
    )
    op.create_index('ix_audit_retention_seals_sealed_at',
                    'audit_retention_seals', ['sealed_at'])


def downgrade() -> None:
    op.drop_index('ix_audit_retention_seals_sealed_at', table_name='audit_retention_seals')
    op.drop_table('audit_retention_seals')
