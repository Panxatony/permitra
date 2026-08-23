"""a way in for a rule that was opened on the firewall first

Revision ID: e7f4a13c8b02
Revises: d5b3c92e14a7
Create Date: 2026-08-23 19:00:00.000000

Every rule needs somebody else's approval. That is the point of the four-eyes
principle, and it holds until three in the morning when an application is down
and the only approver is unreachable. The rule gets opened on the firewall, and
the state Permitra exists to abolish is back: no request, no justification, no
approval, and by the time the drift report notices, nobody remembers why.

A tool without a documented fast path does not prevent emergency changes. It
only prevents them from being recorded.

These columns are that path, and they are deliberately narrow: the reason is
mandatory free text, the declaration is permanent, and approval_due makes the
rule deactivate itself if nobody approves it afterwards. declared_at is never
cleared - it is what makes "how often do we do this?" answerable a year later,
which is the difference between a working control and a habit.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e7f4a13c8b02'
down_revision: Union[str, Sequence[str], None] = 'd5b3c92e14a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('rules', sa.Column('emergency_declared_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('rules', sa.Column('emergency_declared_by', sa.String(length=64),
                                     nullable=False, server_default=''))
    op.add_column('rules', sa.Column('emergency_reason', sa.Text(), nullable=False, server_default=''))
    op.add_column('rules', sa.Column('emergency_approval_due', sa.DateTime(timezone=True), nullable=True))
    op.create_index('ix_rules_emergency_approval_due', 'rules', ['emergency_approval_due'])


def downgrade() -> None:
    op.drop_index('ix_rules_emergency_approval_due', table_name='rules')
    for column in ('emergency_approval_due', 'emergency_reason',
                   'emergency_declared_by', 'emergency_declared_at'):
        op.drop_column('rules', column)
