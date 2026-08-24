"""a rule's requestor can be handed over, with the new one confirming

Revision ID: e83b1c4f26a9
Revises: d2e5f18a0c47
Create Date: 2026-08-24 21:00:00.000000

An architect changes department or company, and the rules they requested need a
new accountable person. The current requestor proposes a successor, who must
confirm taking the rule over - an accountable person is not assigned one without
consent, or the record would name someone who never agreed to it.

These columns hold the pending proposal; the requestor itself changes only on
confirmation.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'e83b1c4f26a9'
down_revision: Union[str, Sequence[str], None] = 'd2e5f18a0c47'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('rules', sa.Column('pending_requestor', sa.String(length=128),
                                     nullable=False, server_default=''))
    op.add_column('rules', sa.Column('handover_proposed_by', sa.String(length=64),
                                     nullable=False, server_default=''))
    op.add_column('rules', sa.Column('handover_proposed_at', sa.DateTime(timezone=True),
                                     nullable=True))


def downgrade() -> None:
    op.drop_column('rules', 'handover_proposed_at')
    op.drop_column('rules', 'handover_proposed_by')
    op.drop_column('rules', 'pending_requestor')
