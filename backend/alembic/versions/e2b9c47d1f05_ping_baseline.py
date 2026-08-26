"""a rule may declare itself the ping baseline between two internal zones

Revision ID: e2b9c47d1f05
Revises: c8f2a0d47b31
Create Date: 2026-08-26 09:00:00.000000

Operations needs one fact before anything else when a system stops answering:
does the network reach it at all. A standing ICMP echo rule between two zones
the matrix already permits answers that, and nothing else - it is any-to-any on
purpose, which is why it has to be declared rather than merely written.

The column records that declaration. Everything already in the database was
written without it, so it defaults to false and no existing rule silently gains
an exemption from the risk assessment.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'e2b9c47d1f05'
down_revision: Union[str, Sequence[str], None] = 'c8f2a0d47b31'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('rules',
                  sa.Column('ping_baseline', sa.Boolean(), nullable=False,
                            server_default=sa.false()))


def downgrade() -> None:
    op.drop_column('rules', 'ping_baseline')
