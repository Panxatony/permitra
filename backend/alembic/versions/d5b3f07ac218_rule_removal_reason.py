"""rule removal_reason (removal proposal after zone re-evaluation)

Revision ID: d5b3f07ac218
Revises: c4f2a8e91d63
Create Date: 2026-08-22 20:10:00.000000

When a network is moved to a different zone, existing rules can become invalid
as a result. They go into review and carry the justification for the removal
proposal here.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd5b3f07ac218'
down_revision: Union[str, Sequence[str], None] = 'c4f2a8e91d63'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('rules', sa.Column('removal_reason', sa.String(length=255),
                                     nullable=False, server_default=''))


def downgrade() -> None:
    op.drop_column('rules', 'removal_reason')
