"""record what each uploaded configuration measured

Revision ID: d5b3c92e14a7
Revises: c4a1e07b52f3
Create Date: 2026-08-23 18:00:00.000000

The coverage figure answers "how much of this device is backed by an approved
security rule". A single figure says nothing about direction, and direction is
the signal: an estate at 94 percent that was at 98 last month is the one worth
looking at.

A trend needs measurements to plot, and there were none - the stored
configuration is replaced on every upload, so the previous one is gone. This
table keeps the summary of each upload. Append-only: rewriting a past
measurement would erase the movement it exists to show.

total and justified stay NULL when the format could not be read, which is a
measurement in its own right - we looked and could not tell, as opposed to
looking and finding nothing.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd5b3c92e14a7'
down_revision: Union[str, Sequence[str], None] = 'c4a1e07b52f3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'coverage_snapshots',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('component_id', sa.Integer(),
                  sa.ForeignKey('security_components.id', ondelete='CASCADE'), nullable=False),
        sa.Column('measured_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('recognised', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('total', sa.Integer(), nullable=True),
        sa.Column('justified', sa.Integer(), nullable=True),
        sa.Column('uploaded_by', sa.String(length=64), nullable=False, server_default=''),
    )
    op.create_index('ix_coverage_snapshots_component_id', 'coverage_snapshots', ['component_id'])


def downgrade() -> None:
    op.drop_index('ix_coverage_snapshots_component_id', table_name='coverage_snapshots')
    op.drop_table('coverage_snapshots')
