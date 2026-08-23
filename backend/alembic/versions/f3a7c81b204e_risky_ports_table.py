"""risky ports as maintainable data

Revision ID: f3a7c81b204e
Revises: e8c1b45d90a7
Create Date: 2026-08-23 09:00:00.000000

The services the risk analysis flags used to be a dictionary in the source.
That made the criteria invisible: an approver sees the hint before deciding and
an auditor asks by which standard it was raised, but neither could look the list
up. It becomes data here, seeded from the previous defaults so nothing changes
for an existing installation.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f3a7c81b204e'
down_revision: Union[str, Sequence[str], None] = 'e8c1b45d90a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    table = op.create_table(
        'risky_ports',
        sa.Column('id', sa.Integer(), primary_key=True),
        # Uniqueness comes from the index below - declaring it here as well
        # would leave PostgreSQL with two constraints for the same thing.
        sa.Column('port', sa.String(length=16), nullable=False),
        sa.Column('label', sa.String(length=128), nullable=False),
    )
    op.create_index('ix_risky_ports_port', 'risky_ports', ['port'], unique=True)

    from app.risk import DEFAULT_RISKY_PORTS

    op.bulk_insert(table, [{"port": port, "label": label}
                           for port, label in DEFAULT_RISKY_PORTS.items()])


def downgrade() -> None:
    op.drop_index('ix_risky_ports_port', table_name='risky_ports')
    op.drop_table('risky_ports')
