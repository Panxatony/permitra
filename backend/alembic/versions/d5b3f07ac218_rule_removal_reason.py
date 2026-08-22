"""rule removal_reason (Löschvorschlag nach Zonen-Neubewertung)

Revision ID: d5b3f07ac218
Revises: c4f2a8e91d63
Create Date: 2026-08-22 20:10:00.000000

Wird ein Netz in eine andere Zone umgehängt, können Bestandsregeln dadurch
unzulässig werden. Sie gehen in den Review und tragen hier die Begründung des
Löschvorschlags.
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
