"""keep the values of a history entry beside its message

Revision ID: c4a1e07b52f3
Revises: b6c2f81a3d97
Create Date: 2026-08-23 17:00:00.000000

A history entry used to be translated as it was written, which froze it in
whichever language the instance was set to that day. An instance switched to
German therefore kept reading "Implemented on every component" forever, and the
implementation status came out as a Python dict repr.

The entry now stores the English template and, here, the values it takes, so
messages.render() can produce the sentence in the language of the reader.

Rows written before this keep a finished sentence in change_note and no values.
That is deliberate: an English one still translates, because the sentence is
itself a catalogue key, and a German one is left exactly as it was rather than
guessed at.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c4a1e07b52f3'
down_revision: Union[str, Sequence[str], None] = 'b6c2f81a3d97'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('rule_versions', sa.Column('change_values', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('rule_versions', 'change_values')
