"""user notify email

Revision ID: a96fa2a253d6
Revises: 1304664f0672
Create Date: 2026-08-22 16:01:42.592891

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a96fa2a253d6'
down_revision: Union[str, Sequence[str], None] = '1304664f0672'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('notify_email', sa.Boolean(), nullable=False, server_default=sa.true()))


def downgrade() -> None:
    op.drop_column('users', 'notify_email')
