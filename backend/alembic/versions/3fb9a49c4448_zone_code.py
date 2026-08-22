"""zone code

Revision ID: 3fb9a49c4448
Revises: e5af5015e53f
Create Date: 2026-08-22 17:11:41.251075

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3fb9a49c4448'
down_revision: Union[str, Sequence[str], None] = 'e5af5015e53f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('zones', sa.Column('code', sa.String(length=8), nullable=False, server_default=''))


def downgrade() -> None:
    op.drop_column('zones', 'code')
