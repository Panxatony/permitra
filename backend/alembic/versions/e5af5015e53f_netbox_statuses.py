"""netbox statuses

Revision ID: e5af5015e53f
Revises: 3dd692cf7d82
Create Date: 2026-08-22 16:59:13.550268

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e5af5015e53f'
down_revision: Union[str, Sequence[str], None] = '3dd692cf7d82'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('netbox_config', sa.Column('statuses', sa.String(length=128), nullable=False, server_default='active,reserved'))


def downgrade() -> None:
    op.drop_column('netbox_config', 'statuses')
