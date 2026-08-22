"""settings table

Revision ID: d9a0ab2ddda8
Revises: e029926e5af1
Create Date: 2026-08-22 08:06:22.681997

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd9a0ab2ddda8'
down_revision: Union[str, Sequence[str], None] = 'e029926e5af1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'settings',
        sa.Column('key', sa.String(length=64), primary_key=True),
        sa.Column('value', sa.String(length=256), nullable=False, server_default=''),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('settings')
