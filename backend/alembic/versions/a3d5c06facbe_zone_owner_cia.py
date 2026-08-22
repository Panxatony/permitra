"""zone owner cia

Revision ID: a3d5c06facbe
Revises: d9a0ab2ddda8
Create Date: 2026-08-22 08:11:56.924215

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a3d5c06facbe'
down_revision: Union[str, Sequence[str], None] = 'd9a0ab2ddda8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('zones') as batch:
        batch.add_column(sa.Column('owner', sa.String(length=128), nullable=False, server_default=''))
        batch.add_column(sa.Column('cia_c', sa.String(length=16), nullable=False, server_default='normal'))
        batch.add_column(sa.Column('cia_i', sa.String(length=16), nullable=False, server_default='normal'))
        batch.add_column(sa.Column('cia_a', sa.String(length=16), nullable=False, server_default='normal'))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('zones') as batch:
        batch.drop_column('cia_a')
        batch.drop_column('cia_i')
        batch.drop_column('cia_c')
        batch.drop_column('owner')
