"""netbox import

Revision ID: 3dd692cf7d82
Revises: 089c4c5fbf5e
Create Date: 2026-08-22 16:47:57.636024

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3dd692cf7d82'
down_revision: Union[str, Sequence[str], None] = '089c4c5fbf5e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'netbox_config',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('url', sa.String(length=256), nullable=False, server_default=''),
        sa.Column('token_enc', sa.Text(), nullable=False, server_default=''),
        sa.Column('verify_tls', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('last_import_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        'netbox_prefixes',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('netbox_id', sa.Integer(), nullable=False, index=True),
        sa.Column('cidr', sa.String(length=64), nullable=False, index=True),
        sa.Column('status', sa.String(length=16), nullable=False, server_default=''),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('vrf', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('adopted', sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_table('netbox_prefixes')
    op.drop_table('netbox_config')
