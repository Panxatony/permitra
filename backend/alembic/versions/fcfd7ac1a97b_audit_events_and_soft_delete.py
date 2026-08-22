"""audit events and soft delete

Revision ID: fcfd7ac1a97b
Revises: e9c584152495
Create Date: 2026-08-22 17:47:32.528359

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'fcfd7ac1a97b'
down_revision: Union[str, Sequence[str], None] = 'e9c584152495'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('rules', sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        'audit_events',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('ts', sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column('category', sa.String(length=24), nullable=False, index=True),
        sa.Column('event', sa.String(length=48), nullable=False),
        sa.Column('actor', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('object', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('detail', sa.Text(), nullable=False, server_default=''),
        sa.Column('source_ip', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('extra', sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('audit_events')
    op.drop_column('rules', 'deleted_at')
