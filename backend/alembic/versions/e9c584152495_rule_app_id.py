"""rule app id

Revision ID: e9c584152495
Revises: 6fa3629979ed
Create Date: 2026-08-22 17:33:54.574717

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e9c584152495'
down_revision: Union[str, Sequence[str], None] = '6fa3629979ed'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('rules', sa.Column('app_id', sa.String(length=64), nullable=False, server_default=''))
    op.create_index(op.f('ix_rules_app_id'), 'rules', ['app_id'])


def downgrade() -> None:
    op.drop_index(op.f('ix_rules_app_id'), table_name='rules')
    op.drop_column('rules', 'app_id')
