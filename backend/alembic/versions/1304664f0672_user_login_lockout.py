"""user login lockout

Revision ID: 1304664f0672
Revises: ef7157bcc152
Create Date: 2026-08-22 15:34:47.718188

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1304664f0672'
down_revision: Union[str, Sequence[str], None] = 'ef7157bcc152'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('users') as b:
        b.add_column(sa.Column('failed_logins', sa.Integer(), nullable=False, server_default='0'))
        b.add_column(sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('users') as b:
        b.drop_column('locked_until')
        b.drop_column('failed_logins')
