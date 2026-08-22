"""user token valid from

Revision ID: ef7157bcc152
Revises: a3d5c06facbe
Create Date: 2026-08-22 12:48:51.280539

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ef7157bcc152'
down_revision: Union[str, Sequence[str], None] = 'a3d5c06facbe'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('token_valid_from', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'token_valid_from')
