"""change extra json

Revision ID: 3721a4d2031a
Revises: 4cb54ef176fb
Create Date: 2026-08-21 19:09:53.065235

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3721a4d2031a'
down_revision: Union[str, Sequence[str], None] = '4cb54ef176fb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('zone_policy_changes', sa.Column('extra', sa.JSON(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('zone_policy_changes', 'extra')
