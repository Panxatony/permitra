"""role change approver

Revision ID: 4d6e0f7ee14f
Revises: c792aca55f66
Create Date: 2026-08-21 09:21:58.163516

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4d6e0f7ee14f'
down_revision: Union[str, Sequence[str], None] = 'c792aca55f66'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Neue Rolle change_approver + Felder für die Zweitfreigabe von Matrix-Anträgen."""
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TYPE role ADD VALUE IF NOT EXISTS 'change_approver'")
    with op.batch_alter_table('zone_policy_changes', schema=None) as batch_op:
        batch_op.add_column(sa.Column('first_approved_by', sa.String(length=64),
                                      server_default='', nullable=False))
        batch_op.add_column(sa.Column('first_approved_at', sa.DateTime(timezone=True),
                                      nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('zone_policy_changes', schema=None) as batch_op:
        batch_op.drop_column('first_approved_at')
        batch_op.drop_column('first_approved_by')
