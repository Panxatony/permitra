"""user accounts auth tokens passkeys

Revision ID: eafa923712e7
Revises: 3721a4d2031a
Create Date: 2026-08-22 07:37:46.818498

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'eafa923712e7'
down_revision: Union[str, Sequence[str], None] = '3721a4d2031a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('users') as batch:
        batch.add_column(sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()))
        batch.add_column(sa.Column('totp_secret', sa.String(length=64), nullable=True))
        batch.add_column(sa.Column('totp_enabled', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table(
        'auth_tokens',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('purpose', sa.String(length=16), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False, index=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        'passkeys',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('credential_id', sa.Text(), nullable=False),
        sa.Column('public_key', sa.Text(), nullable=False),
        sa.Column('sign_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('name', sa.String(length=64), nullable=False, server_default='Passkey'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('passkeys')
    op.drop_table('auth_tokens')
    with op.batch_alter_table('users') as batch:
        batch.drop_column('totp_enabled')
        batch.drop_column('totp_secret')
        batch.drop_column('is_active')
