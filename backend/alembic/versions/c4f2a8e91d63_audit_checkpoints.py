"""audit checkpoints (anchoring the end of the chain)

Revision ID: c4f2a8e91d63
Revises: b7e1c4a9d2f0
Create Date: 2026-08-22 19:20:00.000000

The hash chain detects changes within the existing records, but not the
truncation of the most recent entries. Checkpoints record the current state and
are forwarded to the SIEM – there they are beyond the reach of an attacker with
database access.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c4f2a8e91d63'
down_revision: Union[str, Sequence[str], None] = 'b7e1c4a9d2f0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'audit_checkpoints',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('ts', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_event_id', sa.Integer(), nullable=False),
        sa.Column('event_count', sa.Integer(), nullable=False),
        sa.Column('head_hash', sa.String(length=64), nullable=False),
        sa.Column('delivered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('attempts', sa.Integer(), nullable=False, server_default='0'),
    )
    op.create_index('ix_audit_checkpoints_ts', 'audit_checkpoints', ['ts'])


def downgrade() -> None:
    op.drop_index('ix_audit_checkpoints_ts', table_name='audit_checkpoints')
    op.drop_table('audit_checkpoints')
