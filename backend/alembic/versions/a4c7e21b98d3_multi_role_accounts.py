"""an account can hold several roles, without eroding the four-eyes principle

Revision ID: a4c7e21b98d3
Revises: e83b1c4f26a9
Create Date: 2026-08-24 21:30:00.000000

A User had exactly one role, but real deployments are smaller than the role
split assumes: the same person is often architect *and* operations, or an
approver who also writes rules. One account per hat means juggling logins, or
handing someone a role they should not have full-time (#78).

`user_roles` holds the set; permission is the union of its rows. The old
`users.role` column stays as the primary role for display - the badge, the
landing route - and is derived from the set on every write, so it can never
promise more than the account actually holds.

This does not loosen separation of duties. The four-eyes checks key on the
acting *account*, not on a role: an account holding both architect and
change_approver still cannot approve a rule it requested, created or submitted,
and the second approval on a zone or matrix change must still come from a
different account. Two hats on one person is one person.

The upgrade carries every existing role across unchanged - each account ends up
holding exactly the one role it had, so nothing gains permission here.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'a4c7e21b98d3'
down_revision: Union[str, Sequence[str], None] = 'e83b1c4f26a9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

ROLE_ENUM = sa.Enum('architect', 'operations', 'change_approver', 'admin', name='role')


def upgrade() -> None:
    op.create_table(
        'user_roles',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(),
                  sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('role', ROLE_ENUM, nullable=False),
        sa.UniqueConstraint('user_id', 'role', name='uq_user_roles_user_role'),
    )
    op.create_index('ix_user_roles_user_id', 'user_roles', ['user_id'])

    # Carry every account's single role into the set unchanged. Written as one
    # INSERT ... SELECT so it holds for any number of accounts and needs no
    # Python-side model, which would drift from this file over time.
    op.execute(
        "INSERT INTO user_roles (user_id, role) SELECT id, role FROM users"
    )


def downgrade() -> None:
    # users.role was kept in step with the set all along, so dropping the table
    # leaves every account on its primary role - no data to carry back.
    op.drop_index('ix_user_roles_user_id', table_name='user_roles')
    op.drop_table('user_roles')
