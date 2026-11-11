"""a read-only role for audits

Revision ID: c4a91e7d3f26
Revises: b7d3f09c1e52
Create Date: 2026-11-11 16:00:00.000000

Supporting an audit is one of the three things version one is for, and until
now nobody could simply look: the audit log was the admin's, reports and
recertification belonged to the three working roles, and every one of those
roles can write. An auditor needed two accounts, both able to change what they
were there to examine.

`auditor` is a new label of the existing `role` type. SQLite stores the column
as text and needs nothing; PostgreSQL needs the label added to the type before
a row can carry it.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c4a91e7d3f26'
down_revision: Union[str, Sequence[str], None] = 'b7d3f09c1e52'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    if conn.dialect.name == "postgresql":
        # ADD VALUE cannot run inside a transaction block on older servers.
        with op.get_context().autocommit_block():
            conn.execute(sa.text("ALTER TYPE role ADD VALUE IF NOT EXISTS 'auditor'"))


def downgrade() -> None:
    # The older code does not know the label and could not load an account
    # carrying it. Such an account must not come back holding a working role it
    # was never given, so it is switched off: the row stays for the audit trail
    # that names it, the placeholder role cannot be used, and an admin who
    # reactivates it decides on the role. PostgreSQL cannot drop a label from
    # an enum type; it stays behind unused, and `IF NOT EXISTS` makes the next
    # upgrade pass over it.
    conn = op.get_bind()
    conn.execute(sa.text("UPDATE users SET is_active = false, role = 'architect' "
                         "WHERE role = 'auditor'"))
    conn.execute(sa.text("UPDATE user_roles SET role = 'architect' WHERE role = 'auditor'"))
