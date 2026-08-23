"""whether a rule logs, and the second kind of refusal

Revision ID: a8e2d61f0c94
Revises: e7f4a13c8b02
Create Date: 2026-08-23 21:00:00.000000

Whether a rule logs is a property of the rule, and Permitra had no place for it.
So it appeared in no export, was never compared against the device, and could
not be reviewed - which for an application meant to hold the evidence about a
firewall ruleset is a strange gap: the ruleset was documented, its logging was
not. "Are accesses into the zone with very high protection requirement logged?"
had no answer here, although Permitra knows the zone, its protection level and
every rule crossing into it.

The default is `detailed`, and that is not a preference. Before this column
existed the Juniper exporter wrote `then log session-init session-close` onto
every single rule. `detailed` is exactly that line, so no existing rule's export
changes. Anything else would have altered, silently, what a device receives -
which is the one thing a migration in this application must not do.

`reject` joins `deny` in the same change because it is the same shape of gap:
drop discards silently and the caller waits for a timeout, reject answers and
the caller gets an immediate error. That is a deliberate choice - silence
outward, an answer inward - and it was not recorded anywhere.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a8e2d61f0c94'
down_revision: Union[str, Sequence[str], None] = 'e7f4a13c8b02'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

LOG_LEVELS = ('none', 'standard', 'detailed')


def upgrade() -> None:
    conn = op.get_bind()
    postgres = conn.dialect.name == "postgresql"

    if postgres:
        # ADD VALUE cannot run inside a transaction block on older servers, and
        # the label has to exist before any row can be written with it.
        with op.get_context().autocommit_block():
            conn.execute(sa.text("ALTER TYPE ruleaction ADD VALUE IF NOT EXISTS 'reject'"))
        sa.Enum(*LOG_LEVELS, name='rulelogging').create(conn, checkfirst=True)

    op.add_column('rules', sa.Column(
        'log_level',
        sa.Enum(*LOG_LEVELS, name='rulelogging', create_type=False) if postgres
        else sa.Enum(*LOG_LEVELS, name='rulelogging'),
        nullable=False, server_default='detailed'))


def downgrade() -> None:
    op.drop_column('rules', 'log_level')
    if op.get_bind().dialect.name == "postgresql":
        sa.Enum(name='rulelogging').drop(op.get_bind(), checkfirst=True)
    # The 'reject' label stays: dropping a value from a PostgreSQL enum means
    # recreating the type, and any rule already using it would have to be
    # rewritten to something it is not.
