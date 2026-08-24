"""requestor and owner become derived accounts, not typed names

Revision ID: c9d4e82a51f6
Revises: b3f7c28e91d5
Create Date: 2026-08-24 15:00:00.000000

The requestor is now the account that created the rule in Permitra, and the
owner (Bearbeiter) is the operations account that last maintained the rule's
implementation status. Both used to be free-text names - and a typed name can
be misspelled, cannot be notified, and matches nobody when the reports ask
whether the person still exists. An account can and does.

No schema change; this rewrites the data to match the new meaning:

- requestor := created_by, wherever a creator is recorded. Rows without one
  (legacy imports) keep their typed name - a wrong-shaped value beats an empty
  one there, and the reports flag it as matching no user anyway.
- owner := the author of the newest "Implementation status" version entry,
  which is exactly the act the field now records. Rules nobody has worked on
  the components yet become empty - the honest value, since the old typed name
  claimed a responsibility nobody had exercised.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'c9d4e82a51f6'
down_revision: Union[str, Sequence[str], None] = 'b3f7c28e91d5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Both spellings, because history written before the render() change holds
# finished German sentences rather than templates.
IMPL_NOTE_PREFIXES = ("Implementation status:", "Umsetzungsstatus:")


def upgrade() -> None:
    conn = op.get_bind()

    conn.execute(sa.text(
        "UPDATE rules SET requestor = created_by "
        "WHERE created_by IS NOT NULL AND created_by <> ''"))

    rows = conn.execute(sa.text(
        "SELECT rule_pk, change_note, changed_by FROM rule_versions "
        "ORDER BY rule_pk, version")).fetchall()
    last_worker: dict[int, str] = {}
    for rule_pk, note, changed_by in rows:
        if note and note.startswith(IMPL_NOTE_PREFIXES):
            last_worker[rule_pk] = changed_by or ""

    conn.execute(sa.text("UPDATE rules SET owner = ''"))
    for rule_pk, worker in last_worker.items():
        conn.execute(sa.text("UPDATE rules SET owner = :w WHERE id = :i"),
                     {"w": worker, "i": rule_pk})


def downgrade() -> None:
    # The typed names are gone; there is nothing truthful to restore them from.
    pass
