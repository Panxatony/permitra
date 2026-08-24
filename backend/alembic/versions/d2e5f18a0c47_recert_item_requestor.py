"""recertification worklist is keyed by requestor, not owner

Revision ID: d2e5f18a0c47
Revises: f1a6b93d0e28
Create Date: 2026-08-24 20:00:00.000000

A recertification campaign asks "is this rule still needed?" - a question only
the account that requested the rule can answer. The worklist was keyed by the
owner (Bearbeiter), the operations account that last rolled the rule out on the
devices; they implemented it, they did not decide it was needed. The column is
renamed to carry the requestor, and existing rows are repointed from the rule's
owner to its requestor.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'd2e5f18a0c47'
down_revision: Union[str, Sequence[str], None] = 'f1a6b93d0e28'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('recert_items') as batch:
        batch.alter_column('owner', new_column_name='requestor')
    # Repoint existing worklist items to the rule's requestor. Open campaigns
    # should ask the right person from now on rather than keep the wrong key.
    op.execute(sa.text(
        "UPDATE recert_items SET requestor = ("
        "  SELECT rules.requestor FROM rules WHERE rules.id = recert_items.rule_pk"
        ") WHERE EXISTS (SELECT 1 FROM rules WHERE rules.id = recert_items.rule_pk)"))


def downgrade() -> None:
    with op.batch_alter_table('recert_items') as batch:
        batch.alter_column('requestor', new_column_name='owner')
