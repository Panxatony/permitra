"""rule status active and deleted

Revision ID: a1d9e6f24c05
Revises: f3a7c81b204e
Create Date: 2026-08-23 15:00:00.000000

Two states the workflow was missing.

`active` separates the approval decision from the rollout: until now a rule that
operations had implemented everywhere looked exactly like one nobody had touched
since the approval. Existing rules are converted by the same rule the running
code applies - every assigned component reports "implemented" - so the status
matches reality instead of being reset for everyone.

`deleted` makes the soft delete a state instead of an absence. Rules that carry
a `deleted_at` get it, which is what they have effectively been all along.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1d9e6f24c05'
down_revision: Union[str, Sequence[str], None] = 'f3a7c81b204e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()

    # PostgreSQL stores this column as a native enum type, so the new labels
    # have to exist before anything can be written with them. SQLite keeps the
    # column as text and needs nothing. ADD VALUE cannot run inside a
    # transaction block on older servers, hence the autocommit escape.
    if conn.dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            for label in ("active", "deleted"):
                conn.execute(sa.text(
                    f"ALTER TYPE rulestatus ADD VALUE IF NOT EXISTS '{label}'"))

    # Deleted rules first: a deleted rule must not be promoted to active below.
    conn.execute(sa.text(
        "UPDATE rules SET status = 'deleted' WHERE deleted_at IS NOT NULL"))

    # `active` is derived, not guessed: read the per-component implementation
    # status the same way the application does.
    rules = conn.execute(sa.text(
        "SELECT id, impl_status FROM rules WHERE status = 'approved'")).fetchall()
    if not rules:
        return

    import json

    assigned = {}
    for rule_id, _impl in rules:
        names = conn.execute(sa.text(
            "SELECT c.name FROM security_components c "
            "JOIN rule_components rc ON rc.component_id = c.id "
            "WHERE rc.rule_pk = :rid"), {"rid": rule_id}).fetchall()
        assigned[rule_id] = [n[0] for n in names]

    promote = []
    for rule_id, impl in rules:
        names = assigned.get(rule_id) or []
        if not names:
            continue
        status = impl if isinstance(impl, dict) else json.loads(impl or "{}")
        if all(status.get(name) == "implemented" for name in names):
            promote.append(rule_id)

    for rule_id in promote:
        conn.execute(sa.text("UPDATE rules SET status = 'active' WHERE id = :rid"),
                     {"rid": rule_id})


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(sa.text("UPDATE rules SET status = 'approved' WHERE status = 'active'"))
    # A rule that was deleted keeps its deleted_at; the status falls back to the
    # value it carried before, which for a soft delete was 'approved'.
    conn.execute(sa.text("UPDATE rules SET status = 'approved' WHERE status = 'deleted'"))
    # The enum labels stay: PostgreSQL cannot drop a value from a type in use,
    # and leaving them costs nothing once no row references them.
