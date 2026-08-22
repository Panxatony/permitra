"""english domain values

Revision ID: e8c1b45d90a7
Revises: d5b3f07ac218
Create Date: 2026-08-22 22:30:00.000000

The code language is English, so the stored domain values become English too:
rollout status per component, protection level per C/I/A goal and the position
relative to the P-A-P structure. Until now these were German and were displayed
untranslated, which meant the English interface showed "umgesetzt" and
"sehr hoch".

The German wording is not lost - it moves to the interface dictionary, keyed by
the English value. The mapping lives in app/domain_values.py so it has a single
documented home; this migration only applies it to existing rows.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


revision: str = 'e8c1b45d90a7'
down_revision: Union[str, Sequence[str], None] = 'd5b3f07ac218'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _translate_columns(bind, mapping: dict[str, str], table: str, columns: Sequence[str],
                       reverse: bool = False) -> None:
    """Rewrites simple string columns via the given mapping."""
    pairs = ((v, k) for k, v in mapping.items()) if reverse else mapping.items()
    for old, new in pairs:
        if old == new:
            continue
        for column in columns:
            bind.execute(
                text(f"UPDATE {table} SET {column} = :new WHERE {column} = :old"),  # noqa: S608
                # S608 rationale: table and column names come from the hard-coded
                # tuples below, never from input; the values are bound parameters.
                {"new": new, "old": old},
            )


def _translate_impl_status(bind, mapping: dict[str, str], reverse: bool = False) -> None:
    """Rewrites the values inside the impl_status JSON object.

    The keys are component names and stay untouched; only the status values are
    translated. Read-modify-write per row keeps this portable across SQLite and
    PostgreSQL instead of relying on a dialect-specific JSON function."""
    import json

    # The column types matter here: without them SQLAlchemy hands psycopg2 a
    # raw dict, which it cannot adapt. SQLite tolerates that, PostgreSQL does
    # not - the kind of difference the migrations-postgres CI job exists for.
    table = sa.table("rules",
                     sa.column("id", sa.Integer),
                     sa.column("impl_status", sa.JSON))
    lookup = {v: k for k, v in mapping.items()} if reverse else dict(mapping)
    rows = bind.execute(sa.select(table.c.id, table.c.impl_status)).fetchall()
    for row_id, raw in rows:
        if not raw:
            continue
        value = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(value, dict):
            continue
        translated = {k: lookup.get(v, v) for k, v in value.items()}
        if translated != value:
            bind.execute(
                sa.update(table).where(table.c.id == row_id).values(impl_status=translated)
            )


def upgrade() -> None:
    from app.domain_values import (
        LEGACY_IMPL_STATUS,
        LEGACY_PAP_LEVEL,
        LEGACY_PROTECTION_LEVEL,
    )

    bind = op.get_bind()
    _translate_columns(bind, LEGACY_PROTECTION_LEVEL, "zones", ("cia_c", "cia_i", "cia_a"))
    _translate_columns(bind, LEGACY_PAP_LEVEL, "zones", ("pap_level",))
    _translate_impl_status(bind, LEGACY_IMPL_STATUS)


def downgrade() -> None:
    from app.domain_values import (
        LEGACY_IMPL_STATUS,
        LEGACY_PAP_LEVEL,
        LEGACY_PROTECTION_LEVEL,
    )

    bind = op.get_bind()
    _translate_columns(bind, LEGACY_PROTECTION_LEVEL, "zones", ("cia_c", "cia_i", "cia_a"),
                       reverse=True)
    _translate_columns(bind, LEGACY_PAP_LEVEL, "zones", ("pap_level",), reverse=True)
    _translate_impl_status(bind, LEGACY_IMPL_STATUS, reverse=True)
