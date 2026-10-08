"""a component says how it enforces: firewall or micro-segmentation

Revision ID: f3a7c21d9e40
Revises: e2b9c47d1f05
Create Date: 2026-10-07 12:00:00.000000

Permitra documents who talks to whom; what it did not record is how a rule
is enforced - by a firewall at the zone transition, or by micro-segmentation
within a zone. Every check that separates the two keyed on the component
type being ACI, so a platform without an exporter could not be documented
at all. The component carries the answer now, derived once from the type
for everything that exists, and a generic micro-segmentation type names the
platforms Permitra generates nothing for.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'f3a7c21d9e40'
down_revision: Union[str, Sequence[str], None] = 'e2b9c47d1f05'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

ENFORCEMENT = sa.Enum('firewall', 'microsegmentation', name='enforcement')


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # The component type is a native enum there; the new member has to
        # exist before a row can carry it.
        op.execute("ALTER TYPE componenttype ADD VALUE IF NOT EXISTS 'microsegmentation'")
        ENFORCEMENT.create(bind, checkfirst=True)
    with op.batch_alter_table("security_components") as batch:
        batch.add_column(sa.Column("enforcement", ENFORCEMENT, nullable=False,
                                   server_default="firewall"))
        batch.add_column(sa.Column("platform", sa.String(64), nullable=False, server_default=""))
    # Derived once for what exists: ACI fabrics enforce within a zone.
    op.execute("UPDATE security_components SET enforcement = 'microsegmentation' WHERE type = 'aci'")


def downgrade() -> None:
    with op.batch_alter_table("security_components") as batch:
        batch.drop_column("platform")
        batch.drop_column("enforcement")
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        ENFORCEMENT.drop(bind, checkfirst=True)
