"""a component link says whether a packet can travel down it

Revision ID: c8f2a0d47b31
Revises: a4c7e21b98d3
Create Date: 2026-08-25 10:00:00.000000

The path analysis now routes over the component links instead of sorting the
hops by their north-south tier, so the links have become load-bearing: they
decide which firewalls a packet crosses, whether there is a way at all, and
whether a redundant second route exists that a rule also has to be on.

That makes it necessary to distinguish a link a packet can travel down from a
link that only documents a relationship. Everything recorded so far is the
former - transfer networks, OSPF adjacencies, BGP peerings - so the column
defaults to true and nothing changes for an existing estate.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'c8f2a0d47b31'
down_revision: Union[str, Sequence[str], None] = 'a4c7e21b98d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('component_links',
                  sa.Column('carries_transit', sa.Boolean(), nullable=False,
                            server_default=sa.true()))


def downgrade() -> None:
    op.drop_column('component_links', 'carries_transit')
