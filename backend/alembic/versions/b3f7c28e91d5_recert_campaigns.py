"""recertification as a decision about a rule, not a calendar

Revision ID: b3f7c28e91d5
Revises: a8e2d61f0c94
Create Date: 2026-08-24 09:00:00.000000

Permitra checked which rules reach their valid_until and deactivated them. That
is expiry control, and the page carrying the name "recertification" promised
more than that: BSI NET.3.2 asks that the ruleset is reviewed regularly, in
full - is each rule still needed, still scoped correctly, still owned by
someone who exists. The gap was not the check but that nobody was ever asked.

Two tables carry the process: a campaign (scope, cut-off, and the report of who
confirmed what - the deliverable an auditor actually asks for) and its items,
one per rule in scope at creation, each holding exactly one recorded decision.

Two columns land on the rule itself: last_confirmed_at / last_confirmed_by.
"When did somebody last deliberately confirm that this rule is still needed?"
is the auditor's question, and it deserves an answer on the rule rather than a
join through campaign history. NULL is the honest starting value - no rule has
been confirmed until somebody confirms it.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b3f7c28e91d5'
down_revision: Union[str, Sequence[str], None] = 'a8e2d61f0c94'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'recert_campaigns',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('scope', sa.String(length=128), nullable=False, server_default='all'),
        sa.Column('due_date', sa.String(length=10), nullable=False),
        sa.Column('created_by', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('closed_by', sa.String(length=64), nullable=False, server_default=''),
    )
    op.create_table(
        'recert_items',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('campaign_id', sa.Integer(),
                  sa.ForeignKey('recert_campaigns.id', ondelete='CASCADE'), nullable=False),
        sa.Column('rule_pk', sa.Integer(),
                  sa.ForeignKey('rules.id', ondelete='CASCADE'), nullable=False),
        sa.Column('owner', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('decision', sa.String(length=16), nullable=True),
        sa.Column('decided_by', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('comment', sa.Text(), nullable=False, server_default=''),
        sa.UniqueConstraint('campaign_id', 'rule_pk'),
    )
    op.create_index('ix_recert_items_campaign_id', 'recert_items', ['campaign_id'])
    op.create_index('ix_recert_items_rule_pk', 'recert_items', ['rule_pk'])

    op.add_column('rules', sa.Column('last_confirmed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('rules', sa.Column('last_confirmed_by', sa.String(length=64),
                                     nullable=False, server_default=''))


def downgrade() -> None:
    op.drop_column('rules', 'last_confirmed_by')
    op.drop_column('rules', 'last_confirmed_at')
    op.drop_index('ix_recert_items_rule_pk', table_name='recert_items')
    op.drop_index('ix_recert_items_campaign_id', table_name='recert_items')
    op.drop_table('recert_items')
    op.drop_table('recert_campaigns')
