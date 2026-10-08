"""workloads with labels, and the groups rules refer to by name

Revision ID: a9c4e71d2b58
Revises: f3a7c21d9e40
Create Date: 2026-10-08 10:00:00.000000

A micro-segmentation policy names groups, not addresses. Permitra's rules
stay address-based - an address is what a firewall and a drift comparison
can check - so a group is resolved to addresses when a rule is written and
re-synchronised when its membership moves. These two tables hold what the
resolution works on: the workloads with their labels, and the groups.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'a9c4e71d2b58'
down_revision: Union[str, Sequence[str], None] = 'f3a7c21d9e40'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

WORKLOAD_KIND = sa.Enum('device', 'vm', 'container', 'service', 'other', name='workloadkind')
GROUP_KIND = sa.Enum('static', 'selector', name='groupkind')


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        WORKLOAD_KIND.create(bind, checkfirst=True)
        GROUP_KIND.create(bind, checkfirst=True)
    op.create_table(
        'workloads',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('vrf_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('kind', WORKLOAD_KIND, nullable=False, server_default='vm'),
        sa.Column('addresses', sa.JSON(), nullable=False),
        sa.Column('labels', sa.JSON(), nullable=False),
        sa.Column('description', sa.String(length=256), nullable=False, server_default=''),
        sa.Column('source', sa.String(length=32), nullable=False, server_default='manual'),
        sa.Column('netbox_id', sa.Integer(), nullable=True),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['vrf_id'], ['vrfs.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('vrf_id', 'name'),
    )
    with op.batch_alter_table('workloads', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_workloads_vrf_id'), ['vrf_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_workloads_name'), ['name'], unique=False)
        batch_op.create_index(batch_op.f('ix_workloads_netbox_id'), ['netbox_id'], unique=False)
    op.create_table(
        'address_groups',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('vrf_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('kind', GROUP_KIND, nullable=False, server_default='selector'),
        sa.Column('selector', sa.String(length=256), nullable=False, server_default=''),
        sa.Column('members', sa.JSON(), nullable=False),
        sa.Column('description', sa.String(length=256), nullable=False, server_default=''),
        sa.ForeignKeyConstraint(['vrf_id'], ['vrfs.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('vrf_id', 'name'),
    )
    with op.batch_alter_table('address_groups', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_address_groups_vrf_id'), ['vrf_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_address_groups_name'), ['name'], unique=False)


def downgrade() -> None:
    op.drop_table('address_groups')
    op.drop_table('workloads')
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        GROUP_KIND.drop(bind, checkfirst=True)
        WORKLOAD_KIND.drop(bind, checkfirst=True)
