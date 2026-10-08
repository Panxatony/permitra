"""segments inside a zone, with their own allow/block matrix

Revision ID: b7d3f09c1e52
Revises: a9c4e71d2b58
Create Date: 2026-10-08 12:00:00.000000

The zone matrix says whether two zones may talk; inside a zone everything
was allowed, which is exactly where micro-segmentation lives. A segment is
a group that belongs to a zone; the segment matrix is the zone matrix one
level down. Zones that are never segmented keep their behaviour: their
`intra_zone_default` stays NULL and intra-zone traffic is not asked.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'b7d3f09c1e52'
down_revision: Union[str, Sequence[str], None] = 'a9c4e71d2b58'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('zones', schema=None) as batch_op:
        batch_op.add_column(sa.Column('intra_zone_default', sa.String(length=8), nullable=True))
    op.create_table(
        'segments',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('zone_id', sa.Integer(), nullable=False),
        sa.Column('group_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=64), nullable=False),
        sa.Column('description', sa.String(length=256), nullable=False, server_default=''),
        sa.ForeignKeyConstraint(['zone_id'], ['zones.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['group_id'], ['address_groups.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('zone_id', 'name'),
    )
    with op.batch_alter_table('segments', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_segments_zone_id'), ['zone_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_segments_group_id'), ['group_id'], unique=False)
    # The policy enum already exists (zone_policies); on PostgreSQL the column
    # reuses it, which is why create_type is off.
    op.create_table(
        'segment_policies',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('from_segment_id', sa.Integer(), nullable=False),
        sa.Column('to_segment_id', sa.Integer(), nullable=False),
        sa.Column('policy', sa.Enum('allow_only', 'block_all', name='zonepolicytype', create_type=False),
                  nullable=False, server_default='block_all'),
        sa.Column('note', sa.Text(), nullable=False, server_default=''),
        sa.ForeignKeyConstraint(['from_segment_id'], ['segments.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['to_segment_id'], ['segments.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('from_segment_id', 'to_segment_id'),
    )
    with op.batch_alter_table('segment_policies', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_segment_policies_from_segment_id'), ['from_segment_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_segment_policies_to_segment_id'), ['to_segment_id'], unique=False)


def downgrade() -> None:
    op.drop_table('segment_policies')
    op.drop_table('segments')
    with op.batch_alter_table('zones', schema=None) as batch_op:
        batch_op.drop_column('intra_zone_default')
