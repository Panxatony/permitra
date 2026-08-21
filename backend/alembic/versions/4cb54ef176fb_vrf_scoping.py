"""vrf scoping

Revision ID: 4cb54ef176fb
Revises: 77ff0bcd4a64
Create Date: 2026-08-21 18:53:08.196945

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4cb54ef176fb'
down_revision: Union[str, Sequence[str], None] = '77ff0bcd4a64'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """VRF als Scoping-Dimension: Netze, Adress-Zuordnungen und Regeln je VRF.

    Bestehende Daten werden dem Default-VRF "IT" zugeordnet."""
    bind = op.get_bind()
    op.create_table(
        'vrfs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=64), nullable=False),
        sa.Column('description', sa.Text(), server_default='', nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    op.execute("INSERT INTO vrfs (name, description) VALUES ('IT', 'Default-VRF (Bestandsdaten)')")

    for table in ('zone_networks', 'address_component_map', 'address_epg_map', 'rules'):
        op.add_column(table, sa.Column('vrf_id', sa.Integer(), nullable=True))
        op.execute(f"UPDATE {table} SET vrf_id = (SELECT id FROM vrfs WHERE name = 'IT')")

    if bind.dialect.name == 'postgresql':
        # Alte globale Eindeutigkeit durch (vrf, key) ersetzen
        op.execute('ALTER TABLE zone_networks DROP CONSTRAINT IF EXISTS zone_networks_cidr_key')
        op.execute('DROP INDEX IF EXISTS ix_zone_networks_cidr')
        op.execute('ALTER TABLE address_component_map DROP CONSTRAINT IF EXISTS address_component_map_ip_key')
        op.execute('DROP INDEX IF EXISTS ix_address_component_map_ip')
        op.execute('ALTER TABLE address_epg_map DROP CONSTRAINT IF EXISTS address_epg_map_ip_key')
        op.execute('DROP INDEX IF EXISTS ix_address_epg_map_ip')
        for table in ('zone_networks', 'address_component_map', 'address_epg_map', 'rules'):
            op.alter_column(table, 'vrf_id', nullable=False)
            op.create_foreign_key(None, table, 'vrfs', ['vrf_id'], ['id'],
                                  ondelete='RESTRICT' if table == 'rules' else 'CASCADE')
            op.create_index(f'ix_{table}_vrf_id', table, ['vrf_id'])
        op.create_unique_constraint('uq_zone_networks_vrf_cidr', 'zone_networks', ['vrf_id', 'cidr'])
        op.create_unique_constraint('uq_acm_vrf_ip', 'address_component_map', ['vrf_id', 'ip'])
        op.create_unique_constraint('uq_aem_vrf_ip', 'address_epg_map', ['vrf_id', 'ip'])
        op.create_index('ix_zone_networks_cidr', 'zone_networks', ['cidr'])
        op.create_index('ix_address_component_map_ip', 'address_component_map', ['ip'])
        op.create_index('ix_address_epg_map_ip', 'address_epg_map', ['ip'])
    # SQLite (nur Dev): Spalten + Backfill genügen; frische DBs entstehen ohnehin
    # über create_all mit dem korrekten Schema.


def downgrade() -> None:
    raise NotImplementedError("VRF-Scoping ist nicht rückwärts migrierbar")
