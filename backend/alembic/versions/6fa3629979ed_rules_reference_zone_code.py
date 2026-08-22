"""rules reference zone code

Revision ID: 6fa3629979ed
Revises: 3fb9a49c4448
Create Date: 2026-08-22 17:22:55.093946

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6fa3629979ed'
down_revision: Union[str, Sequence[str], None] = '3fb9a49c4448'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Bestehende Regeln und Matrix-Anträge von Zonen-Name auf Zonen-ID (code)
    umstellen – die ID ist künftig der führende Identifier."""
    conn = op.get_bind()
    zones = conn.execute(sa.text("SELECT name, code FROM zones WHERE code != ''")).fetchall()
    for name, code in zones:
        for col in ("source_zone", "destination_zone"):
            conn.execute(
                sa.text(f"UPDATE rules SET {col} = :code WHERE UPPER({col}) = :name"),
                {"code": code, "name": name.upper()},
            )
        for col in ("from_zone", "to_zone"):
            conn.execute(
                sa.text(f"UPDATE zone_policy_changes SET {col} = :code WHERE UPPER({col}) = :name"),
                {"code": code, "name": name.upper()},
            )


def downgrade() -> None:
    pass
