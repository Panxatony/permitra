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
    """Switch existing rules and matrix requests from zone name to zone ID (code)
    – the ID is the leading identifier from now on."""
    conn = op.get_bind()
    zones = conn.execute(sa.text("SELECT name, code FROM zones WHERE code != ''")).fetchall()
    for name, code in zones:
        # S608 rationale: only the column name is interpolated, and it comes from the
        # hardcoded tuples; the values are passed as bound parameters.
        for col in ("source_zone", "destination_zone"):
            conn.execute(
                sa.text(f"UPDATE rules SET {col} = :code WHERE UPPER({col}) = :name"),  # noqa: S608
                {"code": code, "name": name.upper()},
            )
        for col in ("from_zone", "to_zone"):
            conn.execute(
                sa.text(f"UPDATE zone_policy_changes SET {col} = :code WHERE UPPER({col}) = :name"),  # noqa: S608
                {"code": code, "name": name.upper()},
            )


def downgrade() -> None:
    pass
