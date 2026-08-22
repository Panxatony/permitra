"""rule ids five digits

Revision ID: e029926e5af1
Revises: eafa923712e7
Create Date: 2026-08-22 07:53:25.231035

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e029926e5af1'
down_revision: Union[str, Sequence[str], None] = 'eafa923712e7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Bestehende SR-Nummern auf 5 Stellen auffüllen (SR0103 -> SR00103),
    damit Permitra bis 99999 Regeln unterstützt."""
    import re

    connection = op.get_bind()
    rows = connection.execute(sa.text("SELECT id, rule_id FROM rules")).fetchall()
    pattern = re.compile(r"^SR(\d{1,4})$")
    for row_id, rule_id in rows:
        match = pattern.match(rule_id or "")
        if match:
            connection.execute(
                sa.text("UPDATE rules SET rule_id = :new WHERE id = :id"),
                {"new": f"SR{int(match.group(1)):05d}", "id": row_id},
            )


def downgrade() -> None:
    """Kein automatisches Zurückkürzen (5-stellige IDs blieben sonst mehrdeutig)."""
    pass
