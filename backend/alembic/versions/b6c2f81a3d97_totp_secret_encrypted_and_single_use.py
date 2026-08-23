"""totp secret encrypted and single use

Revision ID: b6c2f81a3d97
Revises: a1d9e6f24c05
Create Date: 2026-08-23 17:00:00.000000

The TOTP seed sat in the database in plaintext while the NetBox token next to it
was encrypted. Read access to the database was therefore enough to mint valid
second factors indefinitely - the factor that is supposed to survive a stolen
password did not survive a stolen dump.

Existing seeds are encrypted in place; the column has to grow first, because
ciphertext is longer than a base32 seed. `totp_last_counter` records the time
step that was last accepted, which is what makes a code single-use instead of
replayable for the whole tolerance window.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b6c2f81a3d97'
down_revision: Union[str, Sequence[str], None] = 'a1d9e6f24c05'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.alter_column("totp_secret", type_=sa.String(255), existing_nullable=True)
        batch.add_column(sa.Column("totp_last_counter", sa.Integer(), nullable=True))

    from app.crypto import encrypt, looks_encrypted

    conn = op.get_bind()
    rows = conn.execute(sa.text(
        "SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL "
        "AND totp_secret <> ''")).fetchall()
    for user_id, secret in rows:
        # Idempotent: a re-run must not encrypt an already encrypted value a
        # second time, which would leave it unreadable.
        if looks_encrypted(secret):
            continue
        conn.execute(sa.text("UPDATE users SET totp_secret = :s WHERE id = :i"),
                     {"s": encrypt(secret), "i": user_id})


def downgrade() -> None:
    from app.crypto import decrypt, looks_encrypted

    conn = op.get_bind()
    rows = conn.execute(sa.text(
        "SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL "
        "AND totp_secret <> ''")).fetchall()
    for user_id, secret in rows:
        if looks_encrypted(secret):
            conn.execute(sa.text("UPDATE users SET totp_secret = :s WHERE id = :i"),
                         {"s": decrypt(secret), "i": user_id})

    with op.batch_alter_table("users") as batch:
        batch.drop_column("totp_last_counter")
        batch.alter_column("totp_secret", type_=sa.String(64), existing_nullable=True)
