"""The server's own logging has to outlive its startup.

Migrations run inside the startup hook, after every module has been imported,
and Alembic's env.py configures logging from alembic.ini. fileConfig disables
every logger that already exists unless told otherwise - which was all of
permitra.*, so from the first request on, failures in SIEM delivery, NetBox
import and mail sending were written nowhere.
"""
import logging
import os

os.environ.setdefault("PERMITRA_DEV", "1")

from alembic import command
from app.migrations import alembic_config


def test_running_the_migrations_leaves_application_loggers_enabled(tmp_path, monkeypatch):
    probe = logging.getLogger("permitra.probe")   # exists before the migrations, like every module logger
    assert not probe.disabled

    # env.py reads the URL from app.database each time it is executed, so a
    # throwaway database is enough to run it - and the logging setup with it.
    monkeypatch.setattr("app.database.DATABASE_URL", f"sqlite:///{tmp_path / 'migrate.db'}")
    command.upgrade(alembic_config(), "head")

    assert not probe.disabled
    assert not logging.getLogger("permitra.audit").disabled
