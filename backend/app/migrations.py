"""Führt beim App-Start Alembic-Migrationen aus.

Bestehende Installationen aus der Zeit vor Alembic (Tabellen vorhanden, aber keine
alembic_version) werden einmalig auf die Baseline gestempelt und danach normal migriert.
"""
import os

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect

from .database import engine

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def alembic_config() -> Config:
    cfg = Config(os.path.join(BACKEND_DIR, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND_DIR, "alembic"))
    return cfg


def base_revision(cfg: Config) -> str:
    """Erste Revision der Kette (die Baseline)."""
    script = ScriptDirectory.from_config(cfg)
    return next(rev.revision for rev in script.walk_revisions() if rev.down_revision is None)


def run_migrations() -> None:
    cfg = alembic_config()
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    if "rules" in tables and "alembic_version" not in tables:
        # Vor-Alembic-Installation: entspricht der Baseline; darauf stempeln,
        # damit alle späteren Migrationen normal angewendet werden.
        command.stamp(cfg, base_revision(cfg))
    command.upgrade(cfg, "head")
