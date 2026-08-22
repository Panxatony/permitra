"""Runs Alembic migrations on application startup.

Existing installations from before Alembic was introduced (tables present, but no
alembic_version) are stamped to the baseline once and migrated normally afterwards.
"""
import os

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect

from alembic import command

from .database import engine

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def alembic_config() -> Config:
    cfg = Config(os.path.join(BACKEND_DIR, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND_DIR, "alembic"))
    return cfg


def base_revision(cfg: Config) -> str:
    """First revision of the chain (the baseline)."""
    script = ScriptDirectory.from_config(cfg)
    return next(rev.revision for rev in script.walk_revisions() if rev.down_revision is None)


def run_migrations() -> None:
    cfg = alembic_config()
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    if "rules" in tables and "alembic_version" not in tables:
        # Pre-Alembic installation: matches the baseline, so stamp it there
        # to let all later migrations be applied normally.
        command.stamp(cfg, base_revision(cfg))
    command.upgrade(cfg, "head")
