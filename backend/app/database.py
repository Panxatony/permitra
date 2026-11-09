import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


def normalize_database_url(url: str) -> str:
    """Pin a bare ``postgresql://`` URL to the psycopg2 driver we ship.

    SQLAlchemy 2.1 changed the default DBAPI behind ``postgresql://`` from
    psycopg2 to psycopg 3. The image only carries psycopg2-binary, so an
    operator whose ``DATABASE_URL`` has no explicit driver would get
    ``ModuleNotFoundError: No module named 'psycopg'`` on the first start after
    the upgrade. Spelling the driver out keeps every existing configuration
    working; a URL that already names a driver is left alone.
    """
    if url.startswith("postgresql://"):
        return "postgresql+psycopg2://" + url[len("postgresql://") :]
    if url.startswith("postgres://"):
        return "postgresql+psycopg2://" + url[len("postgres://") :]
    return url


# PostgreSQL in Docker/production, SQLite as a fallback for local development
DATABASE_URL = normalize_database_url(
    os.environ.get("DATABASE_URL", "sqlite:///./permitra.db")
)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
