"""SQLAlchemy 2.1 resolves a bare ``postgresql://`` URL to psycopg 3, which the
image does not ship; the application must pin the driver it has (psycopg2)
so that existing DATABASE_URL values keep working after the upgrade."""

from app.database import normalize_database_url


def test_bare_postgresql_url_gets_the_psycopg2_driver():
    assert (
        normalize_database_url("postgresql://u:p@db:5432/permitra")
        == "postgresql+psycopg2://u:p@db:5432/permitra"
    )


def test_legacy_postgres_scheme_gets_the_psycopg2_driver():
    assert (
        normalize_database_url("postgres://u:p@db/permitra")
        == "postgresql+psycopg2://u:p@db/permitra"
    )


def test_explicit_driver_and_sqlite_are_left_alone():
    for url in (
        "postgresql+psycopg2://u:p@db/permitra",
        "postgresql+psycopg://u:p@db/permitra",
        "sqlite:///./permitra.db",
    ):
        assert normalize_database_url(url) == url
