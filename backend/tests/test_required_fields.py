"""Tests für konfigurierbare Pflichtfelder (Issue #8)."""
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.routers.rules_router import enforce_required_fields
from app.settings import set_setting


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


class Payload:
    def __init__(self, justification="", requestor="", valid_until=""):
        self.justification = justification
        self.requestor = requestor
        self.valid_until = valid_until


def test_defaults_do_not_enforce(db):
    enforce_required_fields(db, Payload())  # alles optional (Bestandsverhalten)


def test_enforced_fields_rejected_when_missing(db):
    set_setting(db, "require_justification", "yes")
    set_setting(db, "require_valid_until", "yes")
    with pytest.raises(HTTPException) as exc:
        enforce_required_fields(db, Payload(requestor="egal"))
    assert exc.value.status_code == 422
    assert "Begründung" in exc.value.detail and "Gültig-bis" in exc.value.detail
    # Vollständig -> ok
    enforce_required_fields(db, Payload(justification="HTTPS", valid_until="2027-01-01"))


def test_requestor_enforcement(db):
    set_setting(db, "require_requestor", "yes")
    with pytest.raises(HTTPException):
        enforce_required_fields(db, Payload(justification="x"))
    enforce_required_fields(db, Payload(requestor="Max Bauer"))
