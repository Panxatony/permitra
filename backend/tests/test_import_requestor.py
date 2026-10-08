"""A requestor typed into the Excel sheet has to become an account, or be named
as the one that did not.

The four-eyes check keys on the requestor as an account username, compared
exactly. The import stored whatever the sheet said - "Max Mustermann" - which
matched no account, so the exclusion that names the person accountable for a
rule applied to nothing that came in through the import. And two places
compared names in two different ways (exact here, lowercased in the
recertification), so the same requestor could be "unknown" on one page and
free to approve on another.
"""
import os

os.environ.setdefault("PERMITRA_DEV", "1")

import openpyxl
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import import_excel
from app.accounts import resolve_account, same_account
from app.database import Base
from app.models import ComponentType, Role, Rule, RuleAction, RuleStatus, SecurityComponent, User, Vrf, apply_roles
from app.routers.rules_router import ReviewDecision, _decide

HEADER = ["Rule-ID", "Application", "Sicherheitselement", "Source SZ", "Quelle", "Destination-SZ",
          "Ziel", "Protokoll", "Port", "Anlass", "Requestor", "Bearbeiter", "Status Juniper",
          "Status ACI", "Status", "Change-ID", "Letzte Änderung", "Info", "Fachlicher Bezug"]


@pytest.fixture()
def factory():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW", type=ComponentType.juniper))
    for name, full, mail, roles in (
        ("mmustermann", "Max Mustermann", "max@example.org", [Role.architect]),
        ("ekant", "Erika Kant", "erika@example.org", [Role.architect, Role.change_approver]),
    ):
        u = User(username=name, full_name=full, email=mail, password_hash="x", is_active=True)
        apply_roles(u, roles)
        s.add(u)
    s.commit()
    s.close()
    return Session


def sheet(tmp_path, rows):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Kommunikationsmatrix"
    ws.append(HEADER)
    for rid, requestor in rows:
        ws.append([rid, "App", "Juniper", "Z010", "10.0.0.5", "Z020", "10.0.1.5", "TCP", "443",
                   "Anlass", requestor, "", "", "", "neu", "", "", "", ""])
    path = tmp_path / "matrix.xlsx"
    wb.save(path)
    return str(path)


def requestor_of(Session, rid):
    db = Session()
    try:
        return db.query(Rule).filter(Rule.rule_id == rid).one().requestor
    finally:
        db.close()


# ---------- the import ----------

def test_a_typed_name_becomes_the_account_username(factory, tmp_path):
    path = sheet(tmp_path, [("SR00001", "Max Mustermann"), ("SR00002", "ERIKA@EXAMPLE.ORG"),
                            ("SR00003", "ekant")])
    summary = import_excel.run(path, "Kommunikationsmatrix", False, session_factory=factory)
    assert summary["imported"] == 3
    assert requestor_of(factory, "SR00001") == "mmustermann"
    assert requestor_of(factory, "SR00002") == "ekant"
    assert requestor_of(factory, "SR00003") == "ekant"
    assert summary["unresolved_requestors"] == {}


def test_a_name_nobody_answers_to_is_kept_and_reported(factory, tmp_path):
    """Kept as typed, so nothing is invented; reported, so somebody assigns it."""
    path = sheet(tmp_path, [("SR00001", "Fritz Weggezogen"), ("SR00002", "Fritz Weggezogen")])
    summary = import_excel.run(path, "Kommunikationsmatrix", False, session_factory=factory)
    assert requestor_of(factory, "SR00001") == "Fritz Weggezogen"
    assert summary["unresolved_requestors"] == {"Fritz Weggezogen": ["SR00001", "SR00002"]}


def test_a_mapping_settles_a_name_the_lookup_cannot(factory, tmp_path):
    path = sheet(tmp_path, [("SR00001", "Fritz Weggezogen")])
    summary = import_excel.run(path, "Kommunikationsmatrix", False,
                               requestor_map=import_excel.parse_requestor_map(["fritz weggezogen=ekant"]),
                               session_factory=factory)
    assert requestor_of(factory, "SR00001") == "ekant"
    assert summary["unresolved_requestors"] == {}


# ---------- one way of comparing names ----------

def test_the_resolver_prefers_the_username_and_ignores_case(factory):
    db = factory()
    assert resolve_account(db, "  MMustermann ").username == "mmustermann"
    assert resolve_account(db, "erika kant").username == "ekant"
    assert resolve_account(db, "nobody") is None
    db.close()
    assert same_account("MMustermann", "mmustermann")
    assert not same_account("", "")


def test_the_four_eyes_check_compares_the_way_the_import_does(factory):
    """A requestor that differs from the approving account only in case is
    the same person - and was free to approve their own rule."""
    db = factory()
    db.add(Rule(rule_id="SR00009", vrf_id=1, name="sr00009", requestor="EKANT",
                created_by="mmustermann", components=[db.get(SecurityComponent, 1)],
                source=[{"ip": "10.0.0.1", "alias": ""}], destination=[{"ip": "10.0.1.1", "alias": ""}],
                services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
                status=RuleStatus.in_review, source_zone="Z010", destination_zone="Z020"))
    db.commit()
    approver = db.query(User).filter(User.username == "ekant").one()
    with pytest.raises(HTTPException) as exc:
        _decide(db, "SR00009", approver, ReviewDecision(), RuleStatus.approved, "Rule approved")
    assert exc.value.status_code == 403
    db.close()
