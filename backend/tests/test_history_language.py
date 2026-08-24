"""The history has to be readable in the language the instance is set to now.

The entries used to be translated as they were written, which froze each one in
whatever language happened to be configured that day. An instance switched to
German kept showing "Implemented on every component" for every rule it had ever
touched, and the rollout status arrived as a Python dict repr.

These tests pin the properties that fix depends on: the language is decided when
an entry is read, a person's own words are never treated as a template, and every
template the code actually stores has a German translation - the last one is what
keeps the catalogue from drifting out of step with the call sites again.
"""
import ast
import os
import pathlib

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import messages
from app.database import Base
from app.messages import render
from app.models import (
    ComponentType,
    Role,
    Rule,
    RuleAction,
    RuleStatus,
    SecurityComponent,
    User,
    Vrf,
)
from app.routers.rules_router import add_version
from app.schemas import RuleVersionOut

BACKEND = pathlib.Path(__file__).resolve().parent.parent
# The seed writes history entries too, and its notes are what the demo shows to
# every visitor - so it is held to the same standard as the application.
SOURCES = [BACKEND / "app", BACKEND / "seed_demo.py"]


@pytest.fixture()
def language_de():
    """Switches the instance to German for the duration of one test."""
    before = messages.current_language()
    messages.set_language("de")
    yield
    messages.set_language(before)


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="ACI-Fabric-FFM", type=ComponentType.aci))
    s.add(User(id=1, username="betrieb", password_hash="x", role=Role.operations))
    s.commit()
    yield s
    s.close()


def make_rule(db):
    rule = Rule(rule_id="SR00001", vrf_id=1, name="test", version=1,
                components=[db.get(SecurityComponent, 1)],
                source=[{"ip": "10.0.0.1", "alias": ""}],
                destination=[{"ip": "10.0.1.1", "alias": ""}],
                services=[{"protocol": "TCP", "port": "22"}],
                action=RuleAction.permit, status=RuleStatus.approved)
    db.add(rule)
    db.commit()
    return rule


# ---------- the reported bug ----------

def test_an_entry_written_in_english_reads_german_after_the_switch(db, language_de):
    """The whole point. The entry was written on an English instance; the
    instance is German now and the history has to follow."""
    messages.set_language("en")
    rule = make_rule(db)
    add_version(db, rule, db.get(User, 1),
                "Implemented on every component – the rule is active")
    db.commit()

    messages.set_language("de")
    entry = RuleVersionOut.model_validate(rule.versions[0])
    assert entry.change_note == "Auf allen Komponenten umgesetzt – die Regel ist aktiv"


def test_the_stored_entry_stays_english(db, language_de):
    """English is the source language and what the database keeps, so the entry
    is not re-written when somebody switches the instance."""
    rule = make_rule(db)
    add_version(db, rule, db.get(User, 1), "Rule created")
    db.commit()

    assert rule.versions[0].change_note == "Rule created"
    assert RuleVersionOut.model_validate(rule.versions[0]).change_note == "Regel angelegt"


def test_the_implementation_status_is_a_sentence_not_a_dict_repr(db, language_de):
    """It used to render as {'ACI-Fabric-FFM': 'implemented'}. The component
    name is a name and stays put; the status word is a term and is translated."""
    rule = make_rule(db)
    add_version(db, rule, db.get(User, 1), "Implementation status: {impl_status}",
                impl_status={"ACI-Fabric-FFM": "implemented"})
    db.commit()

    note = RuleVersionOut.model_validate(rule.versions[0]).change_note
    assert note == "Umsetzungsstatus: ACI-Fabric-FFM → umgesetzt"


def test_the_values_are_not_served_beside_the_sentence(db):
    """They are the raw material for the note, not a second copy of it."""
    rule = make_rule(db)
    add_version(db, rule, db.get(User, 1), "Rolled back to version {version}", version=1)
    db.commit()

    assert "change_values" not in RuleVersionOut.model_validate(rule.versions[0]).model_dump()


# ---------- what must not be translated ----------

def test_a_note_somebody_typed_is_not_treated_as_a_template(db, language_de):
    """A change note is a person's own words. Braces in it are theirs too, and
    formatting them would either mangle the note or raise inside a read."""
    rule = make_rule(db)
    add_version(db, rule, db.get(User, 1), "Port {8443} für Kunde X geöffnet")
    db.commit()

    entry = RuleVersionOut.model_validate(rule.versions[0])
    assert entry.change_note == "Port {8443} für Kunde X geöffnet"


def test_an_entry_written_before_this_existed_still_translates(language_de):
    """Old rows hold a finished English sentence and no values. The sentence is
    itself a catalogue key, so it translates; nothing had to be migrated."""
    assert render("Rule created", None) == "Regel angelegt"


def test_an_entry_frozen_in_german_is_left_alone(language_de):
    """The other kind of old row. There is no way back to the template, so it
    is passed through as written rather than guessed at."""
    assert render("Regel angelegt", None) == "Regel angelegt"


def test_a_template_without_a_translation_falls_back_to_english(language_de):
    assert render("Nothing in the catalogue {x}", {"x": "1"}) == "Nothing in the catalogue 1"


# ---------- the same thing for the append-only audit store ----------

def test_an_audit_entry_reads_german_after_the_switch(db, language_de):
    """The audit page shows these beside the rule history, so the two have to
    agree. The store itself stays English - it is a record, and the SIEM that
    receives it has no language."""
    from app import audit

    messages.set_language("en")
    audit.record(db, "rule", "rule.deleted", actor="admin", object="SR00001",
                 detail="Rule deleted (soft delete): {name}",
                 detail_values={"name": "jump-to-app"})

    messages.set_language("de")
    entry = next(e for e in audit.collect(db) if e["event"] == "rule.deleted")
    assert entry["detail"] == "Regel gelöscht (Soft-Delete): jump-to-app"


def test_an_audit_entry_written_before_this_existed_still_translates(db, language_de):
    """Old rows hold a finished sentence and no values - and an English one is
    a catalogue key, so the past translates without a data migration."""
    from app import audit
    from app.models import AuditEvent

    db.add(AuditEvent(category="auth", event="auth.login_failed", actor="x",
                      detail="account locked", prev_hash="", hash="h"))
    db.commit()

    entry = next(e for e in audit.collect(db) if e["event"] == "auth.login_failed")
    assert entry["detail"] == "Konto gesperrt"


# ---------- keeping the catalogue in step with the call sites ----------

def _stored_templates() -> set[str]:
    """Every literal template the code hands to add_version, RuleVersion or record.

    Read out of the source rather than listed by hand, so a new call site is
    covered the moment it is written.

    A template is often assigned to a name first - `note = "..."` in one branch,
    `add_version(..., note)` below - so a name is followed back to the string
    literals assigned to it in the same function. Without that the walk misses
    exactly the entries this whole change is about, and reports success.
    """
    found: set[str] = set()
    paths = [f for s in SOURCES for f in ([s] if s.is_file() else s.rglob("*.py"))]
    for path in paths:
        tree = ast.parse(path.read_text())
        for scope in [tree] + [n for n in ast.walk(tree)
                               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            literals: dict[str, set[str]] = {}
            for node in ast.walk(scope):
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                        and isinstance(node.value.value, str):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            literals.setdefault(target.id, set()).add(node.value.value)

            for node in ast.walk(scope):
                if not isinstance(node, ast.Call):
                    continue
                name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                if name == "add_version" and len(node.args) >= 4:
                    found |= _texts(node.args[3], literals)
                elif name in ("RuleVersion", "record"):
                    for kw in node.keywords:
                        if kw.arg in ("change_note", "detail"):
                            found |= _texts(kw.value, literals)
    return found


def _texts(node, literals: dict[str, set[str]]) -> set[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.Name):
        return literals.get(node.id, set())
    return set()


def test_the_walk_still_reaches_a_template_that_goes_through_a_variable():
    """A canary for the guard below.

    The guard is a test that can stop testing: narrow the walk and it finds
    fewer templates, has nothing to complain about, and passes. This one names a
    template that is only reachable by following `note = "..."` to the call, so
    the walk losing that ability is a failure rather than a quiet success.
    """
    assert "Implemented on every component – the rule is active" in _stored_templates()


def test_every_template_the_code_stores_has_a_german_translation():
    """Without this the catalogue drifts silently: a missing entry falls back to
    English, which is exactly the symptom being fixed and shows up in nobody's
    test run."""
    templates = _stored_templates()
    assert templates, "no templates found - the AST walk stopped matching"

    missing = sorted(t for t in templates if t not in messages.CATALOG["de"])
    assert missing == [], f"no German translation for: {missing}"


def test_every_implementation_status_has_a_german_translation():
    """They are inserted into a sentence by messages._value()."""
    from app.domain_values import IMPL_STATUSES

    missing = [s for s in IMPL_STATUSES if s not in messages.CATALOG["de"]]
    assert missing == []


def test_the_public_settings_read_heals_a_stale_language_cache(db, language_de):
    """Messages cache the instance language; a change from another process (the
    nightly demo reseed) can leave the running server's cache stale - German UI,
    an English backend message. The interface fetches public settings on every
    load, so that read corrects the drift."""
    from app.routers.settings_router import read_public_settings
    from app.settings import set_setting

    set_setting(db, "ui_language", "de")
    messages.set_language("en")          # simulate the drift
    assert messages.current_language() == "en"

    read_public_settings(db)
    assert messages.current_language() == "de"
