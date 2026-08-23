"""The demo has to be a state the application could have produced.

For most people demo.permitra.de *is* Permitra, so a demo that shows something
the workflow cannot reach is not a cosmetic problem - it teaches the wrong
model. And it is easy to reach: the seed writes fields straight onto the rules,
skipping the endpoints that keep them in step with each other.

That is exactly what happened. impl_status was written directly, so 30 approved
rules were implemented on every component while the promotion to `active` never
ran. The dashboard read "Approved 63 / Active 0" next to "To implement 33" - the
numbers did not add up, and they should not have, because no sequence of actions
in Permitra produces that state.

These tests assert the invariants the application maintains, against the data the
seed actually produces.
"""
import os
import pathlib
import subprocess
import sys

os.environ.setdefault("PERMITRA_DEV", "1")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

BACKEND = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    """Runs the real seed, in a subprocess against a database of its own.

    A subprocess because seed_demo binds its session at import time from
    DATABASE_URL; importing it here would attach it to whatever the test session
    is using.
    """
    path = tmp_path_factory.mktemp("seed") / "demo.db"
    result = subprocess.run(
        [sys.executable, "seed_demo.py", "--wipe"],
        cwd=BACKEND, capture_output=True, text=True,
        env={**os.environ, "DATABASE_URL": f"sqlite:///{path}",
             "PYTHONPATH": str(BACKEND), "PERMITRA_DEV": "1"},
    )
    assert result.returncode == 0, result.stderr[-2000:]

    session = sessionmaker(bind=create_engine(f"sqlite:///{path}"))()
    yield session
    session.close()


def test_no_approved_rule_is_already_implemented_everywhere(seeded):
    """The invariant this test exists for.

    Confirming the last component promotes a rule to `active`. A rule left
    approved while every component reports it implemented is a state the
    application cannot produce, and it made the dashboard contradict itself.
    """
    from app.models import Rule, RuleStatus
    from app.routers.rules_router import fully_implemented

    stuck = [r.rule_id for r in seeded.query(Rule)
             .filter(Rule.status == RuleStatus.approved).all()
             if fully_implemented(r)]

    assert stuck == [], f"approved but implemented on every component: {stuck}"


def test_active_rules_really_are_implemented_everywhere(seeded):
    """The other direction, and the one that would actually mislead: `active`
    asserts the rule is in force on every component it names."""
    from app.models import Rule, RuleStatus
    from app.routers.rules_router import fully_implemented

    lying = [r.rule_id for r in seeded.query(Rule)
             .filter(Rule.status == RuleStatus.active).all()
             if not fully_implemented(r)]

    assert lying == [], f"active without being implemented everywhere: {lying}"


def test_the_demo_actually_has_active_rules(seeded):
    """Without this the first test passes on a demo that simply has none, and
    the status the whole workflow leads up to would be invisible."""
    from app.models import Rule, RuleStatus

    assert seeded.query(Rule).filter(Rule.status == RuleStatus.active).count() > 0


def test_the_status_counts_add_up_to_the_total(seeded):
    """What the dashboard shows: the tile and the bars are the same rules
    counted twice, so they have to agree."""
    from sqlalchemy import func

    from app.models import Rule

    total = seeded.query(Rule).filter(Rule.deleted_at.is_(None)).count()
    by_status = dict(seeded.query(Rule.status, func.count(Rule.id))
                     .filter(Rule.deleted_at.is_(None)).group_by(Rule.status).all())

    assert sum(by_status.values()) == total


def test_every_implementation_status_is_a_known_value(seeded):
    """The seed picks these from literals; a typo would be invisible until some
    rule silently never counts as implemented."""
    from app.domain_values import IMPL_STATUSES
    from app.models import Rule

    seen = {v for r in seeded.query(Rule).all() for v in (r.impl_status or {}).values()}
    assert seen <= set(IMPL_STATUSES), f"unknown: {seen - set(IMPL_STATUSES)}"


def test_the_implementation_status_names_only_the_rule_own_components(seeded):
    """A stale component name never becomes "implemented", so the rule can never
    reach active - the kind of thing that sits in a demo unnoticed for months."""
    from app.models import Rule

    wrong = {
        r.rule_id: sorted(set(r.impl_status or {}) - {c.name for c in r.components})
        for r in seeded.query(Rule).all()
        if set(r.impl_status or {}) - {c.name for c in r.components}
    }
    assert wrong == {}
