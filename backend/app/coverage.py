"""How much of the estate is covered by an approved security rule, in one figure.

The per-component report answers "is this firewall covered?". Nobody watches six
of those, and the number that matters is the one across all of them - together
with whether it is moving the wrong way. That is what this produces.

The whole value of the figure rests on it being honest about what it did *not*
measure. A component whose configuration was never uploaded, or whose format we
cannot read, contributes nothing - and if it were simply left out, the aggregate
would climb every time somebody stopped uploading. So the components that could
not be measured are named and counted beside the figure, and the caller is given
no way to see the percentage without also seeing how much of the estate it
covers.

Staleness is the same argument in the time dimension: coverage computed from a
configuration uploaded three months ago is not a control, it is a souvenir. The
age of the oldest measurement travels with the figure.
"""
from __future__ import annotations

from datetime import timedelta, timezone

from sqlalchemy.orm import Session

from . import config_blocks
from .models import (
    ComponentActualConfig,
    CoverageSnapshot,
    SecurityComponent,
    utcnow,
)

# Beyond this, a measurement is reported as stale. Not a threshold anything is
# blocked on - a number the dashboard can say out loud.
STALE_AFTER = timedelta(days=30)


def _aware(dt):
    """A stored timestamp as UTC-aware.

    PostgreSQL hands these back with a timezone and SQLite without one, so
    subtracting two of them raises on the database the tests run against and not
    on the one production uses - the worst possible split. Same normalisation as
    audit._ts_canonical."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def measure(content: str, component_type) -> dict | None:
    """Coverage of one configuration, or None if it could not be read."""
    blocks = config_blocks.scan(content, component_type)
    result = config_blocks.coverage(blocks)
    return result if result["recognised"] else None


def record_snapshot(db: Session, component: SecurityComponent, content: str,
                    uploaded_by: str) -> CoverageSnapshot | None:
    """Records what this configuration measured, so a trend has something to plot.

    Written when a configuration arrives, never when somebody looks at the
    dashboard. A point per page view would draw a flat line out of an estate
    nobody has uploaded anything for in weeks, and a flat line reads as "stable"
    rather than "unmeasured".
    """
    result = measure(content, component.type)
    snapshot = CoverageSnapshot(
        component_id=component.id,
        recognised=result is not None,
        total=result["total"] if result else None,
        justified=result["justified"] if result else None,
        uploaded_by=uploaded_by,
    )
    db.add(snapshot)
    return snapshot


def _previous(db: Session, component_id: int) -> CoverageSnapshot | None:
    """The measurement before the most recent one, if there is one."""
    rows = (
        db.query(CoverageSnapshot)
        .filter(CoverageSnapshot.component_id == component_id,
                CoverageSnapshot.recognised.is_(True))
        .order_by(CoverageSnapshot.measured_at.desc(), CoverageSnapshot.id.desc())
        .limit(2)
        .all()
    )
    return rows[1] if len(rows) == 2 else None


def fleet_coverage(db: Session) -> dict:
    """One coverage figure for the estate, with everything needed to read it.

    Computed live from the stored configurations rather than from the recorded
    snapshots, so it always agrees with the per-component report. The snapshots
    are the history and are used only for the trend.
    """
    components = db.query(SecurityComponent).order_by(SecurityComponent.name).all()
    configs = {
        c.component_id: c
        for c in db.query(ComponentActualConfig).all()
    }

    total = justified = 0
    measured: list[dict] = []
    not_measured: list[dict] = []
    oldest = None
    unjustified_change = 0
    compared = 0

    for component in components:
        config = configs.get(component.id)
        if not config or not config.content.strip():
            # "Never uploaded" is a finding in itself, not a component to skip.
            not_measured.append({"component": component.name, "reason": "no configuration"})
            continue

        result = measure(config.content, component.type)
        if result is None:
            not_measured.append({"component": component.name,
                                 "reason": "configuration format not recognised"})
            continue

        total += result["total"]
        justified += result["justified"]
        if config.fetched_at:
            fetched = _aware(config.fetched_at)
            oldest = fetched if oldest is None else min(oldest, fetched)

        unjustified = result["total"] - result["justified"]
        entry = {
            "component": component.name,
            "component_id": component.id,
            "total": result["total"],
            "justified": result["justified"],
            "unjustified": unjustified,
            "percent": result["percent"],
            "fetched_at": config.fetched_at.isoformat() if config.fetched_at else None,
            "change": None,
        }

        # The trend is a comparison of measurements, so a component measured only
        # once contributes nothing to it - and how many did is reported, because
        # "no change" and "nothing to compare" are different answers.
        previous = _previous(db, component.id)
        if previous is not None and previous.total is not None:
            before = previous.total - (previous.justified or 0)
            entry["change"] = unjustified - before
            unjustified_change += entry["change"]
            compared += 1
        measured.append(entry)

    now = _aware(utcnow())
    age_days = int((now - oldest).total_seconds() // 86400) if oldest else None
    return {
        "components_total": len(components),
        "measured": len(measured),
        "total": total,
        "justified": justified,
        "unjustified": total - justified,
        # No denominator, no percentage. Reporting 100% for an estate nobody has
        # uploaded a configuration for is the one answer worse than none.
        "percent": round(justified * 100 / total) if total else None,
        "per_component": measured,
        "not_measured": not_measured,
        "oldest_measurement": oldest.isoformat() if oldest else None,
        "oldest_measurement_age_days": age_days,
        "stale": bool(oldest and now - oldest > STALE_AFTER),
        "unjustified_change": unjustified_change if compared else None,
        "compared": compared,
    }
