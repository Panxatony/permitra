"""Gültigkeits-Überwachung: ablaufende und abgelaufene Regeln.

- expiring_rules(): freigegebene Regeln, deren valid_until in den nächsten N Tagen
  liegt oder bereits überschritten ist (für die Rezertifizierungs-Ansicht).
- expire_rules(): täglicher Job – deaktiviert freigegebene Regeln automatisch,
  wenn ihre Gültigkeit abgelaufen ist (mit Versions- und Kommentareintrag).
"""
import logging
from datetime import date, timedelta

from sqlalchemy.orm import Session

from .models import Comment, Rule, RuleStatus, RuleVersion

log = logging.getLogger("permitra.expiry")


def _split_by_due(rules: list[Rule], today: date):
    """Teilt in bereits abgelaufen und demnächst ablaufend.

    Ein unlesbares Datum darf hier NICHT durchschlagen: Neue Regeln werden zwar
    serverseitig geprüft (schemas.parse_iso_date), Altbestand und Importe können
    aber Unsinn wie '2020-02-30' enthalten. Eine einzige solche Regel hätte
    sonst Dashboard, Ablaufliste und den täglichen Job für alle Nutzer
    lahmgelegt. Solche Regeln werden übersprungen und gemeldet – bewusst nicht
    automatisch deaktiviert, denn eine Rückbau-Entscheidung auf Basis
    unbrauchbarer Daten wäre schlimmer als das Liegenbleiben."""
    expired, expiring = [], []
    for rule in rules:
        try:
            due = date.fromisoformat((rule.valid_until or "").strip())
        except ValueError:
            log.warning("Regel %s hat ein unlesbares Gültig-bis (%r) und wird bei der "
                        "Ablaufprüfung übersprungen – bitte korrigieren",
                        rule.rule_id, rule.valid_until)
            continue
        (expired if due < today else expiring).append(rule)
    return expired, expiring


def invalid_validity_rules(db: Session) -> list[Rule]:
    """Regeln mit unlesbarem Gültig-bis – Datenqualitätsproblem, das sonst
    unbemerkt bliebe, weil die Ablaufprüfung sie überspringt."""
    rows = (db.query(Rule)
            .filter(Rule.valid_until.isnot(None), Rule.valid_until != "",
                    Rule.deleted_at.is_(None))
            .all())
    bad = []
    for rule in rows:
        try:
            date.fromisoformat((rule.valid_until or "").strip())
        except ValueError:
            bad.append(rule)
    return bad


def expiring_rules(db: Session, days: int = 30) -> tuple[list[Rule], list[Rule]]:
    """Liefert (abgelaufen, läuft in <days> Tagen ab) – nur freigegebene Regeln."""
    today = date.today()
    horizon = today + timedelta(days=days)
    candidates = (
        db.query(Rule)
        .filter(Rule.status == RuleStatus.approved, Rule.valid_until.isnot(None), Rule.deleted_at.is_(None))
        .filter(Rule.valid_until <= horizon.isoformat())
        .order_by(Rule.valid_until)
        .all()
    )
    return _split_by_due(candidates, today)


def expire_rules(db: Session) -> int:
    """Deaktiviert abgelaufene freigegebene Regeln. Gibt die Anzahl zurück."""
    expired, _ = expiring_rules(db, days=0)
    for rule in expired:
        rule.status = RuleStatus.deactivated
        rule.version += 1
        db.add(
            RuleVersion(
                rule_pk=rule.id,
                version=rule.version,
                snapshot={"auto": "expiry"},
                change_note=f"Automatisch deaktiviert: Gültigkeit bis {rule.valid_until} abgelaufen",
                changed_by="system",
            )
        )
        db.add(
            Comment(
                rule_pk=rule.id,
                author="system",
                text=f"Regel automatisch deaktiviert – Gültigkeit bis {rule.valid_until} abgelaufen. "
                     "Bei weiterem Bedarf bitte rezertifizieren (neu einreichen).",
            )
        )
    if expired:
        db.commit()
    return len(expired)
