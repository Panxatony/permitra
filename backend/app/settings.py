"""Permitra-Einstellungen (settings-Tabelle, Pflege im Admin-Bereich).

Bekannte Schlüssel und erlaubte Werte stehen in KNOWN_SETTINGS; der jeweils
erste Wert ist der Default, wenn der Schlüssel nicht gesetzt ist."""
from sqlalchemy.orm import Session

from .models import Setting

# zone_matrix_default: Verhalten für Zonen-Beziehungen OHNE Matrix-Eintrag.
#   "permit" = erlaubt mit Hinweis (Bestandsverhalten)
#   "deny"   = Minimalprinzip: Regeln werden abgelehnt, bis die Beziehung
#              per Matrix-Antrag explizit auf Allow gesetzt ist (BSI-Empfehlung)
KNOWN_SETTINGS = {
    "zone_matrix_default": ("permit", "deny"),
    # Pflichtfelder für Regeln (BSI-Dokumentationspflichten):
    # standardmäßig AKTIV (erster Wert = Default), Admin kann sie abschalten
    "require_justification": ("yes", "no"),   # Begründung
    "require_requestor": ("yes", "no"),       # Verantwortlicher/Requestor
    "require_valid_until": ("yes", "no"),     # Ablaufdatum erzwingen
}


def get_setting(db: Session, key: str) -> str:
    allowed = KNOWN_SETTINGS[key]
    row = db.query(Setting).get(key)
    return row.value if row and row.value in allowed else allowed[0]


def set_setting(db: Session, key: str, value: str) -> None:
    if key not in KNOWN_SETTINGS:
        raise ValueError(f"Unbekannte Einstellung '{key}'")
    if value not in KNOWN_SETTINGS[key]:
        raise ValueError(f"Ungültiger Wert '{value}' für '{key}' "
                        f"(erlaubt: {', '.join(KNOWN_SETTINGS[key])})")
    row = db.query(Setting).get(key)
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))
    db.commit()


def all_settings(db: Session) -> dict:
    return {key: get_setting(db, key) for key in KNOWN_SETTINGS}
