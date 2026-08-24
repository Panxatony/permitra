"""Permitra settings (settings table, maintained in the admin area).

Known keys and their allowed values live in KNOWN_SETTINGS; the first value of
each entry is the default used when the key is not set."""
from sqlalchemy.orm import Session

from .messages import _
from .models import Setting

# zone_matrix_default: behaviour for zone relations WITHOUT a matrix entry.
#   "permit" = allowed with a warning (legacy behaviour)
#   "deny"   = least privilege: rules are rejected until the relation has been
#              explicitly set to allow via a matrix request (BSI recommendation)
KNOWN_SETTINGS = {
    "zone_matrix_default": ("permit", "deny"),
    # Mandatory rule fields (BSI documentation requirements):
    # ACTIVE by default (first value = default), admins may turn them off
    "require_justification": ("yes", "no"),   # justification
    "require_valid_until": ("yes", "no"),     # enforce an expiry date
    # Interface language of this instance, chosen by the administrator. English
    # is the source language of the application; German is a translation. The
    # setting is binding for everyone - there is no per-user override, so
    # screenshots, training material and support all speak one language.
    "ui_language": ("en", "de"),
    # How long an emergency change may stand before somebody has to approve it
    # after the fact. Short on purpose: the window is what keeps the fast path
    # from becoming an ordinary Tuesday. First value is the default.
    "emergency_window_hours": ("24", "8", "48", "72"),
    # How long an audit event is kept before its segment is collapsed behind a
    # retention seal (days). "0" keeps everything forever, which is the current
    # behaviour and the safe default - retention deletes personal data, so it is
    # an operator decision, never a surprise on upgrade. See audit.collapse_expired.
    "audit_retention_days": ("0", "90", "180", "365", "730", "1095"),
}


def get_setting(db: Session, key: str) -> str:
    allowed = KNOWN_SETTINGS[key]
    row = db.get(Setting, key)
    return row.value if row and row.value in allowed else allowed[0]


def set_setting(db: Session, key: str, value: str) -> None:
    if key not in KNOWN_SETTINGS:
        raise ValueError(_("Unknown setting '{key}'", key=key))
    if value not in KNOWN_SETTINGS[key]:
        raise ValueError(_("Invalid value '{value}' for '{key}' (allowed: {allowed})",
                           value=value, key=key,
                           allowed=", ".join(KNOWN_SETTINGS[key])))
    row = db.get(Setting, key)
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))
    db.commit()


def all_settings(db: Session) -> dict:
    return {key: get_setting(db, key) for key in KNOWN_SETTINGS}
