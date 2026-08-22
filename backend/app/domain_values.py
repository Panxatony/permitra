"""Canonical domain values and their translation for the interface.

The code language is English, so the values stored in the database are English
too: a rule is "implemented", a zone has protection level "high". Until now
these values were German and were shown untranslated, which meant the English
interface displayed "umgesetzt" and "sehr hoch".

The German wording is not lost - it lives in the frontend dictionary, keyed by
the English value. Storing English and translating for display keeps one
representation in the database while both languages stay available.

`LEGACY_*` maps the former German values to the current ones. The Alembic
migration uses it to convert existing rows; it is kept here so the mapping has
a single, documented home.
"""

# Rollout status per component (maintained by operations)
IMPL_STATUSES = ["open", "new", "to change", "to remove", "implemented", "deactivated"]

LEGACY_IMPL_STATUS = {
    "offen": "open",
    "neu": "new",
    "zu ändern": "to change",
    "zu löschen": "to remove",
    "umgesetzt": "implemented",
    "deaktiviert": "deactivated",
}

# Protection level per BSI goal (C/I/A); the zone's overall level is the maximum
PROTECTION_LEVELS = ["normal", "high", "very high"]

LEGACY_PROTECTION_LEVEL = {
    "normal": "normal",
    "hoch": "high",
    "sehr hoch": "very high",
}

# Position relative to the BSI P-A-P structure
PAP_LEVELS = ["external", "pap", "internal"]

LEGACY_PAP_LEVEL = {
    "extern": "external",
    "pap": "pap",
    "intern": "internal",
}

# Severity of a risk finding
RISK_LEVELS = ["none", "low", "medium", "high"]

LEGACY_RISK_LEVEL = {
    "none": "none",
    "niedrig": "low",
    "mittel": "medium",
    "hoch": "high",
}
