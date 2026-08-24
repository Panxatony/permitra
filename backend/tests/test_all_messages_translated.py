"""Every user-facing message has a German translation.

The catalogue guard in test_history_language covers audit and version-note
templates - the ones stored and rendered later. It does not cover the messages
raised inline with _(), and that gap is exactly how an English risk finding and
an English zone-matrix message reached a German instance: the templates were
never in the catalogue, so _() fell back to English regardless of the language.

This walks every _("literal") call across app/ and asserts the template is in
the German catalogue. A missing entry falls back to English silently - which is
the symptom - and would show up in nobody's test run otherwise.
"""
import ast
import pathlib

from app import messages

APP = pathlib.Path(__file__).resolve().parent.parent / "app"


def _translation_templates() -> dict:
    """Every literal first argument to _() across the application, with one
    location each - so a failure names where to look."""
    found: dict[str, str] = {}
    for path in APP.rglob("*.py"):
        if path.name == "messages.py":
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if getattr(node.func, "id", None) != "_":
                continue
            if node.args and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str):
                found.setdefault(node.args[0].value,
                                 f"{path.relative_to(APP.parent)}:{node.lineno}")
    return found


def test_every_translation_call_has_a_german_entry():
    templates = _translation_templates()
    assert templates, "no _() calls found - the AST walk stopped matching"

    missing = {t: loc for t, loc in templates.items()
               if t not in messages.CATALOG["de"]}
    assert missing == {}, "untranslated messages (fall back to English):\n" + \
        "\n".join(f"  {loc}: {t}" for t, loc in sorted(missing.items()))


def test_the_walk_still_finds_a_known_translated_message():
    """A canary: the guard can pass by finding nothing. This pins one message it
    must always see, so a narrowed walk fails rather than silently passing."""
    assert "Rule {rule_id} not found" in _translation_templates()
