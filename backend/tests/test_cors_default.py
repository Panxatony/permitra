"""CORS is off unless an operator names an origin.

The shipped deployment is same-origin (nginx serves the UI and proxies /api),
and the Vite dev server proxies /api too, so nothing needs CORS by default. The
previous default admitted three localhost origins on every installation that
did not override it.
"""
import importlib
import os

os.environ.setdefault("PERMITRA_DEV", "1")


def _origins(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("PERMITRA_CORS_ORIGINS", raising=False)
    else:
        monkeypatch.setenv("PERMITRA_CORS_ORIGINS", value)
    import app.main
    return importlib.reload(app.main).CORS_ORIGINS


def test_no_origin_is_allowed_by_default(monkeypatch):
    assert _origins(monkeypatch, None) == []


def test_configured_origins_are_used(monkeypatch):
    assert _origins(monkeypatch, "https://permitra.example, https://b.example") == [
        "https://permitra.example", "https://b.example"]


def test_a_wildcard_is_never_accepted(monkeypatch):
    assert _origins(monkeypatch, "*") == []
