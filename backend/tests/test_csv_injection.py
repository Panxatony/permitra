"""A CSV cell a spreadsheet cannot execute.

Permitra replaces the Excel matrix, so its CSV exports are opened in Excel and
LibreOffice - where a cell starting =, +, -, @ or a control character is parsed
as a formula. A justification of =HYPERLINK(...) or a DDE payload runs on open,
in front of the auditor who trusts the file.
"""
from app.exporters.common import csv_safe


def test_a_formula_trigger_is_neutralised():
    for danger in ("=1+1", "+1", "-1", "@SUM(A1)", "=cmd|'/c calc'!A1"):
        assert csv_safe(danger).startswith("'")


def test_ordinary_text_is_untouched():
    for ok in ("SR00042", "HTTPS for the web servers", "10.0.0.1/24", ""):
        assert csv_safe(ok) == ok


def test_the_export_quotes_a_malicious_justification(db_with_rule=None):
    """End to end: a rule whose justification is a formula exports as text."""
    from app.exporters.generic import export_csv
    from app.models import Rule, RuleAction, RuleStatus

    rule = Rule(rule_id="SR00001", name="x", action=RuleAction.permit,
                status=RuleStatus.approved,
                justification='=HYPERLINK("http://evil","click")',
                source=[{"ip": "10.0.0.1", "alias": ""}],
                destination=[{"ip": "10.0.1.1", "alias": ""}],
                services=[{"protocol": "TCP", "port": "443"}])
    out = export_csv([rule])
    assert '=HYPERLINK' not in out.replace("'=HYPERLINK", "")
    assert "'=HYPERLINK" in out
