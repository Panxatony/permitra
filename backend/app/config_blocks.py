"""Finds where a rule starts in a device configuration, without reading it.

The drift comparison used to look only for SR IDs. That answers "did my rules
arrive?" and misses the question Permitra exists for: is everything on the
device covered by an approved security rule? A rule somebody opened by hand
carries no SR ID, so it produced nothing to find — it was not reported as
unjustified, it was not reported at all, and there was no total to measure
against either.

This module supplies the denominator. It recognises *where a rule begins* and
what identifier it carries, deliberately without interpreting addresses,
services or actions. That is the cheap half: a regular expression per vendor
instead of a parser. Understanding what a rule permits — and therefore whether
it complies with the zone matrix — is a separate, larger job.

The honesty rule here matters more than the coverage: when a configuration is
in a format we do not recognise, we say so. Reporting "0 unjustified" because
nothing was found would be worse than reporting nothing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .models import ComponentType

RULE_ID_RE = re.compile(r"\bSR\d{3,6}\b")


@dataclass
class RuleBlock:
    """One rule found on the device."""

    identifier: str          # what the device calls it
    rule_id: str | None      # the security rule it claims, if any
    line: int                # 1-based, so a person can find it


# Where a rule starts, per platform. The capture group is the device's own name
# for it. Only formats Permitra itself writes are covered - guessing at a vendor
# syntax nobody here has seen would produce confident nonsense.
BLOCK_STARTS: dict[ComponentType, re.Pattern] = {
    # Juniper: many lines share one policy name; the name is the block.
    ComponentType.juniper: re.compile(
        r"^\s*set\s+security\s+policies\s+from-zone\s+\S+\s+to-zone\s+\S+\s+policy\s+(\S+)"),
    # Check Point: one invocation per rule in the mgmt_cli script.
    ComponentType.checkpoint: re.compile(
        r"^\s*mgmt_cli\s+add-access-rule\b.*?(?:--name|\bname)\s+[\"']?([^\"'\s]+)"),
}


def scan(text: str, component_type: ComponentType) -> list[RuleBlock] | None:
    """The rules in this configuration, or None if the format is not recognised.

    None and [] mean different things and must not be conflated: an empty list
    is "we looked and there are none", None is "we cannot tell". Only the first
    justifies a coverage figure.
    """
    pattern = BLOCK_STARTS.get(component_type)
    if pattern is None:
        return None

    lines = text.splitlines()
    starts: list[tuple[int, str]] = []
    seen: set[str] = set()
    for number, line in enumerate(lines, start=1):
        match = pattern.match(line)
        if not match:
            continue
        name = match.group(1)
        if name in seen:
            continue          # Juniper repeats the policy name on every match line
        seen.add(name)
        starts.append((number, name))

    if not starts:
        return None           # right platform, unrecognisable content

    blocks = []
    for index, (number, name) in enumerate(starts):
        # The SR ID may sit inside the block (Check Point writes it into the
        # name and comments, Juniper into the policy description) or in a
        # comment directly above it (Permitra's export file writes
        # "# SR00042: ..." before the policy).
        next_start = starts[index + 1][0] - 1 if index + 1 < len(starts) else len(lines)
        own = lines[number - 1:next_start]

        # Only the comment block immediately above counts. Reaching further
        # back would pick up the *previous* rule's ID and mark an undocumented
        # rule as covered - which is the one mistake this whole module exists
        # to prevent.
        preamble, cursor = [], number - 2
        while cursor >= 0 and (not lines[cursor].strip()
                               or lines[cursor].lstrip().startswith("#")):
            preamble.insert(0, lines[cursor])
            cursor -= 1

        found = RULE_ID_RE.search("\n".join(preamble + own))
        blocks.append(RuleBlock(identifier=name,
                                rule_id=found.group(0) if found else None,
                                line=number))
    return blocks


def coverage(blocks: list[RuleBlock] | None) -> dict:
    """The figure that belongs on a dashboard, or an explicit "unknown".

    A rule with no SR ID is the interesting one: it exists on the device and no
    approved security rule claims it. That is the thing Permitra is for.
    """
    if blocks is None:
        return {
            "recognised": False,
            "total": None, "justified": None, "percent": None,
            "unjustified": [],
        }

    unjustified = [b for b in blocks if not b.rule_id]
    justified = len(blocks) - len(unjustified)
    return {
        "recognised": True,
        "total": len(blocks),
        "justified": justified,
        "percent": round(justified * 100 / len(blocks)) if blocks else 100,
        "unjustified": [{"identifier": b.identifier, "line": b.line} for b in unjustified],
    }
