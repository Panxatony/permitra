"""Workloads, labels and the groups rules refer to by name.

A micro-segmentation policy names groups ("the web tier may reach the
database tier"), not addresses. Permitra's rules are address-based on purpose
- an address is what a firewall and a drift comparison can check - so a group
is resolved to addresses at the moment a rule is written, and again whenever
its membership changes. The rule keeps the group's name on every member
entry, which is what makes the second step possible: a rule is found by the
group it refers to, its members are recomputed, and the rule is re-checked
the way an edited rule would be.

What this is not: a push to any platform. The inventory and the groups are
documentation, and the exporters that exist resolve a group to the objects
their platform knows.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from .messages import _
from .models import AddressGroup, GroupKind, Rule, Workload, active_rules
from .validation import parse_network

# ---------- selectors ----------

def parse_selector(selector: str) -> list[tuple[str, str, str]]:
    """`app=shop, tier!=db, env` -> [(key, op, value)], op in '=', '!=', 'exists'.

    Comma-separated terms, all of which must hold. Deliberately small: what a
    label selector in Kubernetes or Illumio expresses in practice is a
    conjunction of equalities, and a richer grammar would have to be taught
    to every person who reads a rule.
    """
    terms = []
    for raw in (selector or "").split(","):
        term = raw.strip()
        if not term:
            continue
        if "!=" in term:
            key, value = term.split("!=", 1)
            terms.append((key.strip(), "!=", value.strip()))
        elif "=" in term:
            key, value = term.split("=", 1)
            terms.append((key.strip(), "=", value.strip()))
        else:
            terms.append((term, "exists", ""))
    return terms


def validate_selector(selector: str) -> str:
    terms = parse_selector(selector)
    if not terms:
        raise ValueError(_("The selector is empty – name at least one label, e.g. app=shop"))
    for key, _op, _value in terms:
        if not key or any(ch in key for ch in " ,=!"):
            raise ValueError(_("'{key}' is not a valid label key", key=key or "?"))
    return ", ".join(f"{k}{'' if op == 'exists' else op + v}" for k, op, v in terms)


def selector_matches(labels: dict | None, selector: str) -> bool:
    labels = labels or {}
    for key, op, value in parse_selector(selector):
        if op == "exists" and key not in labels:
            return False
        if op == "=" and str(labels.get(key)) != value:
            return False
        if op == "!=" and str(labels.get(key)) == value:
            return False
    return True


# ---------- resolution ----------

def _entry(ip: str, alias: str, group: str) -> dict:
    return {"ip": ip, "alias": alias, "group": group}


def workload_entries(workload: Workload, group: str) -> list[dict]:
    return [_entry(ip, workload.name, group) for ip in (workload.addresses or [])]


def resolve_group(db: Session, group: AddressGroup) -> list[dict]:
    """The group's members as address entries, each carrying the group's name.

    A selector group is every workload in the group's environment whose labels
    satisfy the selector; a static group is what was listed: workloads by
    name, addresses as given."""
    members: list[dict] = []
    if group.kind == GroupKind.selector:
        workloads = db.query(Workload).filter(Workload.vrf_id == group.vrf_id).order_by(Workload.name).all()
        for w in workloads:
            if selector_matches(w.labels, group.selector or ""):
                members.extend(workload_entries(w, group.name))
    else:
        for item in group.members or []:
            if item.get("workload"):
                w = (db.query(Workload)
                       .filter(Workload.vrf_id == group.vrf_id, Workload.name.ilike(item["workload"]))
                       .first())
                if w:
                    members.extend(workload_entries(w, group.name))
            elif item.get("ip"):
                members.append(_entry(item["ip"].strip(), (item.get("alias") or "").strip(), group.name))
    # One entry per address: two workloads sharing an address, or an address
    # listed twice, must not produce two identical rule entries.
    seen, unique = set(), []
    for m in members:
        key = str(parse_network(m["ip"]) or m["ip"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(m)
    return unique


def find_group(db: Session, name: str, vrf_id: int) -> AddressGroup | None:
    return (db.query(AddressGroup)
              .filter(AddressGroup.vrf_id == vrf_id, AddressGroup.name.ilike((name or "").strip()))
              .first())


def expand_entries(db: Session, entries: list[dict], vrf_id: int) -> tuple[list[dict], list[str]]:
    """Replace group references by their members; plain entries pass through.

    An entry refers to a group when it carries `group`. Entries that are
    already expanded members (they carry `group` and an address) collapse
    back to one reference first, so a rule sent back as it was stored
    re-expands against the current membership rather than keeping stale
    members. Returns (entries, problems); a problem is a group that does not
    exist or has no members - a rule must not quietly be about nothing.
    """
    expanded: list[dict] = []
    problems: list[str] = []
    seen_groups: list[str] = []
    for entry in entries or []:
        group_name = (entry.get("group") or "").strip()
        if not group_name:
            expanded.append({"ip": (entry.get("ip") or "").strip(), "alias": (entry.get("alias") or "").strip()})
            continue
        if group_name.lower() in (g.lower() for g in seen_groups):
            continue
        seen_groups.append(group_name)
        group = find_group(db, group_name, vrf_id)
        if group is None:
            problems.append(_("Group '{name}' does not exist", name=group_name))
            continue
        members = resolve_group(db, group)
        if not members:
            problems.append(_("Group '{name}' has no members", name=group.name))
            continue
        expanded.extend(members)
    return expanded, problems


def groups_referenced(entries: list[dict]) -> set[str]:
    return {(e.get("group") or "").strip().lower() for e in entries or [] if (e.get("group") or "").strip()}


def rules_referencing(db: Session, names: set[str]) -> list[Rule]:
    """Active rules with at least one entry that refers to one of the groups."""
    wanted = {n.lower() for n in names}
    out = []
    for rule in active_rules(db).all():
        if (groups_referenced(rule.source) | groups_referenced(rule.destination)) & wanted:
            out.append(rule)
    return out


def groups_affected_by_labels(db: Session, vrf_id: int, before: dict | None, after: dict | None) -> set[str]:
    """Selector groups whose membership a label change could have moved."""
    names = set()
    for group in db.query(AddressGroup).filter(AddressGroup.vrf_id == vrf_id,
                                               AddressGroup.kind == GroupKind.selector).all():
        was = before is not None and selector_matches(before, group.selector or "")
        now = after is not None and selector_matches(after, group.selector or "")
        if was or now:
            names.add(group.name)
    return names


def groups_listing_workload(db: Session, vrf_id: int, workload_name: str) -> set[str]:
    names = set()
    for group in db.query(AddressGroup).filter(AddressGroup.vrf_id == vrf_id,
                                               AddressGroup.kind == GroupKind.static).all():
        if any((m.get("workload") or "").lower() == workload_name.lower() for m in group.members or []):
            names.add(group.name)
    return names
