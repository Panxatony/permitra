"""What changed on a rule since a component was configured.

Operations confirms a rule per component ("implemented"). A renewed approval
turns that into "to change", and the implementation view then shows the rule
as it is approved now - which says what the device should look like, but not
what to do: an address that was dropped is simply no longer in the preview.
This module finds the version operations confirmed and names the difference to
the current rule, so the entries to add and the entries to take off the device
are both on the page.

It compares what the rule says, not generated configuration lines: the
exporters render the current object catalogue (EPG mappings, object names),
and replaying them for an old version would show today's catalogue under
yesterday's rule.
"""
from __future__ import annotations

# The scalar fields of a version snapshot that reach a device: the policy name,
# what the rule does and between which zones. Texts such as the justification
# end up in comments only, and a new expiry date changes nothing on a firewall.
# The logging level is not part of a version snapshot and cannot be compared.
DEVICE_FIELDS = ("name", "action", "source_zone", "destination_zone", "vrf")


def implemented_version(versions, component: str):
    """The version at which `component` was last confirmed as implemented, or None.

    A status report by operations stores what it set next to the version, and
    that is taken at its word. Versions without one (imported rules, history
    from before the values were stored separately) count when the component
    *turns* implemented from one snapshot to the next - not while it merely
    stays implemented, because an edit leaves the status standing until the
    next approval and its snapshot already holds the new, unconfirmed content.
    Automatic entries (address re-checks, expiry) carry no rule content and are
    skipped.
    """
    found = None
    previous = None
    for version in sorted(versions, key=lambda v: v.version):
        snap = version.snapshot or {}
        if "rule_id" not in snap:
            continue
        now = (snap.get("impl_status") or {}).get(component)
        reported = (version.change_values or {}).get("impl_status")
        if isinstance(reported, dict) and component in reported:
            confirmed = reported[component] == "implemented"
        else:
            confirmed = now == "implemented" and previous != "implemented"
        if confirmed:
            found = version
        previous = now
    return found


def _address_key(entry: dict) -> str:
    # The address is what a device matches on. An alias can be renamed without
    # any packet being treated differently, so it does not make an entry new.
    return (entry.get("ip") or entry.get("group") or entry.get("alias") or "").strip().lower()


def _service_key(entry: dict) -> tuple[str, str]:
    return ((entry.get("protocol") or "").strip().upper(), (entry.get("port") or "").strip().lower())


def _added_removed(old: list | None, new: list | None, key) -> dict:
    old, new = old or [], new or []
    old_keys, new_keys = {key(e) for e in old}, {key(e) for e in new}
    return {
        "added": [e for e in new if key(e) not in old_keys],
        "removed": [e for e in old if key(e) not in new_keys],
    }


def difference(old: dict, new: dict) -> dict:
    """The difference between two version snapshots, limited to what reaches a device."""
    return {
        "source": _added_removed(old.get("source"), new.get("source"), _address_key),
        "destination": _added_removed(old.get("destination"), new.get("destination"), _address_key),
        "services": _added_removed(old.get("services"), new.get("services"), _service_key),
        "fields": [
            {"field": field, "old": old.get(field), "new": new.get(field)}
            for field in DEVICE_FIELDS
            if (old.get(field) or "") != (new.get(field) or "")
        ],
    }


def is_empty(diff: dict) -> bool:
    return not diff["fields"] and not any(
        diff[part][side] for part in ("source", "destination", "services") for side in ("added", "removed"))


def has_removals(diff: dict) -> bool:
    return any(diff[part]["removed"] for part in ("source", "destination", "services"))
