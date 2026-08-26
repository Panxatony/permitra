"""What a rule on the device actually permits — the reading side of the export.

The coverage figure (config_blocks) answers "is this rule justified at all?".
It does not answer "is it justified by *this*?". A rule widened during an
incident — one host on port 443 opened up to `any` — still carries its SR ID in
the description, so it wears the approval of the narrow rule it used to be, and
every check reads green.

This module parses a rule block into what it permits (sources, destinations,
services, action) and compares that against the approved rule. The whole point
is one asymmetry: **narrower than approved is fine** — operations may implement
less than was allowed — **wider is a finding**. Getting that backwards would
turn every partial rollout into a false alarm and hide every real widening.

Only the formats Permitra itself writes are parsed (Juniper set commands, Check
Point mgmt_cli). Where a block cannot be parsed to this depth, that is said, not
guessed: `parse()` returns None for the whole configuration, and the drift
report marks the fidelity check as not performed rather than as passed. "Cannot
tell" must never render as "all clear".
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .models import ComponentType
from .validation import is_ping_port

ANY_V4 = ipaddress.ip_network("0.0.0.0/0")
ANY_V6 = ipaddress.ip_network("::/0")

# junos-* service names our own exporter emits, plus the handful a hand-written
# config is likely to use. An unknown junos-* name is left unresolved on
# purpose - claiming a port for a service we do not know would invent fidelity.
# ICMP has no ports, so for it the range holds the *type* instead. That keeps
# one comparison for everything: a device permitting every ICMP type (0-65535)
# covers an approval for echo (8-8), and the widening check reports it - which
# is the whole question a ping-only rule raises. Approved echo against a device
# that answers every ICMP type is exactly the asymmetric widening this module
# exists to catch.
ICMP_ECHO = (8, 8)

JUNOS_SERVICES: dict[str, tuple[str, int, int]] = {
    "junos-icmp-all": ("icmp", 0, 65535),
    "junos-ping": ("icmp", *ICMP_ECHO),
    "junos-icmp-ping": ("icmp", *ICMP_ECHO),
    "junos-https": ("tcp", 443, 443),
    "junos-http": ("tcp", 80, 80),
    "junos-ssh": ("tcp", 22, 22),
    "junos-dns-udp": ("udp", 53, 53),
    "junos-dns-tcp": ("tcp", 53, 53),
    "junos-ntp": ("udp", 123, 123),
    "junos-ldap": ("tcp", 389, 389),
    "junos-smtp": ("tcp", 25, 25),
    "junos-ftp": ("tcp", 21, 21),
    "junos-telnet": ("tcp", 23, 23),
}


@dataclass
class Service:
    """A protocol and a port range. proto 'any' matches every protocol; a range
    of (0, 65535) is every port."""

    proto: str
    lo: int
    hi: int

    def covers(self, other: "Service") -> bool:
        if self.proto != "any" and other.proto != self.proto:
            return False
        return self.lo <= other.lo and other.hi <= self.hi


@dataclass
class Permission:
    """What a rule allows, normalised so two rules can be compared.

    None inside `unresolved` means a name that could not be resolved to an
    address or a service - it makes the permission un-comparable rather than
    silently narrower, so the caller reports "cannot tell" instead of "matches".
    """

    sources: list = field(default_factory=list)          # ip_network
    destinations: list = field(default_factory=list)     # ip_network
    services: list = field(default_factory=list)         # Service
    action: str = "permit"
    src_any: bool = False
    dst_any: bool = False
    svc_any: bool = False
    unresolved: list = field(default_factory=list)       # names we could not resolve


def _networks_cover(covering: list, covering_any: bool, subject: list, subject_any: bool):
    """Is every address in `subject` inside the `covering` set? Returns the list
    of subject networks that are NOT covered - empty means fully covered."""
    if covering_any:
        return []
    if subject_any:
        # The device permits any, the approval does not: the whole address space
        # is the widening.
        return ["any"]
    escaped = []
    for net in subject:
        if not any(_subnet_of(net, c) for c in covering):
            escaped.append(str(net))
    return escaped


def _subnet_of(net, other) -> bool:
    if net.version != other.version:
        return False
    return net.subnet_of(other)


def _services_cover(covering: list, covering_any: bool, subject: list, subject_any: bool):
    if covering_any:
        return []
    if subject_any:
        return ["any"]
    escaped = []
    for svc in subject:
        if not any(c.covers(svc) for c in covering):
            escaped.append(_svc_str(svc))
    return escaped


def _svc_str(svc: Service) -> str:
    if svc.proto.startswith("icmp") and (svc.lo, svc.hi) == ICMP_ECHO:
        return f"{svc.proto}/echo"
    port = "any" if (svc.lo, svc.hi) == (0, 65535) else (
        str(svc.lo) if svc.lo == svc.hi else f"{svc.lo}-{svc.hi}")
    return f"{svc.proto}/{port}"


def widening(device: Permission, approved: Permission) -> list[str]:
    """How the device rule permits more than the approval - empty if it does not.

    Narrower is fine and returns nothing. Each entry names one concrete way the
    device is wider, so the finding tells operations what to look at rather than
    just "does not match".
    """
    diffs: list[str] = []
    # A device rule with an unresolved name is not compared here: it cannot be
    # proven wider, and calling it a widening would be a false alarm. The caller
    # separates those into "unverified" - cannot tell, which is not all clear
    # but is not a finding either.
    for over in _networks_cover(approved.sources, approved.src_any,
                                device.sources, device.src_any):
        diffs.append(f"source {over} is not covered by the approved sources")
    for over in _networks_cover(approved.destinations, approved.dst_any,
                                device.destinations, device.dst_any):
        diffs.append(f"destination {over} is not covered by the approved destinations")
    for over in _services_cover(approved.services, approved.svc_any,
                                device.services, device.svc_any):
        diffs.append(f"service {over} is beyond what was approved")
    # A device that permits where the approval refuses (or vice versa) is a
    # different rule, not a wider one - but for a permit rule the permissive
    # direction is the dangerous one, so it is reported.
    if device.action == "permit" and approved.action != "permit":
        diffs.append(f"action is permit, approved was {approved.action}")
    return diffs


# --------------------------------------------------------------------------
# Building the approved side, from a Permitra rule

def _service_from_spec(proto: str, port: str) -> list:
    proto = (proto or "").strip().lower()
    port = (port or "").strip()
    if proto in ("", "any", "ip"):
        return [Service("any", 0, 65535)]
    if proto.startswith("icmp"):
        return [Service(proto, *(ICMP_ECHO if is_ping_port(port) else (0, 65535)))]
    protos = ["tcp", "udp"] if proto in ("tcp/udp", "tcpudp") else [proto]
    ranges = _port_ranges(port)
    out = []
    for p in protos:
        for lo, hi in ranges:
            out.append(Service(p, lo, hi))
    return out


def _port_ranges(spec: str) -> list:
    """Parses '443', '20-25', '22,23', '' (=any) into (lo, hi) ranges."""
    spec = (spec or "").strip()
    if not spec or spec.lower() == "any":
        return [(0, 65535)]
    ranges = []
    for part in re.split(r"[,\s]+", spec):
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                continue
            ranges.append((min(lo, hi), max(lo, hi)))
        else:
            try:
                p = int(part)
            except ValueError:
                continue
            ranges.append((p, p))
    return ranges or [(0, 65535)]


def approved_permission(rule) -> Permission:
    """The Permission a rule was approved for - the yardstick device rules are
    measured against."""
    perm = Permission(action=rule.action.value)
    for entry in rule.source or []:
        _add_address(perm, entry.get("ip", ""), is_source=True)
    for entry in rule.destination or []:
        _add_address(perm, entry.get("ip", ""), is_source=False)
    for svc in rule.services or []:
        for s in _service_from_spec(svc.get("protocol", ""), svc.get("port", "")):
            if s.proto == "any" and (s.lo, s.hi) == (0, 65535):
                perm.svc_any = True
            perm.services.append(s)
    return perm


def _add_address(perm: Permission, ip: str, *, is_source: bool):
    ip = (ip or "").strip()
    if ip.lower() == "any" or ip == "":
        if is_source:
            perm.src_any = True
        else:
            perm.dst_any = True
        return
    try:
        net = ipaddress.ip_network(ip, strict=False)
    except ValueError:
        perm.unresolved.append(ip)
        return
    (perm.sources if is_source else perm.destinations).append(net)


# --------------------------------------------------------------------------
# Parsing the device side, per platform

def parse(text: str, component_type: ComponentType) -> dict | None:
    """{identifier -> Permission} for every rule in the configuration, or None
    if the platform's format cannot be parsed to this depth."""
    if component_type == ComponentType.juniper:
        return _parse_juniper(text)
    if component_type == ComponentType.checkpoint:
        return _parse_checkpoint(text)
    return None


_J_ADDR = re.compile(
    r"^\s*set\s+security\s+zones\s+security-zone\s+\S+\s+address-book\s+address\s+(\S+)\s+(\S+)")
_J_APP_PROTO = re.compile(
    r"^\s*set\s+applications\s+application\s+(\S+)\s+protocol\s+(\S+)")
_J_APP_PORT = re.compile(
    r"^\s*set\s+applications\s+application\s+(\S+)\s+destination-port\s+(\S+)")
_J_POLICY = re.compile(
    r"^\s*set\s+security\s+policies\s+from-zone\s+\S+\s+to-zone\s+\S+\s+policy\s+(\S+)\s+(.*)")


def _parse_juniper(text: str) -> dict | None:
    address_book: dict[str, str] = {}
    app_proto: dict[str, str] = {}
    app_port: dict[str, str] = {}
    policies: dict[str, dict] = {}
    saw_policy = False

    for line in text.splitlines():
        m = _J_ADDR.match(line)
        if m:
            address_book[m.group(1)] = m.group(2)
            continue
        m = _J_APP_PROTO.match(line)
        if m:
            app_proto[m.group(1)] = m.group(2).lower()
            continue
        m = _J_APP_PORT.match(line)
        if m:
            app_port[m.group(1)] = m.group(2)
            continue
        m = _J_POLICY.match(line)
        if m:
            saw_policy = True
            name, rest = m.group(1), m.group(2).strip()
            p = policies.setdefault(name, {"src": [], "dst": [], "app": [], "action": "permit"})
            sm = re.match(r"match\s+source-address\s+(\S+)", rest)
            dm = re.match(r"match\s+destination-address\s+(\S+)", rest)
            am = re.match(r"match\s+application\s+(\S+)", rest)
            act = re.match(r"then\s+(permit|deny|reject)\b", rest)
            if sm:
                p["src"].append(sm.group(1))
            elif dm:
                p["dst"].append(dm.group(1))
            elif am:
                p["app"].append(am.group(1))
            elif act:
                p["action"] = act.group(1)

    if not saw_policy:
        return None

    result = {}
    for name, p in policies.items():
        perm = Permission(action=p["action"])
        _resolve_juniper_addresses(perm, p["src"], address_book, is_source=True)
        _resolve_juniper_addresses(perm, p["dst"], address_book, is_source=False)
        _resolve_juniper_apps(perm, p["app"], app_proto, app_port)
        result[name] = perm
    return result


def _resolve_juniper_addresses(perm, names, address_book, *, is_source):
    for name in names:
        if name == "any":
            if is_source:
                perm.src_any = True
            else:
                perm.dst_any = True
            continue
        cidr = address_book.get(name)
        if cidr is None:
            perm.unresolved.append(name)
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            perm.unresolved.append(name)
            continue
        (perm.sources if is_source else perm.destinations).append(net)


def _resolve_juniper_apps(perm, apps, app_proto, app_port):
    for app in apps:
        if app == "any":
            perm.svc_any = True
            continue
        if app in JUNOS_SERVICES:
            proto, lo, hi = JUNOS_SERVICES[app]
            perm.services.append(Service(proto, lo, hi))
            continue
        # Our own naming: "tcp-443"
        m = re.match(r"^(tcp|udp)-(\d+)(?:-(\d+))?$", app)
        if m:
            lo = int(m.group(2))
            hi = int(m.group(3)) if m.group(3) else lo
            perm.services.append(Service(m.group(1), lo, hi))
            continue
        # A custom application defined elsewhere in the config
        if app in app_proto:
            for lo, hi in _port_ranges(app_port.get(app, "")):
                perm.services.append(Service(app_proto[app], lo, hi))
            continue
        perm.unresolved.append(app)


# Check Point: objects first, then the access-rule referencing them by name.
_CP_HOST = re.compile(r'add\s+host\s+name\s+"?([^"\s]+)"?\s+ip-address\s+"?([^"\s]+)"?')
_CP_NET = re.compile(
    r'add\s+network\s+name\s+"?([^"\s]+)"?\s+subnet\s+"?([^"\s]+)"?\s+mask-length\s+"?(\d+)"?')
_CP_SVC = re.compile(r'add\s+service-(tcp|udp)\s+name\s+"?([^"\s]+)"?\s+port\s+"?([^"\s]+)"?')
_CP_RULE = re.compile(r'add[-\s]access-rule\b(.*)')
_CP_NAME = re.compile(r'(?:--name|\bname)\s+"?([^"\s]+)')
_CP_INDEXED = re.compile(r'\b(source|destination|service)(?:\.\d+)?\s+"?([^"\s]+)')
_CP_ACTION = re.compile(r'\baction\s+"?([^"\s]+)')


def _parse_checkpoint(text: str) -> dict | None:
    hosts: dict[str, str] = {}
    nets: dict[str, str] = {}
    svcs: dict[str, tuple[str, str]] = {}
    rules: dict[str, Permission] = {}
    saw_rule = False

    for line in text.splitlines():
        m = _CP_HOST.search(line)
        if m:
            hosts[m.group(1)] = m.group(2)
        m = _CP_NET.search(line)
        if m:
            nets[m.group(1)] = f"{m.group(2)}/{m.group(3)}"
        m = _CP_SVC.search(line)
        if m:
            svcs[m.group(2)] = (m.group(1), m.group(3))
        rm = _CP_RULE.search(line)
        if rm:
            saw_rule = True
            body = rm.group(1)
            nm = _CP_NAME.search(body)
            name = nm.group(1) if nm else f"rule@{len(rules)}"
            perm = Permission()
            am = _CP_ACTION.search(body)
            if am:
                perm.action = "permit" if am.group(1).lower() in ("accept", "allow") else "deny"
            for kind, val in _CP_INDEXED.findall(body):
                _resolve_checkpoint_ref(perm, kind, val, hosts, nets, svcs)
            rules[name] = perm

    if not saw_rule:
        return None
    return rules


def _resolve_checkpoint_ref(perm, kind, val, hosts, nets, svcs):
    if val.lower() in ("any", "any_"):
        if kind == "source":
            perm.src_any = True
        elif kind == "destination":
            perm.dst_any = True
        else:
            perm.svc_any = True
        return
    if kind in ("source", "destination"):
        cidr = hosts.get(val)
        if cidr is not None and "/" not in cidr:
            cidr += "/32" if ":" not in cidr else "/128"
        cidr = cidr or nets.get(val)
        if cidr is None:
            perm.unresolved.append(val)
            return
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            perm.unresolved.append(val)
            return
        (perm.sources if kind == "source" else perm.destinations).append(net)
    else:  # service
        if val in svcs:
            proto, port = svcs[val]
            for lo, hi in _port_ranges(port):
                perm.services.append(Service(proto, lo, hi))
        else:
            perm.unresolved.append(val)
