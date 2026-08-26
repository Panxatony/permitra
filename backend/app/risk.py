"""Risk analysis for security rules (issue #10, BSI compliance checks).

Assesses a rule against typical risk patterns – non-blocking, purely advisory.
The overall severity results from the pattern combined with the protection level
of the destination zone (simple risk matrix: the higher the protection level of
the destination, the heavier a risky pattern weighs)."""
from __future__ import annotations

import ipaddress

from sqlalchemy.orm import Session

from .messages import _
from .models import RuleLogging
from .zone_check import find_zone

# Seed for the risky-service list. The list itself lives in the database
# (models.RiskyPort) so administrators can adapt it: what counts as risky
# differs per organisation - Telnet on an isolated segment may be deliberate,
# while SSH from the outside may well deserve a hint. These defaults are what
# an installation starts with.
DEFAULT_RISKY_PORTS = {
    "23": "Telnet (unencrypted)",
    "21": "FTP (unencrypted)",
    "3389": "RDP (remote access)",
    "445": "SMB (file sharing)",
    "139": "NetBIOS",
    "135": "MS-RPC",
    "3306": "MySQL (direct DB access)",
    "5432": "PostgreSQL (direct DB access)",
    "1433": "MSSQL (direct DB access)",
    "1521": "Oracle (direct DB access)",
    "5900": "VNC (remote access)",
    "6379": "Redis",
    "9200": "Elasticsearch",
    "2049": "NFS",
    "161": "SNMP",
    "512": "rexec", "513": "rlogin", "514": "rsh",
}

# Source zones considered "untrusted"/exposed (origin of risky access)
UNTRUSTED_PAP = {"external"}

# A source or destination network at least this wide counts as too broad.
# /8 covers 16.7 million addresses - beyond any plausible "the servers".
BROAD_PREFIX_MAX = 8

_SEV_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}
_SB_WEIGHT = {"normal": 0, "high": 1, "very high": 2}


def _bump(sev: str, protection_level: str) -> str:
    """Raise the severity according to the destination zone's protection level (risk matrix)."""
    level = min(3, _SEV_ORDER[sev] + _SB_WEIGHT.get(protection_level, 0))
    return next(k for k, v in _SEV_ORDER.items() if v == level)


def _segments(port_spec: str) -> list[tuple[int, int]]:
    """Splits a port specification into numeric ranges.

    Allowed are single ports ("443"), ranges ("20-25") and lists of those
    ("22,8000-8080"). Non-numeric specifications such as "any" yield nothing –
    they are assessed elsewhere."""
    ranges: list[tuple[int, int]] = []
    for part in (port_spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo_s, hi_s = part.split("-", 1)
                lo, hi = int(lo_s.strip()), int(hi_s.strip())
                if lo > hi:            # tolerate a reversed range
                    lo, hi = hi, lo
            else:
                lo = hi = int(part)
        except ValueError:
            continue                   # "any", "http" etc. – not evaluable here
        ranges.append((lo, hi))
    return ranges


def configured_risky_ports(db: Session) -> dict[str, str]:
    """The risky-service list of this installation (port -> label).

    Falls back to the defaults while the table is still empty, so a risk
    assessment never silently loses its criteria."""
    from .models import RiskyPort

    rows = db.query(RiskyPort).order_by(RiskyPort.port).all()
    return {r.port: r.label for r in rows} if rows else dict(DEFAULT_RISKY_PORTS)


def risky_ports_in(port_spec: str, ports: dict[str, str] | None = None) -> list[tuple[str, str]]:
    """All risky ports covered by a port specification – as (port, label).

    Essential for ranges and lists: "20-25" contains FTP (21) and Telnet (23),
    "22,23" contains Telnet. Previously only exact single ports were checked, so
    precisely the broadly scoped rules – the ones that should stand out most –
    produced no warning at all."""
    ranges = _segments(port_spec)
    if not ranges:
        return []
    catalogue = DEFAULT_RISKY_PORTS if ports is None else ports
    hits = [
        (port, label) for port, label in catalogue.items()
        if any(lo <= int(port) <= hi for lo, hi in ranges)
    ]
    return sorted(hits, key=lambda t: int(t[0]))


def _is_any(entries) -> bool:
    return any((e.get("ip") or "").strip().lower() == "any" for e in entries or [])


def _broadest_prefix(entries):
    """Smallest prefix length (broadest network) of the entries; None for 'any'/empty."""
    best = None
    for e in entries or []:
        ip = (e.get("ip") or "").strip()
        if not ip or ip.lower() == "any":
            continue
        try:
            net = ipaddress.ip_network(ip, strict=False)
        except ValueError:
            continue
        if best is None or net.prefixlen < best:
            best = net.prefixlen
    return best


def assess_rule(db: Session, rule) -> dict:
    """Returns {level, findings:[{severity, code, detail}]} for a rule."""
    findings: list[dict] = []
    dst_zone = find_zone(db, rule.destination_zone or "")
    protection_level = dst_zone.protection_level if dst_zone else "normal"

    src_any = _is_any(rule.source)
    dst_any = _is_any(rule.destination)

    # 1) Any-to-Any
    #
    # A ping baseline is any-to-any deliberately and was granted on exactly that
    # basis: internal zones, a relation the matrix already allows, ICMP echo and
    # nothing else (app/ping_baseline.py). Reporting it as "too broad" would say
    # the assessment does not know what the approver decided - and a criterion
    # that fires on every rule of a kind is one reviewers learn to skip past,
    # which costs the findings around it their weight. It is still named, at the
    # severity its breadth is worth, because a standing rule nobody sees is how
    # one outlives its reason.
    if getattr(rule, "ping_baseline", False):
        findings.append({"severity": "low", "code": "ping-baseline",
                         "detail": _("Ping baseline: every address in {from_zone} may ping "
                                     "every address in {to_zone}, ICMP echo only",
                                     from_zone=rule.source_zone or "?",
                                     to_zone=rule.destination_zone or "?")})
    elif src_any and dst_any:
        findings.append({"severity": "high", "code": "any-to-any",
                         "detail": _("Source and destination are both 'any' – the rule is too broad")})
    elif src_any:
        findings.append({"severity": _bump("medium", protection_level), "code": "any-source",
                         "detail": _("Source is 'any' – every address may connect")})

    # 2) Very broad networks (<= /8)
    for label, entries in ((_("Source"), rule.source), (_("Destination"), rule.destination)):
        pfx = _broadest_prefix(entries)
        if pfx is not None and pfx <= BROAD_PREFIX_MAX:
            findings.append({"severity": "medium", "code": "broad-network",
                             "detail": _("{label} contains a very broad network (/{pfx})",
                                         label=label, pfx=pfx)})

    # 3) Risky services – weighted higher when coming from an exposed source zone
    risky_ports = configured_risky_ports(db)
    src_zone = find_zone(db, rule.source_zone or "")
    exposed = src_any or (src_zone and src_zone.pap_level in UNTRUSTED_PAP)
    for svc in rule.services or []:
        port = (svc.get("port") or "").strip()
        for hit_port, label in risky_ports_in(port, risky_ports):
            base = "high" if exposed else "medium"
            # For ranges/lists name the concrete match, otherwise the reviewer
            # searches "20-25" in vain for the actual problem.
            where = (_("Port {hit_port} in {port}", hit_port=hit_port, port=port)
                     if hit_port != port else _("Port {port}", port=port))
            findings.append({"severity": _bump(base, protection_level), "code": "risky-service",
                             "detail": _("Risky service {label} ({where})",
                                         label=_(label), where=where)
                                       + (_(" from an exposed source") if exposed else "")})

    # 4) Service 'any' across zone boundaries
    cross = (rule.source_zone or "").upper() != (rule.destination_zone or "").upper()
    if cross and any((s.get("protocol") or "").strip().lower() in ("any", "ip")
                     for s in rule.services or []):
        findings.append({"severity": "medium", "code": "any-service",
                         "detail": _("Service 'any' on a cross-zone rule")})

    # 5) A rule into a protected zone that logs nothing (#37, BSI OPS.1.1.5).
    # "Are accesses into the zone with very high protection requirement logged?"
    # is the question that had no answer here. Only raised where the protection
    # level makes it one - logging every rule everywhere is a cost, and a
    # criterion that fires on everything is one nobody reads.
    if (rule.effective_log_level == RuleLogging.none
            and protection_level in ("high", "very high")):
        findings.append({
            "severity": _bump("medium", protection_level), "code": "no-logging",
            "detail": _("The rule logs nothing, into a zone with protection level "
                        "'{level}' – an access nobody recorded cannot be "
                        "reconstructed afterwards", level=_(protection_level))})

    level = "none"
    for f in findings:
        if _SEV_ORDER[f["severity"]] > _SEV_ORDER[level]:
            level = f["severity"]
    return {"level": level, "target_protection_level": protection_level, "findings": findings}
