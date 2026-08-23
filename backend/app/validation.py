"""Plausibility checks for rule attributes.

Addresses: one entry per line. Allowed are
  - CIDR/IP (IPv4 or IPv6): 10.0.1.0/24, 2a0f:2687:9::/64, 10.40.72.5
  - hostname, optionally followed by an IP: "host.example.de - 10.40.72.5" or "host (10.40.72.5)"
  - "any" / "Internet"
"""
import ipaddress
import re

from .messages import _

PROTOCOLS = {"TCP", "UDP", "TCP/UDP", "UDP/TCP", "ICMP", "ICMPV6", "ICMP/ICMPV6", "ANY"}

HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
IP_IN_TEXT_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)|([0-9A-Fa-f:]+:[0-9A-Fa-f:]+(?:/\d{1,3})?)"
)


def parse_network(token: str):
    """Returns an ip_network if token is an IP/CIDR, otherwise None."""
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None


def extract_networks(entry: str) -> list:
    """Extracts all IP/CIDR values from an address entry (including 'host - 10.0.0.1')."""
    networks = []
    for match in IP_IN_TEXT_RE.finditer(entry):
        net = parse_network(match.group(0))
        if net:
            networks.append(net)
    return networks


def format_entry(entry: dict) -> str:
    """Display form of an address entry: "alias (ip)" or just "ip"."""
    ip = (entry.get("ip") or "").strip()
    alias = (entry.get("alias") or "").strip()
    return f"{alias} ({ip})" if alias else ip


def format_entries(entries: list) -> str:
    return "\n".join(format_entry(e) for e in entries or [])


def validate_ip_entry(ip: str) -> str:
    """Address entries are always an IP/network (IPv4/IPv6) or 'any'."""
    ip = ip.strip()
    if not ip:
        raise ValueError(_("IP or network is required"))
    if ip.lower() == "any":
        return "any"
    if parse_network(ip) is None:
        raise ValueError(_("'{ip}' is not a valid IP address or network (CIDR)", ip=ip))
    return ip


def validate_address_entry(entry: str, field: str) -> None:
    entry = entry.strip()
    if not entry:
        return
    if entry.lower() in ("any", "internet"):
        return
    if parse_network(entry):
        return
    if extract_networks(entry):
        # Entry contains at least one valid IP/CIDR (e.g. "host - 10.0.0.1"
        # or "10.40.114.0/23 - 2a0f:2687::/64")
        return
    # Plain hostname
    host_part = re.split(r"[\s(]", entry, maxsplit=1)[0].rstrip("-").strip()
    if HOSTNAME_RE.match(host_part):
        return
    raise ValueError(
        _("{field}: '{entry}' is neither a CIDR/IP nor a hostname nor 'any'",
          field=field, entry=entry)
    )


def validate_address_list(value: str, field: str) -> str:
    entries = [line.strip() for line in value.splitlines() if line.strip()]
    if not entries:
        raise ValueError(_("{field}: at least one entry is required", field=field))
    for entry in entries:
        validate_address_entry(entry, field)
    return "\n".join(entries)


def validate_port(port: str) -> None:
    port = port.strip().lower()
    if port in ("", "any", "ping", "ping/ping6", "icmp", "icmp/icmpv6", "icmp/icmp6"):
        return
    for part in re.split(r"[,/]", port):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _sep, hi = part.partition("-")
            if not (lo.isdigit() and hi.isdigit() and 1 <= int(lo) <= int(hi) <= 65535):
                raise ValueError(_("Invalid port range: '{part}'", part=part))
        elif part.isdigit():
            if not 1 <= int(part) <= 65535:
                raise ValueError(_("Port outside 1-65535: '{part}'", part=part))
        else:
            raise ValueError(_("Invalid port: '{part}'", part=part))


def validate_service(protocol: str, port: str) -> None:
    proto = protocol.strip().upper()
    if proto not in PROTOCOLS:
        raise ValueError(
            _("Invalid protocol '{protocol}'. Allowed: {allowed}",
              protocol=protocol, allowed=", ".join(sorted(PROTOCOLS)))
        )
    if proto.startswith("ICMP"):
        return  # ICMP has no ports
    if proto != "ANY" and not port.strip():
        raise ValueError(_("{proto} requires a port specification", proto=proto))
    validate_port(port)


def parse_ports(port: str) -> list[tuple[int, int]]:
    """Splits a port specification into (from, to) ranges. 'any'/empty => full range.

    Tolerant of legacy data such as "49152-65535 (High Ports)" – extra text is ignored.
    """
    port = port.strip().lower()
    if port in ("", "any") or port.startswith(("icmp", "ping")):
        return [(1, 65535)]
    ranges = []
    for part in re.split(r"[,/\n]", port):
        m = re.search(r"(\d{1,5})\s*-\s*(\d{1,5})", part)
        if m:
            ranges.append((int(m.group(1)), int(m.group(2))))
            continue
        m = re.search(r"\d{1,5}", part)
        if m:
            ranges.append((int(m.group(0)), int(m.group(0))))
    return ranges or [(1, 65535)]
