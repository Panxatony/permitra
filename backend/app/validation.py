"""Plausibilitätsprüfungen für Regel-Attribute.

Adressen: pro Zeile ein Eintrag. Erlaubt sind
  - CIDR/IP (IPv4 oder IPv6): 10.0.1.0/24, 2a0f:2687:9::/64, 10.40.72.5
  - Hostname, optional mit IP dahinter: "host.example.de - 10.40.72.5" oder "host (10.40.72.5)"
  - "any" / "Internet"
"""
import ipaddress
import re

PROTOCOLS = {"TCP", "UDP", "TCP/UDP", "UDP/TCP", "ICMP", "ICMPV6", "ICMP/ICMPV6", "ANY"}

HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
IP_IN_TEXT_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)|([0-9A-Fa-f:]+:[0-9A-Fa-f:]+(?:/\d{1,3})?)"
)


def parse_network(token: str):
    """Gibt ein ip_network zurück, wenn token eine IP/CIDR ist, sonst None."""
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None


def extract_networks(entry: str) -> list:
    """Extrahiert alle IP/CIDR-Angaben aus einem Adress-Eintrag (auch 'host - 10.0.0.1')."""
    networks = []
    for match in IP_IN_TEXT_RE.finditer(entry):
        net = parse_network(match.group(0))
        if net:
            networks.append(net)
    return networks


def format_entry(entry: dict) -> str:
    """Anzeigeform eines Adress-Eintrags: "alias (ip)" oder nur "ip"."""
    ip = (entry.get("ip") or "").strip()
    alias = (entry.get("alias") or "").strip()
    return f"{alias} ({ip})" if alias else ip


def format_entries(entries: list) -> str:
    return "\n".join(format_entry(e) for e in entries or [])


def validate_ip_entry(ip: str) -> str:
    """Adress-Einträge sind immer IP/Netz (IPv4/IPv6) oder 'any'."""
    ip = ip.strip()
    if not ip:
        raise ValueError("IP/Netz ist erforderlich")
    if ip.lower() == "any":
        return "any"
    if parse_network(ip) is None:
        raise ValueError(f"'{ip}' ist keine gültige IP-Adresse oder kein gültiges Netz (CIDR)")
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
        # Eintrag enthält mindestens eine gültige IP/CIDR (z.B. "host - 10.0.0.1"
        # oder "10.40.114.0/23 - 2a0f:2687::/64")
        return
    # Reiner Hostname
    host_part = re.split(r"[\s(]", entry, maxsplit=1)[0].rstrip("-").strip()
    if HOSTNAME_RE.match(host_part):
        return
    raise ValueError(
        f"{field}: '{entry}' ist weder CIDR/IP noch Hostname noch 'any'"
    )


def validate_address_list(value: str, field: str) -> str:
    entries = [line.strip() for line in value.splitlines() if line.strip()]
    if not entries:
        raise ValueError(f"{field}: mindestens ein Eintrag erforderlich")
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
            lo, _, hi = part.partition("-")
            if not (lo.isdigit() and hi.isdigit() and 1 <= int(lo) <= int(hi) <= 65535):
                raise ValueError(f"Ungültiger Port-Bereich: '{part}'")
        elif part.isdigit():
            if not 1 <= int(part) <= 65535:
                raise ValueError(f"Port außerhalb 1-65535: '{part}'")
        else:
            raise ValueError(f"Ungültiger Port: '{part}'")


def validate_service(protocol: str, port: str) -> None:
    proto = protocol.strip().upper()
    if proto not in PROTOCOLS:
        raise ValueError(
            f"Ungültiges Protokoll '{protocol}'. Erlaubt: {', '.join(sorted(PROTOCOLS))}"
        )
    if proto.startswith("ICMP"):
        return  # ICMP hat keine Ports
    if proto != "ANY" and not port.strip():
        raise ValueError(f"Für {proto} ist eine Port-Angabe erforderlich")
    validate_port(port)


def parse_ports(port: str) -> list[tuple[int, int]]:
    """Zerlegt eine Port-Angabe in (von, bis)-Bereiche. 'any'/leer => voller Bereich.

    Tolerant gegenüber Altdaten wie "49152-65535 (High Ports)" – Zusätze werden ignoriert.
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
