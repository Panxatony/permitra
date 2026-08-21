"""Gemeinsame Helfer für alle Exporter."""
import re
from dataclasses import dataclass

from ..validation import extract_networks, parse_network


@dataclass
class AddressObject:
    name: str        # objektfähiger Name, z.B. "net-10-0-1-0-24" oder "host-example-de"
    cidr: str | None  # "10.0.1.0/24" oder None (any / Hostname ohne IP)
    raw: str         # Original-Eintrag aus der Regel
    is_any: bool = False


def sanitize_name(text: str, max_len: int = 60) -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", text.strip()).strip("-.")
    return name[:max_len] or "obj"


def parse_address_entries(entries: list, prefix: str) -> list[AddressObject]:
    """Wandelt strukturierte Adress-Einträge [{"ip": ..., "alias": ...}] in benannte Objekte.

    Objektname = Alias (sofern gesetzt), sonst generiert aus der IP/dem Netz.
    """
    objects: list[AddressObject] = []
    for entry in entries or []:
        ip = (entry.get("ip") or "").strip()
        alias = (entry.get("alias") or "").strip()
        raw = f"{alias} ({ip})" if alias else ip
        if not ip:
            continue
        if ip.lower() == "any":
            objects.append(AddressObject(name="any", cidr=None, raw=raw, is_any=True))
            continue
        net = parse_network(ip)
        if net is None:
            # Altdaten-Toleranz: unparsebare Einträge als benanntes Objekt ohne CIDR
            objects.append(AddressObject(name=sanitize_name(alias or ip), cidr=None, raw=raw))
            continue
        cidr = str(net)
        name = sanitize_name(alias) if alias else sanitize_name(f"{prefix}-{cidr.replace('/', '-')}")
        objects.append(AddressObject(name=name, cidr=cidr, raw=raw))
    return objects


def service_ports(port: str) -> list[str]:
    """Zerlegt "22/80/443" oder "8000-8080" in einzelne Port-Angaben."""
    port = (port or "").strip().lower()
    if port in ("", "any") or port.startswith(("icmp", "ping")):
        return []
    return [p.strip() for p in re.split(r"[,/]", port) if p.strip()]


def split_protocols(protocol: str) -> list[str]:
    """"TCP/UDP" -> ["tcp", "udp"]; ICMP-Varianten -> ["icmp"]."""
    proto = (protocol or "").strip().upper()
    if proto == "ANY":
        return ["tcp", "udp", "icmp"]
    if proto.startswith("ICMP"):
        return ["icmp"]
    return [p.lower() for p in proto.split("/") if p]
