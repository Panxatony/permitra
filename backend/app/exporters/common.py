"""Shared helpers for all exporters."""
import re
from dataclasses import dataclass

from ..validation import parse_network


@dataclass
class AddressObject:
    name: str        # object-safe name, e.g. "net-10-0-1-0-24" or "host-example-de"
    cidr: str | None  # "10.0.1.0/24" or None (any / hostname without an IP)
    raw: str         # original entry from the rule
    is_any: bool = False


def sanitize_name(text: str, max_len: int = 60) -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", text.strip()).strip("-.")
    return name[:max_len] or "obj"


def parse_address_entries(entries: list, prefix: str) -> list[AddressObject]:
    """Converts structured address entries [{"ip": ..., "alias": ...}] into named objects.

    Object name = alias (if set), otherwise generated from the IP/network.
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
            # Legacy data tolerance: unparsable entries become a named object without CIDR
            objects.append(AddressObject(name=sanitize_name(alias or ip), cidr=None, raw=raw))
            continue
        cidr = str(net)
        name = sanitize_name(alias) if alias else sanitize_name(f"{prefix}-{cidr.replace('/', '-')}")
        objects.append(AddressObject(name=name, cidr=cidr, raw=raw))
    return objects


def service_ports(port: str) -> list[str]:
    """Splits "22/80/443" or "8000-8080" into individual port specifications."""
    port = (port or "").strip().lower()
    if port in ("", "any") or port.startswith(("icmp", "ping")):
        return []
    return [p.strip() for p in re.split(r"[,/]", port) if p.strip()]


def split_protocols(protocol: str) -> list[str]:
    """"TCP/UDP" -> ["tcp", "udp"]; ICMP variants -> ["icmp"]."""
    proto = (protocol or "").strip().upper()
    if proto == "ANY":
        return ["tcp", "udp", "icmp"]
    if proto.startswith("ICMP"):
        return ["icmp"]
    return [p.lower() for p in proto.split("/") if p]


def csv_safe(value) -> str:
    """A cell that a spreadsheet cannot execute.

    Permitra's whole point is replacing the Excel matrix, so these CSVs are
    opened in Excel and LibreOffice - where a cell beginning =, +, -, @, or a
    tab/CR is parsed as a formula. A justification of
    =HYPERLINK("http://evil","ok") or a worse DDE payload becomes live on open,
    and the person opening it is an auditor who trusts the file. Prefixing a
    single quote is the CSV-injection defence OWASP recommends: the spreadsheet
    shows the text and runs nothing.
    """
    text = "" if value is None else str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text
