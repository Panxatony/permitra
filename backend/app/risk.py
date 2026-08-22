"""Risikoanalyse für Sicherheitsregeln (Issue #10, BSI Compliance-Checks).

Bewertet eine Regel auf typische Risikomuster – nicht blockierend, nur als
Hinweis. Der Gesamtschweregrad ergibt sich aus dem Muster kombiniert mit dem
Schutzbedarf der Ziel-Zone (einfache Risikomatrix: je höher der Schutzbedarf
des Ziels, desto schwerer wiegt ein riskantes Muster)."""
from __future__ import annotations

import ipaddress

from sqlalchemy.orm import Session

from .zone_check import find_zone

# Riskante Dienste (Port -> Bezeichnung), v.a. aus unsicheren Zonen kritisch
RISKY_PORTS = {
    "23": "Telnet (unverschlüsselt)",
    "21": "FTP (unverschlüsselt)",
    "3389": "RDP (Fernzugriff)",
    "445": "SMB (Dateifreigabe)",
    "139": "NetBIOS",
    "135": "MS-RPC",
    "3306": "MySQL (DB direkt)",
    "5432": "PostgreSQL (DB direkt)",
    "1433": "MSSQL (DB direkt)",
    "1521": "Oracle (DB direkt)",
    "5900": "VNC (Fernzugriff)",
    "6379": "Redis",
    "9200": "Elasticsearch",
    "2049": "NFS",
    "161": "SNMP",
    "512": "rexec", "513": "rlogin", "514": "rsh",
}

# Als "unsicher"/exponiert geltende Quell-Zonen (Ausgangspunkt riskanter Zugriffe)
UNTRUSTED_PAP = {"extern"}

_SEV_ORDER = {"none": 0, "niedrig": 1, "mittel": 2, "hoch": 3}
_SB_WEIGHT = {"normal": 0, "hoch": 1, "sehr hoch": 2}


def _bump(sev: str, schutzbedarf: str) -> str:
    """Schweregrad nach Schutzbedarf der Ziel-Zone anheben (Risikomatrix)."""
    level = min(3, _SEV_ORDER[sev] + _SB_WEIGHT.get(schutzbedarf, 0))
    return [k for k, v in _SEV_ORDER.items() if v == level][0]


def _is_any(entries) -> bool:
    return any((e.get("ip") or "").strip().lower() == "any" for e in entries or [])


def _broadest_prefix(entries):
    """Kleinste Präfixlänge (breitestes Netz) der Einträge; None bei 'any'/leer."""
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
    """Liefert {level, findings:[{severity, code, detail}]} für eine Regel."""
    findings: list[dict] = []
    dst_zone = find_zone(db, rule.destination_zone or "")
    schutzbedarf = dst_zone.schutzbedarf if dst_zone else "normal"

    src_any = _is_any(rule.source)
    dst_any = _is_any(rule.destination)

    # 1) Any-to-Any
    if src_any and dst_any:
        findings.append({"severity": "hoch", "code": "any-to-any",
                         "detail": "Quelle und Ziel sind beide 'any' – zu breite Regel"})
    elif src_any:
        findings.append({"severity": _bump("mittel", schutzbedarf), "code": "any-source",
                         "detail": "Quelle ist 'any' – jede Adresse darf zugreifen"})

    # 2) Sehr breite Netze (<= /8)
    for label, entries in (("Quelle", rule.source), ("Ziel", rule.destination)):
        pfx = _broadest_prefix(entries)
        if pfx is not None and pfx <= 8:
            findings.append({"severity": "mittel", "code": "broad-network",
                             "detail": f"{label} enthält ein sehr breites Netz (/{pfx})"})

    # 3) Riskante Dienste – aus exponierter Quell-Zone schwerer gewichtet
    src_zone = find_zone(db, rule.source_zone or "")
    exposed = src_any or (src_zone and src_zone.pap_level in UNTRUSTED_PAP)
    for svc in rule.services or []:
        port = (svc.get("port") or "").strip()
        label = RISKY_PORTS.get(port)
        if not label and "-" not in port and "," not in port and port not in RISKY_PORTS:
            continue
        if label:
            base = "hoch" if exposed else "mittel"
            findings.append({"severity": _bump(base, schutzbedarf), "code": "risky-service",
                             "detail": f"Riskanter Dienst {label} (Port {port})"
                                       + (" aus exponierter Quelle" if exposed else "")})

    # 4) Dienst 'any' zonenübergreifend
    cross = (rule.source_zone or "").upper() != (rule.destination_zone or "").upper()
    if cross and any((s.get("protocol") or "").strip().lower() in ("any", "ip")
                     for s in rule.services or []):
        findings.append({"severity": "mittel", "code": "any-service",
                         "detail": "Dienst 'any' bei zonenübergreifender Regel"})

    level = "none"
    for f in findings:
        if _SEV_ORDER[f["severity"]] > _SEV_ORDER[level]:
            level = f["severity"]
    return {"level": level, "schutzbedarf_ziel": schutzbedarf, "findings": findings}
