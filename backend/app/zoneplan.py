"""BSI-konformer Zonenplan (bereinigter Netzplan) als Mermaid-Flowchart.

Wird vollständig aus den Bestandsdaten generiert (Zonen mit Schutzbedarf/
Verantwortlichem, Firewall-Anbindungen, intra-zonale ACI-Segmentierung) und
dient als Export für Audits, Wikis und Betriebsdoku (GitLab/viele Wikis
rendern Mermaid nativ). BSI-Bezug: NET.1.1 (Netzarchitektur/-design,
Zonierung nach P-A-P) und NET.3.2 (Firewall als Zonenübergang)."""
from __future__ import annotations

import re

from sqlalchemy.orm import Session

from .models import Rule, RuleStatus, SecurityComponent, Zone

BAND_LABELS = {
    "extern": "Extern (Nord) – Internet / Partner",
    "pap": "P-A-P-Ebene (BSI): Paketfilter – ALG – Paketfilter",
    "intern": "Intern (Süd) – unterhalb der P-A-P-Struktur",
}
SB_CLASS = {"normal": "sbNormal", "hoch": "sbHoch", "sehr hoch": "sbSehrhoch"}


def _node_id(name: str) -> str:
    return "Z_" + re.sub(r"[^A-Za-z0-9]", "_", name)


def _fw_id(name: str) -> str:
    return "FW_" + re.sub(r"[^A-Za-z0-9]", "_", name)


def build_mermaid(db: Session, generated_at: str = "") -> str:
    zones = db.query(Zone).order_by(Zone.sort_order, Zone.name).all()
    rules = db.query(Rule).filter(Rule.status != RuleStatus.deactivated).all()

    # Intra-zonale ACI-Segmentierung je Zone (wie in der Zonen-Übersicht:
    # abgeleitet aus den aktiven Regeln der Zone)
    aci_by_zone: dict[str, set[str]] = {}
    for rule in rules:
        # ACI-Contracts zählen für das Ziel-Segment (Provider-EPG) der Regel
        if not rule.destination_zone:
            continue
        for component in rule.components:
            if component.type.value == "aci":
                aci_by_zone.setdefault(rule.destination_zone.upper(), set()).add(component.name)

    firewalls: dict[int, SecurityComponent] = {}
    for zone in zones:
        for component in zone.components:
            if component.type.value != "aci":
                firewalls[component.id] = component

    lines = [
        "%% Permitra Zonenplan (bereinigter Netzplan) – automatisch generiert",
        "%% BSI IT-Grundschutz: NET.1.1 (Zonierung/P-A-P), NET.3.2 (Firewall als Zonenübergang)",
    ]
    if generated_at:
        lines.append(f"%% Stand: {generated_at}")
    lines.append("flowchart TB")

    for level in ("extern", "pap", "intern"):
        band_zones = [z for z in zones if (z.pap_level or "intern") == level]
        band_fws = [f for f in firewalls.values()] if level == "pap" else []
        if not band_zones and not band_fws:
            continue
        lines.append(f'  subgraph BAND_{level}["{BAND_LABELS[level]}"]')
        if level == "pap":
            for fw in sorted(band_fws, key=lambda f: (f.ns_tier or 100, f.name)):
                label = f"{fw.name}<br/><i>{'Juniper SRX' if fw.type.value == 'juniper' else 'Check Point'}</i>"
                lines.append(f'    {_fw_id(fw.name)}{{{{"{label}"}}}}')
        for zone in band_zones:
            parts = [f"<b>{zone.name}</b>", f"Schutzbedarf: {zone.schutzbedarf}"]
            if zone.owner:
                parts.append(f"Verantwortlich: {zone.owner}")
            aci = sorted(aci_by_zone.get(zone.name.upper(), ()))
            if aci:
                parts.append(f"ACI intra-zonal: {', '.join(aci)}")
            lines.append(f'    {_node_id(zone.name)}["{"<br/>".join(parts)}"]')
        lines.append("  end")

    # Kanten: Zone – Firewall (Zonenübergang erfolgt immer über eine Firewall)
    for zone in zones:
        for component in zone.components:
            if component.type.value != "aci":
                lines.append(f"  {_node_id(zone.name)} --- {_fw_id(component.name)}")

    # Schutzbedarf-Farbkodierung (wie in der Permitra-Oberfläche)
    lines += [
        "  classDef sbNormal fill:#eef1f6,stroke:#9aa7b8;",
        "  classDef sbHoch fill:#fff0d2,stroke:#cfa64e;",
        "  classDef sbSehrhoch fill:#fadddd,stroke:#cf7b7b;",
        "  classDef fw fill:#dbe9ff,stroke:#1c53b8,stroke-width:2px;",
    ]
    for zone in zones:
        lines.append(f"  class {_node_id(zone.name)} {SB_CLASS.get(zone.schutzbedarf, 'sbNormal')};")
    for fw in firewalls.values():
        lines.append(f"  class {_fw_id(fw.name)} fw;")

    return "\n".join(lines) + "\n"
