"""BSI-compliant zone plan (sanitised network plan) as a Mermaid flowchart.

Generated entirely from the stored data (zones with protection level/owner,
firewall attachments, intra-zone ACI segmentation) and serves as an export for
audits, wikis and operations documentation (GitLab and many wikis render Mermaid
natively). BSI reference: NET.1.1 (network architecture/design, zoning following
the P-A-P model) and NET.3.2 (firewall as the zone transition)."""
from __future__ import annotations

import re

from sqlalchemy.orm import Session

from .models import Rule, RuleStatus, SecurityComponent, Zone, active_rules
from .zone_check import zone_ref

BAND_LABELS = {
    "external": "External (north) – internet / partners",
    "pap": "P-A-P layer (BSI): packet filter – ALG – packet filter",
    "internal": "Internal (south) – below the P-A-P structure",
}
SB_CLASS = {"normal": "sbNormal", "high": "sbHigh", "very high": "sbVeryhigh"}


def _node_id(name: str) -> str:
    return "Z_" + re.sub(r"[^A-Za-z0-9]", "_", name)


def _fw_id(name: str) -> str:
    return "FW_" + re.sub(r"[^A-Za-z0-9]", "_", name)


def build_mermaid(db: Session, generated_at: str = "") -> str:
    zones = db.query(Zone).order_by(Zone.sort_order, Zone.name).all()
    rules = active_rules(db).filter(Rule.status != RuleStatus.deactivated).all()

    # Intra-zone ACI segmentation per zone (as in the zone overview:
    # derived from the active rules of the zone)
    aci_by_zone: dict[str, set[str]] = {}
    for rule in rules:
        # ACI contracts count towards the rule's destination segment (provider EPG)
        if not rule.destination_zone:
            continue
        for component in rule.components:
            if component.type.value == "aci":
                aci_by_zone.setdefault((rule.destination_zone or '').upper(), set()).add(component.name)

    firewalls: dict[int, SecurityComponent] = {}
    for zone in zones:
        for component in zone.components:
            if component.type.value != "aci":
                firewalls[component.id] = component

    lines = [
        "%% Permitra zone plan (sanitised network plan) – generated automatically",
        "%% BSI IT-Grundschutz: NET.1.1 (zoning/P-A-P), NET.3.2 (firewall as the zone transition)",
    ]
    if generated_at:
        lines.append(f"%% Generated: {generated_at}")
    lines.append("flowchart TB")

    for level in ("external", "pap", "internal"):
        band_zones = [z for z in zones if (z.pap_level or "internal") == level]
        band_fws = list(firewalls.values()) if level == "pap" else []
        if not band_zones and not band_fws:
            continue
        lines.append(f'  subgraph BAND_{level}["{BAND_LABELS[level]}"]')
        if level == "pap":
            for fw in sorted(band_fws, key=lambda f: (f.ns_tier or 100, f.name)):
                label = f"{fw.name}<br/><i>{'Juniper SRX' if fw.type.value == 'juniper' else 'Check Point'}</i>"
                lines.append(f'    {_fw_id(fw.name)}{{{{"{label}"}}}}')
        for zone in band_zones:
            label = f"{zone.code}-{zone.name}" if zone.code else zone.name
            parts = [f"<b>{label}</b>", f"Protection level: {zone.protection_level}"]
            if zone.owner:
                parts.append(f"Owner: {zone.owner}")
            aci = sorted(aci_by_zone.get(zone_ref(zone).upper(), ()))
            if aci:
                parts.append(f"ACI intra-zone: {', '.join(aci)}")
            lines.append(f'    {_node_id(zone.name)}["{"<br/>".join(parts)}"]')
        lines.append("  end")

    # Edges: zone – firewall (a zone transition always passes through a firewall)
    for zone in zones:
        for component in zone.components:
            if component.type.value != "aci":
                lines.append(f"  {_node_id(zone.name)} --- {_fw_id(component.name)}")

    # Protection level colour coding (as in the Permitra user interface)
    lines += [
        "  classDef sbNormal fill:#eef1f6,stroke:#9aa7b8;",
        "  classDef sbHigh fill:#fff0d2,stroke:#cfa64e;",
        "  classDef sbVeryhigh fill:#fadddd,stroke:#cf7b7b;",
        "  classDef fw fill:#dbe9ff,stroke:#1c53b8,stroke-width:2px;",
    ]
    for zone in zones:
        lines.append(f"  class {_node_id(zone.name)} {SB_CLASS.get(zone.protection_level, 'sbNormal')};")
    for fw in firewalls.values():
        lines.append(f"  class {_fw_id(fw.name)} fw;")

    return "\n".join(lines) + "\n"
