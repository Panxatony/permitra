"""Generic exports: CSV (Excel-compatible, columns as in the communication matrix) and JSON."""
import csv
import io
import json

from ..models import Rule
from ..validation import format_entry
from .common import csv_safe

CSV_COLUMNS = [
    "Rule-ID", "Application", "APP-ID", "Platform", "Components", "Source SZ",
    "Source system", "Destination-SZ", "Destination system", "Protocol", "Port",
    "Justification", "Requestor", "Owner", "Implementation status", "Status",
    "Change-ID", "Last change", "Info", "Business context",
]

PLATFORM_LABELS = {"juniper": "Juniper", "checkpoint": "Check Point", "aci": "ACI"}


def rule_to_dict(rule: Rule, with_meta: bool = True) -> dict:
    data = {
        "rule_id": rule.rule_id,
        "name": rule.name,
        "application": rule.application,
        "app_id": rule.app_id,
        "vrf": rule.vrf.name if rule.vrf else None,
        "components": [c.name for c in rule.components],
        "platforms": rule.platforms,
        "source_zone": rule.source_zone,
        "destination_zone": rule.destination_zone,
        "source": rule.source,
        "destination": rule.destination,
        "services": rule.services,
        "action": rule.action.value,
        "status": rule.status.value,
        "impl_status": rule.impl_status,
    }
    if with_meta:
        data.update(
            {
                "description": rule.description,
                "justification": rule.justification,
                "business_context": rule.business_context,
                "info": rule.info,
                "requestor": rule.requestor,
                "owner": rule.owner,
                "change_id": rule.change_id,
                "valid_from": rule.valid_from,
                "valid_until": rule.valid_until,
                "version": rule.version,
                "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
            }
        )
    return data


def export_json(rules: list[Rule]) -> str:
    return json.dumps([rule_to_dict(r) for r in rules], indent=2, ensure_ascii=False)


def export_csv(rules: list[Rule]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";")
    writer.writerow(CSV_COLUMNS)
    for r in rules:
        writer.writerow([csv_safe(c) for c in
            [
                r.rule_id,
                r.application,
                r.app_id,
                "/".join(PLATFORM_LABELS.get(p, p) for p in r.platforms),
                " | ".join(c.name for c in r.components),
                r.source_zone,
                " | ".join(format_entry(e) for e in r.source or []),
                r.destination_zone,
                " | ".join(format_entry(e) for e in r.destination or []),
                " | ".join(s.get("protocol", "") for s in r.services),
                " | ".join(s.get("port", "") for s in r.services),
                r.justification,
                r.requestor,
                r.owner,
                " | ".join(f"{k}: {v}" for k, v in (r.impl_status or {}).items()),
                r.status.value,
                r.change_id,
                r.updated_at.date().isoformat() if r.updated_at else "",
                r.info,
                r.business_context,
            ]])
    return buf.getvalue()
