"""Check Point: Export als Management-API-JSON und als mgmt_cli-Skript.

Das JSON entspricht den Payloads der Web-API (add-host / add-network /
add-service-tcp / add-access-rule), das Skript nutzt mgmt_cli in einer
Login-Session mit abschließendem publish.
"""
import json

from ..models import Rule
from .common import parse_address_entries, sanitize_name, service_ports, split_protocols

ACCESS_LAYER = "Network"


def _network_objects(rule: Rule) -> tuple[list[dict], list[str], list[str]]:
    """Liefert (Objekt-Definitionen, Quell-Namen, Ziel-Namen)."""
    objects, src_names, dst_names = [], [], []
    for field, names in (("source", src_names), ("destination", dst_names)):
        for obj in parse_address_entries(getattr(rule, field), "net"):
            if obj.is_any or not obj.cidr:
                names.append("Any")
                continue
            names.append(obj.name)
            ip, _, prefix = obj.cidr.partition("/")
            if prefix in ("32", "128"):
                objects.append({"type": "host", "name": obj.name, "ip-address": ip})
            else:
                objects.append(
                    {"type": "network", "name": obj.name, "subnet": ip, "mask-length": int(prefix)}
                )
    return objects, src_names, dst_names


def _service_objects(rule: Rule) -> tuple[list[dict], list[str]]:
    objects, names = [], []
    for svc in rule.services or []:
        for proto in split_protocols(svc.get("protocol", "")):
            if proto == "icmp":
                names.append("icmp-proto")
                continue
            ports = service_ports(svc.get("port", ""))
            if not ports:
                names.append("Any")
                continue
            for port in ports:
                name = f"{proto}_{port}"
                names.append(name)
                objects.append({"type": f"service-{proto}", "name": name, "port": port})
    return objects, names or ["Any"]


def rule_payload(rule: Rule) -> dict:
    """Payload für add-access-rule (Management API)."""
    _, src_names, dst_names = _network_objects(rule)
    _, svc_names = _service_objects(rule)
    return {
        "layer": ACCESS_LAYER,
        "position": "top",
        "name": f"{rule.rule_id} {rule.name}".strip(),
        "source": sorted(set(src_names)),
        "destination": sorted(set(dst_names)),
        "service": sorted(set(svc_names)),
        "action": "Accept" if rule.action.value == "permit" else "Drop",
        "track": {"type": "Log"},
        "comments": f"{rule.rule_id} | {rule.change_id} | {rule.justification}".strip(" |"),
    }


def export_api_json(rules: list[Rule]) -> str:
    """Management-API-kompatibles JSON: Objekte + Regeln."""
    all_objects, access_rules = [], []
    seen = set()
    for rule in rules:
        net_objs, _, _ = _network_objects(rule)
        svc_objs, _ = _service_objects(rule)
        for obj in net_objs + svc_objs:
            key = (obj["type"], obj["name"])
            if key not in seen:
                seen.add(key)
                all_objects.append(obj)
        access_rules.append(rule_payload(rule))
    return json.dumps(
        {"objects": all_objects, "access-rules": access_rules}, indent=2, ensure_ascii=False
    )


def export_cli(rules: list[Rule]) -> str:
    """mgmt_cli-Skript für die Umsetzung auf dem Management-Server."""
    lines = [
        "#!/bin/bash",
        "# Permitra Export – Check Point mgmt_cli",
        f"# Regeln: {', '.join(r.rule_id for r in rules)}",
        "set -e",
        'mgmt_cli login user "$CP_USER" password "$CP_PASSWORD" > session.txt',
        "",
    ]
    seen = set()
    for rule in rules:
        lines.append(f"# --- {rule.rule_id}: {rule.justification or rule.name} ---")
        net_objs, _, _ = _network_objects(rule)
        svc_objs, _ = _service_objects(rule)
        for obj in net_objs + svc_objs:
            key = (obj["type"], obj["name"])
            if key in seen:
                continue
            seen.add(key)
            if obj["type"] == "host":
                lines.append(
                    f"mgmt_cli add host name \"{obj['name']}\" ip-address \"{obj['ip-address']}\""
                    " -s session.txt --ignore-warnings true"
                )
            elif obj["type"] == "network":
                lines.append(
                    f"mgmt_cli add network name \"{obj['name']}\" subnet \"{obj['subnet']}\""
                    f" mask-length {obj['mask-length']} -s session.txt --ignore-warnings true"
                )
            else:
                proto = obj["type"].removeprefix("service-")
                lines.append(
                    f"mgmt_cli add service-{proto} name \"{obj['name']}\" port {obj['port']}"
                    " -s session.txt --ignore-warnings true"
                )
        payload = rule_payload(rule)

        def indexed(key: str, values: list[str]) -> str:
            return " ".join(f'{key}.{i} "{v}"' for i, v in enumerate(values, 1))

        lines.append(
            f'mgmt_cli add access-rule layer "{ACCESS_LAYER}" position top'
            f' name "{payload["name"]}"'
            f" {indexed('source', payload['source'])}"
            f" {indexed('destination', payload['destination'])}"
            f" {indexed('service', payload['service'])}"
            f' action "{payload["action"]}" -s session.txt'
        )
        lines.append("")
    lines += ["mgmt_cli publish -s session.txt", "mgmt_cli logout -s session.txt"]
    return "\n".join(lines) + "\n"
