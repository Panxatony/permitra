"""Cisco ACI: EPG-basierter, aggregierender Contract-Export.

Idiomatische Abbildung statt "ein Contract pro Regel":
  - Adressen werden über AddressEpgMap zu EPGs aufgelöst (exakt oder spezifischstes
    enthaltendes Netz); Quelle -> Consumer, Ziel -> Provider; ip='any' -> vzAny.
  - Alle Regeln eines (Consumer-EPG, Provider-EPG)-Paars werden zu EINEM Contract
    (con-<consumer>-to-<provider>) mit einem Subject je Filter zusammengefasst.
  - Filter werden aus dem Dienst-Objektkatalog wiederverwendet (flt-<objektname>),
    sonst generisch benannt (flt-tcp-443) und über alle Contracts dedupliziert.
  - Trägt die Bridge Domain des Provider-EPG ein PBR-Gateway, referenziert das
    Subject dessen Service-Graph-Template.
  - Die SR-IDs bleiben in den Subject-Beschreibungen erhalten (Drift-Abgleich).
Regeln ohne EPG-Zuordnung werden als Einzel-Contract exportiert (Fallback) und in
den Warnungen ausgewiesen.
"""
import json

import yaml

from ..models import AciGateway, AddressEpgMap, Epg, Rule, ServiceObject
from ..validation import parse_network
from .common import sanitize_name, service_ports, split_protocols

DEFAULT_TENANT = "Permitra"


# --- EPG-Auflösung -----------------------------------------------------------

def resolve_epg(ip: str, mappings: list[AddressEpgMap]):
    """Liefert Epg, "vzAny" oder None (keine Zuordnung)."""
    ip = (ip or "").strip()
    if not ip:
        return None
    if ip.lower() == "any":
        return "vzAny"
    net = parse_network(ip)
    if net is None:
        return None
    best, best_prefix = None, -1
    for mapping in mappings:
        if mapping.ip == "any":
            continue
        mapped = parse_network(mapping.ip)
        if not mapped or mapped.version != net.version:
            continue
        if net == mapped or net.subnet_of(mapped):
            if mapped.prefixlen > best_prefix:
                best, best_prefix = mapping.epg, mapped.prefixlen
    return best


def _epgs_for(entries: list, mappings) -> tuple[set, bool]:
    """(aufgelöste EPGs, alles auflösbar?)"""
    epgs, complete = set(), True
    for entry in entries or []:
        resolved = resolve_epg(entry.get("ip", ""), mappings)
        if resolved is None:
            complete = False
        else:
            epgs.add(resolved)
    return epgs, complete


# --- Filter ------------------------------------------------------------------

def _filter_entries_for_service(svc: dict) -> list[dict]:
    entries = []
    for proto in split_protocols(svc.get("protocol", "")):
        if proto == "icmp":
            entries.append({"name": "icmp", "etherT": "ip", "prot": "icmp"})
            continue
        ports = service_ports(svc.get("port", "")) or ["unspecified"]
        for port in ports:
            lo, _, hi = port.partition("-")
            entries.append(
                {
                    "name": sanitize_name(f"{proto}-{port}"),
                    "etherT": "ip",
                    "prot": proto,
                    "dFromPort": lo or "unspecified",
                    "dToPort": hi or lo or "unspecified",
                    "stateful": "yes" if proto == "tcp" else "no",
                }
            )
    return entries


def _filter_name(svc: dict, service_objects: list[ServiceObject]) -> str:
    proto = (svc.get("protocol") or "").upper()
    port = (svc.get("port") or "").strip().lower()
    for obj in service_objects:
        if obj.protocol.upper() == proto and (obj.port or "").strip().lower() == port:
            return sanitize_name(f"flt-{obj.name.lower()}")
    base = proto.lower().replace("/", "-")
    return sanitize_name(f"flt-{base}-{port}" if port else f"flt-{base}")


# --- Modellaufbau ------------------------------------------------------------

def build_contract_model(rules: list[Rule], db) -> dict:
    all_mappings = db.query(AddressEpgMap).all() if db else []
    mappings_by_vrf: dict = {}
    for m in all_mappings:
        mappings_by_vrf.setdefault(m.vrf_id, []).append(m)
    service_objects = db.query(ServiceObject).all() if db else []
    pbr_by_bd = {}
    if db:
        for gw in db.query(AciGateway).filter(AciGateway.pbr_enabled).all():
            if gw.bridge_domain and gw.pbr_service_graph:
                pbr_by_bd[gw.bridge_domain] = gw.pbr_service_graph

    filters: dict[str, list[dict]] = {}
    contracts: dict[tuple[str, str], dict] = {}
    legacy, warnings = [], []
    tenants = set()

    for rule in rules:
        mappings = mappings_by_vrf.get(getattr(rule, "vrf_id", None), [])
        consumers, src_ok = _epgs_for(rule.source, mappings)
        providers, dst_ok = _epgs_for(rule.destination, mappings)
        providers = {p for p in providers if p != "vzAny"}  # Provider vzAny ist nicht sinnvoll
        if not src_ok or not dst_ok or not consumers or not providers:
            legacy.append(rule)
            warnings.append(
                f"{rule.rule_id}: Adressen ohne EPG-Zuordnung – als Einzel-Contract exportiert"
            )
            continue

        rule_filters = {}
        for svc in rule.services or []:
            name = _filter_name(svc, service_objects)
            filters.setdefault(name, _filter_entries_for_service(svc))
            rule_filters[name] = True

        for consumer in consumers:
            for provider in providers:
                consumer_name = consumer if consumer == "vzAny" else consumer.name
                key = (consumer_name, provider.name)
                contract = contracts.setdefault(
                    key,
                    {
                        "name": sanitize_name(f"con-{consumer_name}-to-{provider.name}"),
                        "consumer": consumer_name,
                        "provider": provider.name,
                        "consumer_epg": None if consumer == "vzAny" else consumer,
                        "provider_epg": provider,
                        "scope": "context",
                        "subjects": {},  # filter_name -> set(rule_ids)
                        "service_graph": pbr_by_bd.get(provider.bridge_domain or ""),
                    },
                )
                for fname in rule_filters:
                    contract["subjects"].setdefault(fname, set()).add(rule.rule_id)
                tenants.add(provider.tenant or DEFAULT_TENANT)

    tenant = tenants.pop() if len(tenants) == 1 else DEFAULT_TENANT
    return {
        "tenant": tenant,
        "filters": filters,
        "contracts": list(contracts.values()),
        "legacy": legacy,
        "warnings": warnings,
    }


# --- Legacy-Fallback (Regel ohne EPG-Zuordnung) ------------------------------

def _legacy_tree(rule: Rule) -> list[dict]:
    flt_name = sanitize_name(f"flt-{rule.rule_id}")
    entries = []
    for svc in rule.services or []:
        entries.extend(_filter_entries_for_service(svc))
    return [
        {"vzFilter": {"attributes": {"name": flt_name, "descr": (rule.justification or "")[:128]},
                      "children": [{"vzEntry": {"attributes": e}} for e in entries]}},
        {"vzBrCP": {"attributes": {"name": sanitize_name(f"con-{rule.rule_id}"), "scope": "context",
                                   "descr": f"{rule.rule_id} | ohne EPG-Zuordnung"[:128]},
                    "children": [{"vzSubj": {"attributes": {"name": f"subj-{sanitize_name(rule.rule_id)}",
                                                            "revFltPorts": "yes"},
                                             "children": [{"vzRsSubjFiltAtt": {"attributes": {"tnVzFilterName": flt_name}}}]}}]}},
    ]


# --- Exporte -----------------------------------------------------------------

def export_json(rules: list[Rule], db=None) -> str:
    model = build_contract_model(rules, db)
    children = []

    for name, entries in sorted(model["filters"].items()):
        children.append(
            {"vzFilter": {"attributes": {"name": name},
                          "children": [{"vzEntry": {"attributes": e}} for e in entries]}}
        )

    epg_bindings: dict[tuple[str, str], dict] = {}  # (app_profile, epg) -> {"prov": set, "cons": set, "epg": Epg}
    for contract in model["contracts"]:
        subj_children = []
        for fname, rule_ids in sorted(contract["subjects"].items()):
            subj = {
                "vzSubj": {
                    "attributes": {
                        "name": sanitize_name(f"subj-{fname.removeprefix('flt-')}"),
                        "revFltPorts": "yes",
                        "descr": ("Regeln: " + ", ".join(sorted(rule_ids)))[:128],
                    },
                    "children": [{"vzRsSubjFiltAtt": {"attributes": {"tnVzFilterName": fname}}}],
                }
            }
            if contract["service_graph"]:
                subj["vzSubj"]["children"].append(
                    {"vzRsSubjGraphAtt": {"attributes": {"tnVnsAbsGraphName": contract["service_graph"]}}}
                )
            subj_children.append(subj)
        children.append(
            {"vzBrCP": {"attributes": {"name": contract["name"], "scope": contract["scope"],
                                       "descr": f"consumer={contract['consumer']} provider={contract['provider']}"[:128]},
                        "children": subj_children}}
        )
        for role, epg in (("cons", contract["consumer_epg"]), ("prov", contract["provider_epg"])):
            if epg is None:
                continue
            key = (epg.app_profile or "AP-Permitra", epg.name)
            binding = epg_bindings.setdefault(key, {"prov": set(), "cons": set(), "epg": epg})
            binding[role].add(contract["name"])

    # EPG-Bindings je Application Profile (fvAp > fvAEPg > fvRsProv/fvRsCons)
    by_ap: dict[str, list] = {}
    for (ap, _epg_name), binding in sorted(epg_bindings.items()):
        epg_children = [
            {"fvRsProv": {"attributes": {"tnVzBrCPName": c}}} for c in sorted(binding["prov"])
        ] + [
            {"fvRsCons": {"attributes": {"tnVzBrCPName": c}}} for c in sorted(binding["cons"])
        ]
        by_ap.setdefault(ap, []).append(
            {"fvAEPg": {"attributes": {"name": binding["epg"].name}, "children": epg_children}}
        )
    for ap, epgs in sorted(by_ap.items()):
        children.append({"fvAp": {"attributes": {"name": ap}, "children": epgs}})

    for rule in model["legacy"]:
        children.extend(_legacy_tree(rule))

    doc = {
        "fvTenant": {
            "attributes": {
                "name": model["tenant"],
                "descr": "Permitra Export",
                "annotation": f"permitra-warnings:{len(model['warnings'])}",
            },
            "children": children,
        }
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def export_yaml(rules: list[Rule], db=None) -> str:
    """Aggregierte, menschenlesbare Sicht (z.B. für Review oder Ansible)."""
    model = build_contract_model(rules, db)
    doc = {
        "tenant": model["tenant"],
        "filters": [
            {"name": name, "entries": entries} for name, entries in sorted(model["filters"].items())
        ],
        "contracts": [
            {
                "name": c["name"],
                "consumer": c["consumer"] + (" (alle EPGs im VRF)" if c["consumer"] == "vzAny" else ""),
                "provider": c["provider"],
                "scope": c["scope"],
                **({"service_graph": c["service_graph"]} if c["service_graph"] else {}),
                "subjects": [
                    {"filter": fname, "rules": sorted(rule_ids)}
                    for fname, rule_ids in sorted(c["subjects"].items())
                ],
            }
            for c in sorted(model["contracts"], key=lambda c: c["name"])
        ],
        "legacy_rules_ohne_epg": [r.rule_id for r in model["legacy"]],
        "warnings": model["warnings"],
    }
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
