"""Cisco ACI: EPG-based, aggregating contract export.

Idiomatic mapping instead of "one contract per rule":
  - addresses are resolved to EPGs through AddressEpgMap (exact match or the most
    specific containing network); source -> consumer, destination -> provider;
    ip='any' -> vzAny.
  - all rules of a (consumer EPG, provider EPG) pair are merged into ONE contract
    (con-<consumer>-to-<provider>) with one subject per filter.
  - filters are reused from the service object catalogue (flt-<object name>),
    otherwise named generically (flt-tcp-443) and deduplicated across all contracts.
  - if the bridge domain of the provider EPG carries a PBR gateway, the subject
    references its service graph template.
  - the SR IDs are preserved in the subject descriptions (drift comparison).
Rules without an EPG mapping are exported as an individual contract (fallback) and
reported in the warnings.
"""
import json

import yaml

from ..models import AciGateway, AddressEpgMap, Rule, ServiceObject
from ..validation import parse_network
from .common import sanitize_name, service_ports, split_protocols

DEFAULT_TENANT = "Permitra"


# --- EPG resolution -----------------------------------------------------------

def resolve_epg(ip: str, mappings: list[AddressEpgMap]):
    """Returns an Epg, "vzAny" or None (no mapping)."""
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
        if (net == mapped or net.subnet_of(mapped)) and mapped.prefixlen > best_prefix:
            best, best_prefix = mapping.epg, mapped.prefixlen
    return best


def _epgs_for(entries: list, mappings) -> tuple[set, bool]:
    """(resolved EPGs, everything resolvable?)"""
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


# --- Model assembly -----------------------------------------------------------

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
        providers = {p for p in providers if p != "vzAny"}  # vzAny as provider makes no sense
        if not src_ok or not dst_ok or not consumers or not providers:
            legacy.append(rule)
            warnings.append(
                f"{rule.rule_id}: addresses without an EPG mapping – exported as a single contract"
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


# --- Legacy fallback (rule without EPG mapping) -------------------------------

def _legacy_tree(rule: Rule) -> list[dict]:
    flt_name = sanitize_name(f"flt-{rule.rule_id}")
    entries = []
    for svc in rule.services or []:
        entries.extend(_filter_entries_for_service(svc))
    return [
        {"vzFilter": {"attributes": {"name": flt_name, "descr": (rule.justification or "")[:128]},
                      "children": [{"vzEntry": {"attributes": e}} for e in entries]}},
        {"vzBrCP": {"attributes": {"name": sanitize_name(f"con-{rule.rule_id}"), "scope": "context",
                                   "descr": f"{rule.rule_id} | no EPG mapping"[:128]},
                    "children": [{"vzSubj": {"attributes": {"name": f"subj-{sanitize_name(rule.rule_id)}",
                                                            "revFltPorts": "yes"},
                                             "children": [{"vzRsSubjFiltAtt": {"attributes": {"tnVzFilterName": flt_name}}}]}}]}},
    ]


# --- Exports ------------------------------------------------------------------

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
                        "descr": ("Rules: " + ", ".join(sorted(rule_ids)))[:128],
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

    # EPG bindings per application profile (fvAp > fvAEPg > fvRsProv/fvRsCons)
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
    """Aggregated, human-readable view (e.g. for review or Ansible)."""
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
        "legacy_rules_without_epg": [r.rule_id for r in model["legacy"]],
        "warnings": model["warnings"],
    }
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
