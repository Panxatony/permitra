"""Generates sample demo data: zones, zone matrix and about 100 security rules.

Usage:
    python seed_demo.py [--wipe]     # --wipe deletes existing rules/zones first

The data is deterministic (fixed random seed) and entirely fictitious:
IP networks from 10.10.0.0/16, hostnames under *.demo.local.
Architecture principle: firewalls between zones (Juniper/Check Point), ACI intra-zone only.
"""
import argparse
import random
from datetime import date, timedelta

from app.database import Base, SessionLocal, engine
from app.models import (
    IN_FORCE,
    AciGateway,
    AddressComponentMap,
    AddressEpgMap,
    AddressObject,
    AuditEvent,
    Comment,
    ComponentActualConfig,
    ComponentLink,
    ComponentType,
    Epg,
    Rule,
    RuleAction,
    RuleStatus,
    RuleVersion,
    SecurityComponent,
    ServiceObject,
    Setting,
    Vrf,
    Zone,
    ZoneNetwork,
    ZonePolicy,
    ZonePolicyChange,
    ZonePolicyType,
    utcnow,
)

random.seed(42)

# --- Zones (name, description, network) -------------------------------------
ZONES = [
    ("INET",      "Internet (extern)",                 None),
    ("DMZ-WEB",   "DMZ – öffentliche Web-Dienste",     "10.10.10.0/24"),
    ("VPN",       "VPN-Einwahl Mitarbeiter/Partner",   "10.10.20.0/24"),
    ("PROD-APP",  "Produktion – Applikationsserver",   "10.10.30.0/24"),
    ("PROD-DB",   "Produktion – Datenbanken",          "10.10.31.0/24"),
    ("TEST",      "Test/Abnahme",                      "10.10.40.0/24"),
    ("DEV",       "Entwicklung",                       "10.10.50.0/24"),
    ("CICD",      "Build- und Deployment-Systeme",     "10.10.60.0/24"),
    ("SHARED",    "Shared Services (DNS, NTP, Repo)",  "10.10.70.0/24"),
    ("MGMT",      "Administration/Jump-Hosts",         "10.10.80.0/24"),
    ("MON",       "Monitoring/Logging",                "10.10.90.0/24"),
    ("AUDIT",     "Audit/SIEM – zentrale Protokollierung", "10.10.95.0/24"),
]

# --- Allowed relationships (everything else: block) --------------------------
ALLOWED = {
    ("INET", "DMZ-WEB"),
    ("DMZ-WEB", "PROD-APP"),
    ("PROD-APP", "PROD-DB"),
    ("PROD-APP", "SHARED"),
    ("DMZ-WEB", "SHARED"),
    ("VPN", "MGMT"),
    ("VPN", "DEV"), ("VPN", "TEST"),
    ("TEST", "SHARED"), ("DEV", "SHARED"), ("CICD", "SHARED"), ("MGMT", "SHARED"),
    ("CICD", "DEV"), ("CICD", "TEST"), ("CICD", "PROD-APP"),
    ("MGMT", "PROD-APP"), ("MGMT", "PROD-DB"), ("MGMT", "DMZ-WEB"),
    ("MGMT", "TEST"), ("MGMT", "DEV"), ("MGMT", "CICD"), ("MGMT", "MON"),
    ("MON", "PROD-APP"), ("MON", "PROD-DB"), ("MON", "DMZ-WEB"), ("MON", "SHARED"),
    ("MON", "TEST"), ("MON", "DEV"), ("MON", "CICD"), ("MON", "MGMT"),
    ("MGMT", "AUDIT"), ("MON", "AUDIT"), ("AUDIT", "SHARED"),
}
TEMPORARY = {("VPN", "TEST")}  # example of a relationship allowed only temporarily

# --- Security components (firewall cluster, ACI fabric) ----------------------
# (name, type, location, mgmt, north-south tier [0=northbound/close to internet], description)
COMPONENTS = [
    ("FW-Cluster-FFM", ComponentType.checkpoint, "Zone FFM",
     "cpmgmt.ffm.demo.local - 10.10.80.20", 10,
     "Check Point Firewall-Cluster am Standort Frankfurt (Zone FFM)"),
    ("FW-Cluster-BER", ComponentType.juniper, "Zone BER",
     "srx.ber.demo.local - 10.10.80.21", 10,
     "Juniper SRX Firewall-Cluster am Standort Berlin (Zone BER)"),
    ("FW-Cluster-FFM-DC", ComponentType.checkpoint, "Zone FFM",
     "cpmgmt-dc.ffm.demo.local - 10.10.80.22", 12,
     "Internes DC-Firewall-Cluster Frankfurt: Segmentierung Richtung Datenbanken/Monitoring "
     "(südlich des Perimeter-Clusters FFM)"),
    ("ACI-Fabric-FFM", ComponentType.aci, "Zone FFM",
     "apic.ffm.demo.local - 10.10.80.30", 30,
     "Cisco ACI Fabric für Intra-Zonen-Contracts (Zone FFM), südlich des FW-Clusters FFM"),
    ("FW-Cluster-Provider", ComponentType.juniper, "Extern (Provider)",
     "(Management beim Provider)", 0,
     "Firewall-Cluster des externen Providers – Internet-Übergang; Anbindung über FW-Cluster-BER"),
    ("FW-Cluster-Provider-2", ComponentType.juniper, "Extern (Provider 2)",
     "(Management beim Provider)", 0,
     "Zweiter Provider-Cluster – redundanter Übergang (u.a. VPN-Einwahl); Anbindung über FW-Cluster-BER"),
]

# --- Building blocks for rules -----------------------------------------------
PEOPLE = [
    ("Max Bauer", "mbauer"), ("Julia Klein", "jklein"), ("Deniz Yilmaz", "dyilmaz"),
    ("Sofia Ricci", "sricci"), ("Jonas Weber", "jweber"), ("Emma Fischer", "efischer"),
]
APPLICATIONS = ["Webshop", "Portal", "ERP", "Monitoring", "CI/CD", "Infrastruktur", "Backup"]
APP_IDS = {a: f"APP-{1000 + i}" for i, a in enumerate(["Webshop", "Portal", "ERP", "Monitoring", "CI/CD", "Infrastruktur", "Backup"])}
BUSINESS = ["Onlineshop", "Kundenportal", "Interne IT", "Monitoring", "Deployment", "Basisdienste"]

HOST_ROLES = {
    "DMZ-WEB": ["web", "lb", "proxy"], "PROD-APP": ["app", "api", "svc"],
    "PROD-DB": ["db", "pg", "mysql"], "TEST": ["tst", "qa"], "DEV": ["dev"],
    "CICD": ["ci", "runner", "registry"], "SHARED": ["dns", "ntp", "repo", "mail"],
    "MGMT": ["jump", "adm"], "MON": ["mon", "log", "graf"], "VPN": ["vpn"],
    "AUDIT": ["sim", "aud", "col"],
}

# Typical services per destination zone
SERVICES_BY_DEST = {
    "DMZ-WEB": [[("TCP", "443")], [("TCP", "80"), ("TCP", "443")]],
    "PROD-APP": [[("TCP", "443")], [("TCP", "8443")], [("TCP", "8080-8090")]],
    "PROD-DB": [[("TCP", "5432")], [("TCP", "3306")], [("TCP", "1521")]],
    "SHARED": [[("TCP/UDP", "53")], [("UDP", "123")], [("TCP", "443")], [("TCP", "25")]],
    "MGMT": [[("TCP", "22")], [("TCP", "3389")], [("TCP", "22"), ("TCP", "443")]],
    "MON": [[("TCP", "10051")], [("TCP", "514"), ("UDP", "514")]],
    "TEST": [[("TCP", "443")], [("TCP", "22")]],
    "DEV": [[("TCP", "443")], [("TCP", "22")]],
    "CICD": [[("TCP", "443")], [("TCP", "5000")]],
    "AUDIT": [[("TCP", "514"), ("UDP", "514")], [("TCP", "6514")], [("TCP", "443")]],
}
DEFAULT_SERVICES = [[("TCP", "443")], [("TCP", "22")], [("ICMP", "")], [("UDP", "161")]]

JUSTIFICATIONS = [
    "Zugriff {app} auf {dst_zone}", "Freischaltung für {app}", "Anbindung {app} an {dst_zone}",
    "Betriebszugriff für {app}", "Monitoring der Systeme in {dst_zone}", "Deployment über {app}",
]


def zone_net(zone: str) -> str | None:
    return next((net for name, _, net in ZONES if name == zone), None)


def make_host_entry(zone: str) -> dict:
    """Single IP with hostname alias, e.g. {"ip": "10.10.30.42", "alias": "app07.demo.local"}."""
    role = random.choice(HOST_ROLES.get(zone, ["srv"]))
    base = zone_net(zone).rsplit(".", 1)[0]
    idx = random.randint(1, 99)
    return {"ip": f"{base}.{random.randint(10, 240)}", "alias": f"{role}{idx:02d}.demo.local"}


def make_addresses(zone: str) -> list[dict]:
    """Address entries: always IP/network, alias = hostname or network name."""
    if zone == "INET":
        return [{"ip": "any", "alias": "Internet"}]
    kind = random.random()
    if kind < 0.35:  # entire zone network with network name
        return [{"ip": zone_net(zone), "alias": f"NET-{zone}"}]
    count = 1 if kind < 0.75 else random.randint(2, 4)
    return [make_host_entry(zone) for _ in range(count)]


def make_services(dst_zone: str) -> list[dict]:
    options = SERVICES_BY_DEST.get(dst_zone, DEFAULT_SERVICES)
    return [{"protocol": p, "port": port} for p, port in random.choice(options)]


def _promote_implemented_rules(db):
    """Moves rules the seed left approved-but-implemented to `active`.

    The seed writes impl_status straight onto the rule; the application never
    does. Going through the endpoint, confirming the last component promotes the
    rule to `active` - so the demo showed 63 approved rules of which 30 were
    implemented everywhere, and none active. The dashboard read "Approved 63 /
    Active 0" beside "To implement 33", which does not add up and should not,
    because it was a state the application itself cannot produce.

    Same condition and same version note as _sync_active_status, so the history
    reads like the workflow it is standing in for.
    """
    from app.routers.rules_router import fully_implemented

    for rule in db.query(Rule).filter(Rule.status == RuleStatus.approved).all():
        if not fully_implemented(rule):
            continue
        rule.status = RuleStatus.active
        rule.version += 1
        db.add(RuleVersion(
            rule_pk=rule.id, version=rule.version, snapshot={"seed": "demo"},
            change_note="Implemented on every component – the rule is active",
            changed_by="betrieb"))


def _seed_device_configs(db):
    """Gives the drift comparison something real to look at.

    The configuration is generated from the demo rules with the actual exporter,
    so it is what Permitra would have produced - and then two rules nobody
    documented are appended, because a device that matches the documentation
    perfectly is not what anybody's estate looks like and shows none of what the
    comparison is for.

    Uploaded twice, the clean version first: the coverage trend compares
    measurements, so a single upload leaves it with nothing to say.
    """
    from app.coverage import record_snapshot
    from app.exporters import checkpoint, juniper

    # Both platforms config_blocks can read. The ACI fabric is left without a
    # configuration on purpose: an estate where everything is measured is not
    # one anybody has, and the figure is only worth showing together with what
    # it does not cover.
    exporters = {ComponentType.juniper: juniper.export,
                 ComponentType.checkpoint: checkpoint.export_cli}
    firewalls = [c for c in db.query(SecurityComponent)
                 .order_by(SecurityComponent.name).all() if c.type in exporters]

    undocumented = {
        ComponentType.juniper: (
            "\n## opened by hand during an incident, never documented\n"
            "set security policies from-zone Z050-PROD to-zone Z090-EXT "
            "policy quickfix-payment match source-address any\n"
            "set security policies from-zone Z050-PROD to-zone Z090-EXT "
            "policy quickfix-payment then permit\n"
            "set security policies from-zone Z030-MGMT to-zone Z050-PROD "
            "policy vendor-support-temp match source-address any\n"
            "set security policies from-zone Z030-MGMT to-zone Z050-PROD "
            "policy vendor-support-temp then permit\n"
        ),
        ComponentType.checkpoint: (
            "\n# opened by hand during an incident, never documented\n"
            'mgmt_cli add-access-rule layer "Network" name "quickfix-payment" '
            'source "any" destination "h_payment" action "Accept"\n'
        ),
    }

    for index, component in enumerate(firewalls):
        rules = [r for r in db.query(Rule).all()
                 if component in r.components and r.status in IN_FORCE]
        if not rules:
            continue
        clean = exporters[component.type](rules[:25])

        # First measurement: everything on the device is accounted for.
        config = ComponentActualConfig(component_id=component.id, content=clean,
                                       uploaded_by="demo-seed")
        db.add(config)
        record_snapshot(db, component, clean, "demo-seed")

        # Second: on some of them, rules nobody documented have appeared since.
        # Others stay clean, so the per-component table shows both outcomes.
        content = clean + undocumented[component.type] if index % 2 == 0 else clean
        config.content = content
        record_snapshot(db, component, content, "demo-seed")


def _seed_emergency_change(db):
    """One emergency change still waiting for its approval after the fact.

    Without it the dashboard banner never appears and the demo shows nothing of
    what #36 is about - which is the half of the feature that matters, since the
    point is that an emergency change is impossible to overlook.
    """
    from datetime import timedelta

    rule = (db.query(Rule)
            .filter(Rule.status == RuleStatus.in_review)
            .order_by(Rule.id.desc()).first())
    if not rule:
        return
    declared = utcnow() - timedelta(hours=6)
    rule.emergency_declared_at = declared
    rule.emergency_declared_by = "betrieb"
    rule.emergency_reason = ("Zahlungs-Gateway ausgefallen (INC-4711), "
                             "Change Approver um 03:00 nicht erreichbar")
    rule.emergency_approval_due = declared + timedelta(hours=24)
    rule.version += 1
    db.add(RuleVersion(
        rule_pk=rule.id, version=rule.version, snapshot={"seed": "demo"},
        change_note="Emergency change declared: {reason}",
        change_values={"reason": rule.emergency_reason},
        changed_by="betrieb"))


def seed(wipe: bool):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    if wipe:
        # AuditEvent is part of the demo reset: the wipe discards the entire
        # rule history, otherwise old events would reference deleted rules
        # and the hash chain would carry remnants of the previous demo cycle (#26).
        for model in (AuditEvent, Setting, Comment, RuleVersion, Rule, ZonePolicyChange, ZonePolicy, ZoneNetwork, Zone, AciGateway,
                      AddressComponentMap, AddressEpgMap, Epg, AddressObject,
                      ServiceObject, ComponentLink, SecurityComponent, Vrf):
            db.query(model).delete()
        db.commit()

    # One environment for now; multi-environment/VRF scoping stays prepared
    # (a second environment, e.g. OT, can be added later via /api/vrfs)
    vrf_it = Vrf(name="IT", description="Default-Umgebung")
    db.add(vrf_it)
    db.flush()

    # Object catalog: reusable address and service objects
    db.add_all([
        AddressObject(name="jump01.demo.local", ip="10.10.80.10", description="Zentraler Jump-Host"),
        AddressObject(name="dns01.demo.local", ip="10.10.70.11", description="DNS-Resolver"),
        AddressObject(name="NET-VPN", ip="10.10.20.0/24", description="VPN-Einwahlnetz"),
        AddressObject(name="NET-PROD-APP", ip="10.10.30.0/24", description="Produktion Applikationsserver"),
    ])
    db.add_all([
        ServiceObject(name="HTTPS", protocol="TCP", port="443"),
        ServiceObject(name="SSH", protocol="TCP", port="22"),
        ServiceObject(name="DNS", protocol="TCP/UDP", port="53"),
        ServiceObject(name="Zabbix-Agent", protocol="TCP", port="10051"),
        ServiceObject(name="Ping", protocol="ICMP", port=""),
    ])

    # Security components
    components = {}
    for name, ctype, location, mgmt, tier, descr in COMPONENTS:
        component = SecurityComponent(name=name, type=ctype, location=location,
                                      mgmt_address=mgmt, ns_tier=tier, description=descr)
        db.add(component)
        components[name] = component
    db.flush()

    # Communication relationships of the components (topology documentation)
    fw_ffm_c, fw_ber_c, aci_c = (components[n] for n in
                                 ("FW-Cluster-FFM", "FW-Cluster-BER", "ACI-Fabric-FFM"))
    db.add_all([
        ComponentLink(
            component_a_id=min(aci_c.id, fw_ffm_c.id), component_b_id=max(aci_c.id, fw_ffm_c.id),
            link_type="PBR / Service Graph",
            description="Nord-Süd-Verkehr der Fabric läuft über den Check Point Cluster FFM",
        ),
        ComponentLink(
            component_a_id=min(fw_ffm_c.id, fw_ber_c.id), component_b_id=max(fw_ffm_c.id, fw_ber_c.id),
            link_type="OSPF Routing",
            description="Standort-Transit FFM–BER (Site-to-Site)",
        ),
        ComponentLink(
            component_a_id=min(fw_ffm_c.id, components["FW-Cluster-FFM-DC"].id),
            component_b_id=max(fw_ffm_c.id, components["FW-Cluster-FFM-DC"].id),
            link_type="OSPF Routing",
            description="Interner Standort-Transit FFM: Perimeter-Cluster ↔ DC-Cluster",
        ),
        ComponentLink(
            component_a_id=min(fw_ber_c.id, components["FW-Cluster-Provider"].id),
            component_b_id=max(fw_ber_c.id, components["FW-Cluster-Provider"].id),
            link_type="BGP Peering",
            description="Upstream-Anbindung an den externen Provider (Internet-Übergang)",
        ),
        ComponentLink(
            component_a_id=min(fw_ber_c.id, components["FW-Cluster-Provider-2"].id),
            component_b_id=max(fw_ber_c.id, components["FW-Cluster-Provider-2"].id),
            link_type="BGP Peering",
            description="Redundante Upstream-Anbindung an den zweiten Provider-Cluster",
        ),
    ])

    # ACI anycast gateways – PBR connection to the Check Point cluster (FFM)
    checkpoint_ffm = components["FW-Cluster-FFM"]
    gateways = [
        AciGateway(
            name="GW-PROD-APP", tenant="DEMO", vrf="VRF-PROD", bridge_domain="BD-PROD-APP",
            gateway_ip="10.10.30.1/24", zone_name="PROD-APP",
            pbr_enabled=True, pbr_component_id=checkpoint_ffm.id,
            pbr_node_ip="10.10.35.10", pbr_node_mac="00:50:56:AB:CD:01",
            pbr_service_graph="SG-CHKP-FFM", pbr_health_group="HG-CHKP-FFM",
            description="Anycast Gateway Produktion App; Nord-Süd-Verkehr per PBR über Check Point FFM",
        ),
        AciGateway(
            name="GW-PROD-DB", tenant="DEMO", vrf="VRF-PROD", bridge_domain="BD-PROD-DB",
            gateway_ip="10.10.31.1/24", zone_name="PROD-DB",
            pbr_enabled=True, pbr_component_id=components["FW-Cluster-FFM-DC"].id,
            pbr_node_ip="10.10.35.11", pbr_node_mac="00:50:56:AB:CD:02",
            pbr_service_graph="SG-CHKP-FFM-DC", pbr_health_group="HG-CHKP-FFM-DC",
            description="Anycast Gateway Produktion DB; Umleitung zur Inspektion über das DC-Cluster FFM",
        ),
        AciGateway(
            name="GW-SHARED", tenant="DEMO", vrf="VRF-SHARED", bridge_domain="BD-SHARED",
            gateway_ip="10.10.70.1/24", zone_name="SHARED",
            pbr_enabled=False,
            description="Anycast Gateway Shared Services; ohne PBR (nur Contracts)",
        ),
    ]
    db.add_all(gateways)

    # Zones + full matrix; BSI P-A-P classification:
    # extern = north of the P-A-P, pap = inside (DMZ/transfer), intern = below
    PAP_LEVELS = {"INET": "external", "DMZ-WEB": "pap", "VPN": "pap"}
    # BSI documentation per zone: owner + protection requirement (C, I, A)
    ZONE_META = {
        "INET":     ("",                    "normal", "normal", "normal"),
        "DMZ-WEB":  ("Team Web-Betrieb",    "high",   "high",   "high"),
        "VPN":      ("Team Netzwerk",       "high",   "high",   "high"),
        "PROD-APP": ("Team Applikationen",  "high",   "high",   "very high"),
        "PROD-DB":  ("Team Datenbanken",    "very high", "very high", "very high"),
        "TEST":     ("Team Applikationen",  "normal", "normal", "normal"),
        "DEV":      ("Team Entwicklung",    "normal", "normal", "normal"),
        "CICD":     ("Team Entwicklung",    "high",   "high",   "normal"),
        "SHARED":   ("Team Infrastruktur",  "normal", "high",   "high"),
        "MGMT":     ("Team Infrastruktur",  "very high", "very high", "high"),
        "MON":      ("Team Betrieb",        "high",   "high",   "high"),
        "AUDIT":    ("Team Security",       "very high", "very high", "high"),
    }
    zones = {}
    for order, (name, descr, _net) in enumerate(ZONES):
        owner, cia_c, cia_i, cia_a = ZONE_META.get(name, ("", "normal", "normal", "normal"))
        # Display identifier in steps of 10 (Z010, Z020, … – leaves gaps for insertions)
        zone = Zone(name=name, description=descr, sort_order=order,
                    code=f"Z{(order + 1) * 10:03d}",
                    pap_level=PAP_LEVELS.get(name, "internal"),
                    owner=owner, cia_c=cia_c, cia_i=cia_i, cia_a=cia_a)
        db.add(zone)
        zones[name] = zone
    db.flush()

    def zc(name):  # zone ID (leading identifier for rules)
        return zones[name].code

    # Network assignment: every network belongs to exactly one zone; "any" -> INET
    for name, _descr, net in ZONES:
        if net:
            db.add(ZoneNetwork(cidr=net, zone_id=zones[name].id, vrf_id=vrf_it.id, description=f"NET-{name}"))
    db.add(ZoneNetwork(cidr="any", zone_id=zones["INET"].id, vrf_id=vrf_it.id, description="Internet"))
    for a, _, _ in ZONES:
        for b, _, _ in ZONES:
            if a == b:
                continue
            db.add(
                ZonePolicy(
                    from_zone_id=zones[a].id, to_zone_id=zones[b].id,
                    policy=ZonePolicyType.allow_only if (a, b) in ALLOWED else ZonePolicyType.block_all,
                    temporary=(a, b) in TEMPORARY,
                )
            )

    # ~100 rules: 88 between allowed zones (FW), 12 intra-zone (ACI)
    pairs = sorted(ALLOWED)
    intra_zones = ["PROD-APP", "PROD-DB", "SHARED", "TEST", "DEV", "CICD"]
    plans = [random.choice(pairs) for _ in range(88)] + \
            [(z, z) for z in (intra_zones * 2)]  # 12 intra-zone rules

    statuses = (
        [RuleStatus.approved] * 60 + [RuleStatus.in_review] * 15 + [RuleStatus.draft] * 14
        + [RuleStatus.rejected] * 5 + [RuleStatus.deactivated] * 6
    )
    random.shuffle(statuses)

    start = date(2026, 1, 5)
    fw_ffm = components["FW-Cluster-FFM"]
    fw_ffm_dc = components["FW-Cluster-FFM-DC"]
    fw_ber = components["FW-Cluster-BER"]
    aci_ffm = components["ACI-Fabric-FFM"]

    # Address->component mapping: zone networks spread across the two clusters,
    # ACI fabric additionally for intra-zone contracts
    # DMZ hangs off the BER cluster: the internet path is consistently provider -> BER,
    # the FFM cluster only serves internal zones (no direct internet path)
    ZONE_FW = {
        "PROD-APP": fw_ffm, "SHARED": fw_ffm,
        "PROD-DB": fw_ffm_dc, "MON": fw_ffm_dc, "AUDIT": fw_ffm_dc,
        "DMZ-WEB": fw_ber, "VPN": fw_ber, "MGMT": fw_ber, "TEST": fw_ber, "DEV": fw_ber, "CICD": fw_ber,
    }
    NO_ACI_ZONES = {"MGMT", "AUDIT"}  # pure FW zones without ACI segmentation
    for zone_name, fw in ZONE_FW.items():
        ids = {fw.id} if zone_name in NO_ACI_ZONES else {fw.id, aci_ffm.id}
        db.add(
            AddressComponentMap(
                ip=zone_net(zone_name), alias=f"NET-{zone_name}", vrf_id=vrf_it.id,
                component_ids=sorted(ids), created_by="demo-seed",
            )
        )
        zones[zone_name].components = [fw]  # "Angebunden an" field: explicit firewall connection
    zones["INET"].components = [components["FW-Cluster-Provider"]]
    zones["DMZ-WEB"].components = [fw_ber, components["FW-Cluster-Provider"]]  # example: multiple connections
    # Shared services (DNS/NTP/repo) are reachable from both sites
    zones["SHARED"].components = [fw_ffm, fw_ber]
    # Administration/jump hosts reach all three site clusters
    zones["MGMT"].components = [fw_ber, fw_ffm, fw_ffm_dc]
    # Audit/SIEM collects from all internal firewall clusters
    zones["AUDIT"].components = [fw_ber, fw_ffm, fw_ffm_dc]
    # VPN dial-in terminates at both provider clusters (redundant), then via BER
    zones["VPN"].components = [fw_ber, components["FW-Cluster-Provider"],
                               components["FW-Cluster-Provider-2"]]
    # Internet ("any") reaches the environment via the provider cluster
    db.add(AddressComponentMap(
        ip="any", alias="Internet", vrf_id=vrf_it.id,
        component_ids=[components["FW-Cluster-Provider"].id], created_by="demo-seed",
    ))

    # ACI: EPG catalog + address->EPG mapping (basis of the contract export)
    ACI_ZONES = ["PROD-APP", "PROD-DB", "SHARED", "TEST", "DEV", "CICD"]
    epgs = {}
    for zone_name in ACI_ZONES:
        epg = Epg(
            name=f"epg-{zone_name.lower()}", tenant="DEMO", app_profile="AP-DEMO",
            bridge_domain=f"BD-{zone_name}", description=f"Endpoint Group Zone {zone_name}",
        )
        db.add(epg)
        epgs[zone_name] = epg
    # External EPG (L3Out) for north-south traffic from the MGMT network into the fabric
    l3out_mgmt = Epg(
        name="epg-l3out-mgmt", tenant="DEMO", app_profile="AP-DEMO",
        description="External EPG (L3Out) für Administration aus dem MGMT-Netz",
    )
    db.add(l3out_mgmt)
    db.flush()
    for zone_name in ACI_ZONES:
        db.add(AddressEpgMap(ip=zone_net(zone_name), alias=f"NET-{zone_name}", vrf_id=vrf_it.id,
                             epg_id=epgs[zone_name].id, created_by="demo-seed"))
    db.add(AddressEpgMap(ip=zone_net("MGMT"), alias="NET-MGMT", vrf_id=vrf_it.id,
                         epg_id=l3out_mgmt.id, created_by="demo-seed"))

    def resolve_seed_components(src_zone: str, dst_zone: str) -> list:
        if src_zone == dst_zone:
            return [aci_ffm]
        fws = {ZONE_FW[z].name: ZONE_FW[z] for z in (src_zone, dst_zone) if z in ZONE_FW}
        if src_zone == "INET" or dst_zone == "INET":
            # Internet traffic runs exclusively via provider -> BER; the FW cluster FFM
            # has no direct internet path (customer environment example)
            provider = components["FW-Cluster-Provider"]
            return sorted([provider, fw_ber], key=lambda c: c.name)
        return sorted(fws.values(), key=lambda c: c.name)

    for i, (src_zone, dst_zone) in enumerate(plans, start=1):
        rule_id = f"SR{i:05d}"
        intra = src_zone == dst_zone
        # Components as the automatic resolution would pick them: intra-zone -> ACI, otherwise FW cluster
        rule_components_list = resolve_seed_components(src_zone, dst_zone)
        app = random.choice(APPLICATIONS)
        requestor, owner = random.choice(PEOPLE), random.choice(PEOPLE)
        status = statuses[i - 1]
        created = start + timedelta(days=random.randint(0, 200))

        impl_status = {}
        if status == RuleStatus.approved:
            for c in rule_components_list:
                impl_status[c.name] = random.choice(["implemented", "implemented", "new"])
        elif status == RuleStatus.deactivated:
            impl_status = {c.name: "deactivated" for c in rule_components_list}

        justification = random.choice(JUSTIFICATIONS).format(app=app, dst_zone=dst_zone)
        rule = Rule(
            rule_id=rule_id,
            vrf_id=vrf_it.id,
            name=f"{app}-{dst_zone}-{i:03d}",
            application=app,
            app_id=APP_IDS.get(app, ""),
            components=rule_components_list,
            source_zone=zc(src_zone),
            destination_zone=zc(dst_zone),
            source=make_addresses(src_zone),
            destination=make_addresses(dst_zone),
            services=make_services(dst_zone),
            action=RuleAction.permit,
            description=f"{'Intra-Zonen-' if intra else ''}Freischaltung für {app}",
            justification=justification,
            business_context=random.choice(BUSINESS),
            requestor=requestor[0],
            owner=owner[1],
            change_id=f"CHN{2026000 + i}",
            valid_from=created.isoformat(),
            valid_until=(created + timedelta(days=365)).isoformat() if random.random() < 0.25 else None,
            status=status,
            impl_status=impl_status,
            created_by="demo-seed",
        )
        db.add(rule)
        db.flush()
        db.add(
            RuleVersion(
                rule_pk=rule.id, version=1,
                snapshot={"seed": "demo"}, change_note="Demo rule created",
                changed_by="demo-seed",
            )
        )
        if status in (RuleStatus.in_review, RuleStatus.rejected):
            db.add(
                Comment(
                    rule_pk=rule.id, author=owner[1],
                    text="Bitte Portfreigabe und Gültigkeitszeitraum prüfen."
                    if status == RuleStatus.in_review
                    else "Abgelehnt: Quelle zu breit gefasst, bitte auf Einzelhosts einschränken.",
                )
            )

    # Two deliberate conflict examples (overlap) for testing the warnings
    for rid, src, src_alias in (
        ("SR00101", "10.10.20.0/24", "NET-VPN"),
        ("SR00102", "10.10.20.128/25", "NET-VPN-B"),
    ):
        rule = Rule(
            rule_id=rid,
            vrf_id=vrf_it.id, name=f"Konflikt-Demo-{rid}", application="Portal",
            components=[fw_ber], source_zone=zc("VPN"), destination_zone=zc("MGMT"),
            source=[{"ip": src, "alias": src_alias}],
            destination=[{"ip": "10.10.80.10", "alias": "jump01.demo.local"}],
            services=[{"protocol": "TCP", "port": "22"}], action=RuleAction.permit,
            justification="Demo: absichtlich überlappende Regel für Konflikt-Warnung",
            requestor="Max Bauer", owner="mbauer", change_id="CHN2026999",
            status=RuleStatus.approved, impl_status={fw_ber.name: "implemented"},
            created_by="demo-seed",
        )
        db.add(rule)
        db.flush()
        db.add(RuleVersion(rule_pk=rule.id, version=1, snapshot={"seed": "demo"},
                           change_note="Demo rule created", changed_by="demo-seed"))

    # Demo rule spanning all three components: MGMT (behind FW BER) -> PROD-APP (FFM).
    # Implementation: firewall rule on both clusters (site transit) plus an
    # ACI contract, because the target segment enforces contracts (L3Out -> EPG).
    rule = Rule(
        rule_id="SR00103",
        vrf_id=vrf_it.id, name="Admin-Zugriff-PROD-APP", application="Infrastruktur",
        components=[components["FW-Cluster-BER"], components["FW-Cluster-FFM"],
                    components["ACI-Fabric-FFM"]],
        source_zone=zc("MGMT"), destination_zone=zc("PROD-APP"),
        source=[{"ip": "10.10.80.10", "alias": "jump01.demo.local"}],
        destination=[{"ip": "10.10.30.20", "alias": "app20.demo.local"}],
        services=[{"protocol": "TCP", "port": "8443"}], action=RuleAction.permit,
        description="Standortübergreifender Admin-Zugriff: Umsetzung auf allen drei Komponenten",
        justification="Administration der PROD-APP-Server vom zentralen Jump-Host (BER -> FFM, "
                      "Transit über beide FW-Cluster, ACI Contract im Ziel-Segment)",
        business_context="Interne IT", requestor="Max Bauer", owner="mbauer",
        change_id="CHN2027001", status=RuleStatus.approved,
        impl_status={"FW-Cluster-BER": "implemented", "FW-Cluster-FFM": "implemented",
                     "ACI-Fabric-FFM": "new"},
        created_by="demo-seed",
    )
    db.add(rule)
    db.flush()
    db.add(RuleVersion(rule_pk=rule.id, version=1, snapshot={"seed": "demo"},
                       change_note="Demo rule created", changed_by="demo-seed"))

    # Least privilege: the demo matrix is fully maintained -> enable default-deny
    # for unmaintained zone relationships (BSI recommendation, issue #13)
    from app.settings import set_setting

    set_setting(db, "zone_matrix_default", "deny")

    # The wipe clears the settings table, so anything not set here reverts to the
    # application default on every reset. The interface language is one: the demo
    # would come back up in English each night, while permitra.de, the
    # screenshots and the audience it is shown to are German.
    set_setting(db, "ui_language", "de")

    _promote_implemented_rules(db)
    _seed_device_configs(db)
    _seed_emergency_change(db)

    db.commit()
    rules_count = db.query(Rule).count()
    zone_count = db.query(Zone).count()
    policy_count = db.query(ZonePolicy).count()
    component_count = db.query(SecurityComponent).count()
    gateway_count = db.query(AciGateway).count()
    db.close()
    print(
        f"Demo data: {zone_count} zones, {policy_count} matrix entries, "
        f"{rules_count} rules, {component_count} security components, "
        f"{gateway_count} ACI Gateways."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--wipe", action="store_true", help="Delete existing rules and zones first")
    args = parser.parse_args()
    seed(args.wipe)
