"""Erzeugt exemplarische Demo-Daten: Zonen, Zonen-Matrix und ca. 100 Sicherheitsregeln.

Aufruf:
    python seed_demo.py [--wipe]     # --wipe löscht vorhandene Regeln/Zonen zuerst

Die Daten sind deterministisch (fester Random-Seed) und komplett fiktiv:
IP-Netze aus 10.10.0.0/16, Hostnamen unter *.demo.local.
Architektur-Prinzip: zwischen Zonen Firewalls (Juniper/Check Point), ACI nur intra-zonal.
"""
import argparse
import random
from datetime import date, timedelta

from app.database import Base, SessionLocal, engine
from app.models import (
    AciGateway,
    AddressComponentMap,
    AddressEpgMap,
    AddressObject,
    Epg,
    Comment,
    ComponentLink,
    ComponentType,
    ServiceObject,
    Rule,
    RuleAction,
    RuleStatus,
    RuleVersion,
    SecurityComponent,
    Vrf,
    Zone,
    ZoneNetwork,
    ZonePolicy,
    ZonePolicyChange,
    ZonePolicyType,
)

random.seed(42)

# --- Zonen (Name, Beschreibung, Netz) ---------------------------------------
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
]

# --- Erlaubte Beziehungen (alles andere: Block) ------------------------------
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
}
TEMPORARY = {("VPN", "TEST")}  # Beispiel für eine nur temporär erlaubte Beziehung

# --- Sicherheitskomponenten (Firewall-Cluster, ACI-Fabric) -------------------
# (Name, Typ, Standort, Mgmt, Nord-Süd-Ebene [0=nördlich/Internet-nah], Beschreibung)
COMPONENTS = [
    ("FW-Cluster-FFM", ComponentType.checkpoint, "Zone FFM",
     "cpmgmt.ffm.demo.local - 10.10.80.20", 10,
     "Check Point Firewall-Cluster am Standort Frankfurt (Zone FFM)"),
    ("FW-Cluster-BER", ComponentType.juniper, "Zone BER",
     "srx.ber.demo.local - 10.10.80.21", 10,
     "Juniper SRX Firewall-Cluster am Standort Berlin (Zone BER)"),
    ("ACI-Fabric-FFM", ComponentType.aci, "Zone FFM",
     "apic.ffm.demo.local - 10.10.80.30", 30,
     "Cisco ACI Fabric für Intra-Zonen-Contracts (Zone FFM), südlich des FW-Clusters FFM"),
    ("FW-Cluster-Provider", ComponentType.juniper, "Extern (Provider)",
     "(Management beim Provider)", 0,
     "Firewall-Cluster des externen Providers – Internet-Übergang; Anbindung über FW-Cluster-BER"),
]

# --- Bausteine für Regeln ----------------------------------------------------
PEOPLE = [
    ("Max Bauer", "mbauer"), ("Julia Klein", "jklein"), ("Deniz Yilmaz", "dyilmaz"),
    ("Sofia Ricci", "sricci"), ("Jonas Weber", "jweber"), ("Emma Fischer", "efischer"),
]
APPLICATIONS = ["Webshop", "Portal", "ERP", "Monitoring", "CI/CD", "Infrastruktur", "Backup"]
BUSINESS = ["Onlineshop", "Kundenportal", "Interne IT", "Monitoring", "Deployment", "Basisdienste"]

HOST_ROLES = {
    "DMZ-WEB": ["web", "lb", "proxy"], "PROD-APP": ["app", "api", "svc"],
    "PROD-DB": ["db", "pg", "mysql"], "TEST": ["tst", "qa"], "DEV": ["dev"],
    "CICD": ["ci", "runner", "registry"], "SHARED": ["dns", "ntp", "repo", "mail"],
    "MGMT": ["jump", "adm"], "MON": ["mon", "log", "graf"], "VPN": ["vpn"],
}

# Typische Dienste je Zielzone
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
}
DEFAULT_SERVICES = [[("TCP", "443")], [("TCP", "22")], [("ICMP", "")], [("UDP", "161")]]

JUSTIFICATIONS = [
    "Zugriff {app} auf {dst_zone}", "Freischaltung für {app}", "Anbindung {app} an {dst_zone}",
    "Betriebszugriff für {app}", "Monitoring der Systeme in {dst_zone}", "Deployment über {app}",
]


def zone_net(zone: str) -> str | None:
    return next((net for name, _, net in ZONES if name == zone), None)


def make_host_entry(zone: str) -> dict:
    """Einzelne IP mit Hostnamen-Alias, z.B. {"ip": "10.10.30.42", "alias": "app07.demo.local"}."""
    role = random.choice(HOST_ROLES.get(zone, ["srv"]))
    base = zone_net(zone).rsplit(".", 1)[0]
    idx = random.randint(1, 99)
    return {"ip": f"{base}.{random.randint(10, 240)}", "alias": f"{role}{idx:02d}.demo.local"}


def make_addresses(zone: str) -> list[dict]:
    """Adress-Einträge: immer IP/Netz, Alias = Hostname bzw. Netzwerkname."""
    if zone == "INET":
        return [{"ip": "any", "alias": "Internet"}]
    kind = random.random()
    if kind < 0.35:  # ganzes Zonen-Netz mit Netzwerknamen
        return [{"ip": zone_net(zone), "alias": f"NET-{zone}"}]
    count = 1 if kind < 0.75 else random.randint(2, 4)
    return [make_host_entry(zone) for _ in range(count)]


def make_services(dst_zone: str) -> list[dict]:
    options = SERVICES_BY_DEST.get(dst_zone, DEFAULT_SERVICES)
    return [{"protocol": p, "port": port} for p, port in random.choice(options)]


def seed(wipe: bool):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    if wipe:
        for model in (Comment, RuleVersion, Rule, ZonePolicyChange, ZonePolicy, ZoneNetwork, Zone, AciGateway,
                      AddressComponentMap, AddressEpgMap, Epg, AddressObject,
                      ServiceObject, ComponentLink, SecurityComponent, Vrf):
            db.query(model).delete()
        db.commit()

    # Vorerst eine Umgebung; das Multi-Umgebungs-/VRF-Scoping bleibt vorbereitet
    # (zweite Umgebung, z.B. OT, kann später über /api/vrfs ergänzt werden)
    vrf_it = Vrf(name="IT", description="Default-Umgebung")
    db.add(vrf_it)
    db.flush()

    # Objektkatalog: wiederverwendbare Adress- und Dienst-Objekte
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

    # Sicherheitskomponenten
    components = {}
    for name, ctype, location, mgmt, tier, descr in COMPONENTS:
        component = SecurityComponent(name=name, type=ctype, location=location,
                                      mgmt_address=mgmt, ns_tier=tier, description=descr)
        db.add(component)
        components[name] = component
    db.flush()

    # Kommunikationsbeziehungen der Komponenten (Topologie-Dokumentation)
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
            component_a_id=min(fw_ber_c.id, components["FW-Cluster-Provider"].id),
            component_b_id=max(fw_ber_c.id, components["FW-Cluster-Provider"].id),
            link_type="BGP Peering",
            description="Upstream-Anbindung an den externen Provider (Internet-Übergang)",
        ),
    ])

    # ACI Anycast Gateways – PBR-Anbindung an den Check Point Cluster (FFM)
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
            pbr_enabled=True, pbr_component_id=checkpoint_ffm.id,
            pbr_node_ip="10.10.35.10", pbr_node_mac="00:50:56:AB:CD:01",
            pbr_service_graph="SG-CHKP-FFM", pbr_health_group="HG-CHKP-FFM",
            description="Anycast Gateway Produktion DB; Umleitung zur Inspektion über Check Point FFM",
        ),
        AciGateway(
            name="GW-SHARED", tenant="DEMO", vrf="VRF-SHARED", bridge_domain="BD-SHARED",
            gateway_ip="10.10.70.1/24", zone_name="SHARED",
            pbr_enabled=False,
            description="Anycast Gateway Shared Services; ohne PBR (nur Contracts)",
        ),
    ]
    db.add_all(gateways)

    # Zonen + vollständige Matrix; BSI P-A-P-Einstufung:
    # extern = nördlich der P-A-P, pap = innerhalb (DMZ/Transfer), intern = unterhalb
    PAP_LEVELS = {"INET": "extern", "DMZ-WEB": "pap", "VPN": "pap"}
    zones = {}
    for order, (name, descr, _net) in enumerate(ZONES):
        zone = Zone(name=name, description=descr, sort_order=order,
                    pap_level=PAP_LEVELS.get(name, "intern"))
        db.add(zone)
        zones[name] = zone
    db.flush()
    # Netzwerk-Zuordnung: jedes Netzwerk gehört zu genau einer Zone; "any" -> INET
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

    # ~100 Regeln: 88 zwischen erlaubten Zonen (FW), 12 intra-zonal (ACI)
    pairs = sorted(ALLOWED)
    intra_zones = ["PROD-APP", "PROD-DB", "SHARED", "TEST", "DEV", "CICD"]
    plans = [random.choice(pairs) for _ in range(88)] + \
            [(z, z) for z in (intra_zones * 2)]  # 12 Intra-Zonen-Regeln

    statuses = (
        [RuleStatus.approved] * 60 + [RuleStatus.in_review] * 15 + [RuleStatus.draft] * 14
        + [RuleStatus.rejected] * 5 + [RuleStatus.deactivated] * 6
    )
    random.shuffle(statuses)

    start = date(2026, 1, 5)
    fw_ffm = components["FW-Cluster-FFM"]
    fw_ber = components["FW-Cluster-BER"]
    aci_ffm = components["ACI-Fabric-FFM"]

    # Adress->Komponenten-Zuordnung: Zonen-Netze verteilt auf die beiden Cluster,
    # ACI-Fabric zusätzlich für Intra-Zonen-Contracts
    # DMZ hängt am BER-Cluster: Internet-Pfad ist durchgängig Provider -> BER,
    # der FFM-Cluster bedient nur interne Zonen (kein direkter Internet-Pfad)
    ZONE_FW = {
        "PROD-APP": fw_ffm, "PROD-DB": fw_ffm, "SHARED": fw_ffm, "MON": fw_ffm,
        "DMZ-WEB": fw_ber, "VPN": fw_ber, "MGMT": fw_ber, "TEST": fw_ber, "DEV": fw_ber, "CICD": fw_ber,
    }
    for zone_name, fw in ZONE_FW.items():
        db.add(
            AddressComponentMap(
                ip=zone_net(zone_name), alias=f"NET-{zone_name}", vrf_id=vrf_it.id,
                component_ids=sorted({fw.id, aci_ffm.id}), created_by="demo-seed",
            )
        )
        zones[zone_name].components = [fw]  # "Angebunden an": explizite Firewall-Anbindung
    zones["INET"].components = [components["FW-Cluster-Provider"]]
    zones["DMZ-WEB"].components = [fw_ber, components["FW-Cluster-Provider"]]  # Beispiel: Mehrfach-Anbindung
    # Internet ("any") erreicht die Umgebung über den Provider-Cluster
    db.add(AddressComponentMap(
        ip="any", alias="Internet", vrf_id=vrf_it.id,
        component_ids=[components["FW-Cluster-Provider"].id], created_by="demo-seed",
    ))

    # ACI: EPG-Katalog + Adresse->EPG-Zuordnung (Basis des Contract-Exports)
    ACI_ZONES = ["PROD-APP", "PROD-DB", "SHARED", "TEST", "DEV", "CICD"]
    epgs = {}
    for zone_name in ACI_ZONES:
        epg = Epg(
            name=f"epg-{zone_name.lower()}", tenant="DEMO", app_profile="AP-DEMO",
            bridge_domain=f"BD-{zone_name}", description=f"Endpoint Group Zone {zone_name}",
        )
        db.add(epg)
        epgs[zone_name] = epg
    # External EPG (L3Out) für Nord-Süd-Verkehr aus dem MGMT-Netz in die Fabric
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
            # Internet läuft ausschließlich über Provider -> BER; der FW-Cluster FFM
            # hat keinen direkten Internet-Pfad (Kundenumgebungs-Beispiel)
            provider = components["FW-Cluster-Provider"]
            return sorted([provider, fw_ber], key=lambda c: c.name)
        return sorted(fws.values(), key=lambda c: c.name)

    for i, (src_zone, dst_zone) in enumerate(plans, start=1):
        rule_id = f"SR{i:05d}"
        intra = src_zone == dst_zone
        # Komponenten wie die automatische Auflösung: Intra-Zone -> ACI, sonst FW-Cluster
        rule_components_list = resolve_seed_components(src_zone, dst_zone)
        app = random.choice(APPLICATIONS)
        requestor, owner = random.choice(PEOPLE), random.choice(PEOPLE)
        status = statuses[i - 1]
        created = start + timedelta(days=random.randint(0, 200))

        impl_status = {}
        if status == RuleStatus.approved:
            for c in rule_components_list:
                impl_status[c.name] = random.choice(["umgesetzt", "umgesetzt", "neu"])
        elif status == RuleStatus.deactivated:
            impl_status = {c.name: "deaktiviert" for c in rule_components_list}

        justification = random.choice(JUSTIFICATIONS).format(app=app, dst_zone=dst_zone)
        rule = Rule(
            rule_id=rule_id,
            vrf_id=vrf_it.id,
            name=f"{app}-{dst_zone}-{i:03d}",
            application=app,
            components=rule_components_list,
            source_zone=src_zone,
            destination_zone=dst_zone,
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
                snapshot={"seed": "demo"}, change_note="Demo-Regel angelegt",
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

    # Zwei bewusste Konflikt-Beispiele (Überlappung) zum Testen der Warnungen
    for rid, src, src_alias in (
        ("SR00101", "10.10.20.0/24", "NET-VPN"),
        ("SR00102", "10.10.20.128/25", "NET-VPN-B"),
    ):
        rule = Rule(
            rule_id=rid,
            vrf_id=vrf_it.id, name=f"Konflikt-Demo-{rid}", application="Portal",
            components=[fw_ber], source_zone="VPN", destination_zone="MGMT",
            source=[{"ip": src, "alias": src_alias}],
            destination=[{"ip": "10.10.80.10", "alias": "jump01.demo.local"}],
            services=[{"protocol": "TCP", "port": "22"}], action=RuleAction.permit,
            justification="Demo: absichtlich überlappende Regel für Konflikt-Warnung",
            requestor="Max Bauer", owner="mbauer", change_id="CHN2026999",
            status=RuleStatus.approved, impl_status={fw_ber.name: "umgesetzt"},
            created_by="demo-seed",
        )
        db.add(rule)
        db.flush()
        db.add(RuleVersion(rule_pk=rule.id, version=1, snapshot={"seed": "demo"},
                           change_note="Demo-Regel angelegt", changed_by="demo-seed"))

    # Demo-Regel über alle drei Komponenten: MGMT (hinter FW BER) -> PROD-APP (FFM).
    # Umsetzung: Firewall-Regel auf beiden Clustern (Standort-Transit) plus
    # ACI Contract, weil das Ziel-Segment Contracts erzwingt (L3Out -> EPG).
    rule = Rule(
        rule_id="SR00103",
        vrf_id=vrf_it.id, name="Admin-Zugriff-PROD-APP", application="Infrastruktur",
        components=[components["FW-Cluster-BER"], components["FW-Cluster-FFM"],
                    components["ACI-Fabric-FFM"]],
        source_zone="MGMT", destination_zone="PROD-APP",
        source=[{"ip": "10.10.80.10", "alias": "jump01.demo.local"}],
        destination=[{"ip": "10.10.30.20", "alias": "app20.demo.local"}],
        services=[{"protocol": "TCP", "port": "8443"}], action=RuleAction.permit,
        description="Standortübergreifender Admin-Zugriff: Umsetzung auf allen drei Komponenten",
        justification="Administration der PROD-APP-Server vom zentralen Jump-Host (BER -> FFM, "
                      "Transit über beide FW-Cluster, ACI Contract im Ziel-Segment)",
        business_context="Interne IT", requestor="Max Bauer", owner="mbauer",
        change_id="CHN2027001", status=RuleStatus.approved,
        impl_status={"FW-Cluster-BER": "umgesetzt", "FW-Cluster-FFM": "umgesetzt",
                     "ACI-Fabric-FFM": "neu"},
        created_by="demo-seed",
    )
    db.add(rule)
    db.flush()
    db.add(RuleVersion(rule_pk=rule.id, version=1, snapshot={"seed": "demo"},
                       change_note="Demo-Regel angelegt", changed_by="demo-seed"))

    # Minimalprinzip: Die Demo-Matrix ist vollständig gepflegt -> default-deny
    # für ungepflegte Zonen-Beziehungen aktivieren (BSI-Empfehlung, Issue #13)
    from app.settings import set_setting

    set_setting(db, "zone_matrix_default", "deny")

    db.commit()
    rules_count = db.query(Rule).count()
    zone_count = db.query(Zone).count()
    policy_count = db.query(ZonePolicy).count()
    component_count = db.query(SecurityComponent).count()
    gateway_count = db.query(AciGateway).count()
    db.close()
    print(
        f"Demo-Daten: {zone_count} Zonen, {policy_count} Matrix-Einträge, "
        f"{rules_count} Regeln, {component_count} Sicherheitskomponenten, "
        f"{gateway_count} ACI Gateways."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--wipe", action="store_true", help="Vorhandene Regeln und Zonen löschen")
    args = parser.parse_args()
    seed(args.wipe)
