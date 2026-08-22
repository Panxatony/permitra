import enum
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow():
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    architect = "architect"            # plant und beantragt
    operations = "operations"          # setzt um (Umsetzungsstatus, Export, Drift)
    change_approver = "change_approver"  # gibt frei (Regel-Reviews, Matrix-Anträge)
    admin = "admin"


class RuleStatus(str, enum.Enum):
    draft = "draft"            # in Planung (Architekt)
    in_review = "in_review"    # zur Prüfung eingereicht
    approved = "approved"      # freigegeben, bereit zur Umsetzung
    rejected = "rejected"      # abgelehnt, zurück an Architekt
    deactivated = "deactivated"  # Regel außer Betrieb genommen


class RuleAction(str, enum.Enum):
    permit = "permit"
    deny = "deny"


# Umsetzungsstatus je Plattform (entspricht "Status Juniper"/"Status ACI" im Excel)
IMPL_STATUSES = ["offen", "neu", "umgesetzt", "deaktiviert"]
PLATFORMS = ["juniper", "checkpoint", "aci"]


class ZonePolicyType(str, enum.Enum):
    allow_only = "allow_only"  # Kommunikation nur über explizite Sicherheitsregeln
    block_all = "block_all"    # keine Sicherheitsregeln zwischen diesen Zonen zulässig


class Vrf(Base):
    """VRF / Routing-Kontext (Mandant): Scoping-Dimension für Netze, Adress-
    Zuordnungen und Regeln – erlaubt überlappende IP-Bereiche zwischen Mandanten.
    Zonen-Katalog, Matrix und Komponenten bleiben global."""

    __tablename__ = "vrfs"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # z.B. GLOBAL, KUNDE-A
    description: Mapped[str] = mapped_column(Text, default="")


# Anbindung einer Sicherheitszone an ihre Firewall-Cluster (explizit gepflegt)
zone_components = Table(
    "zone_components",
    Base.metadata,
    Column("zone_id", ForeignKey("zones.id", ondelete="CASCADE"), primary_key=True),
    Column("component_id", ForeignKey("security_components.id", ondelete="CASCADE"), primary_key=True),
)


class Zone(Base):
    __tablename__ = "zones"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # z.B. D-PRD
    description: Mapped[str] = mapped_column(Text, default="")
    # BSI P-A-P-Einstufung: "extern" (nördlich der P-A-P), "pap" (innerhalb der
    # P-A-P-Ebene, z.B. DMZ), "intern" (unterhalb der P-A-P-Struktur)
    pap_level: Mapped[str] = mapped_column(String(16), default="intern")
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    # BSI-Dokumentation: Verantwortlicher und Schutzbedarf je Schutzziel (CIA),
    # jeweils "normal" | "hoch" | "sehr hoch"; Gesamt-Schutzbedarf = Maximumprinzip
    owner: Mapped[str] = mapped_column(String(128), default="")
    cia_c: Mapped[str] = mapped_column(String(16), default="normal")  # Vertraulichkeit
    cia_i: Mapped[str] = mapped_column(String(16), default="normal")  # Integrität
    cia_a: Mapped[str] = mapped_column(String(16), default="normal")  # Verfügbarkeit

    @property
    def schutzbedarf(self) -> str:
        order = {"normal": 0, "hoch": 1, "sehr hoch": 2}
        return max((self.cia_c, self.cia_i, self.cia_a),
                   key=lambda v: order.get(v, 0))

    # "Angebunden an": Firewall-Cluster, über die diese Zone erreichbar ist
    components: Mapped[list["SecurityComponent"]] = relationship(secondary=zone_components)
    networks: Mapped[list["ZoneNetwork"]] = relationship(
        back_populates="zone", cascade="all, delete-orphan", order_by="ZoneNetwork.cidr"
    )


class ZoneNetwork(Base):
    """Netzwerk-Zuordnung: jedes Netzwerk gehört zu genau einer Sicherheitszone.

    Regeln leiten daraus Quell-/Ziel-Zone automatisch ab; Adressen aus nicht
    zugeordneten Netzen werden abgelehnt. Sonderwert cidr='any' (z.B. Internet)."""

    __tablename__ = "zone_networks"
    __table_args__ = (UniqueConstraint("vrf_id", "cidr"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    vrf_id: Mapped[int] = mapped_column(ForeignKey("vrfs.id", ondelete="CASCADE"), index=True)
    cidr: Mapped[str] = mapped_column(String(64), index=True)  # normalisiert oder "any"
    zone_id: Mapped[int] = mapped_column(ForeignKey("zones.id", ondelete="CASCADE"), index=True)
    description: Mapped[str] = mapped_column(String(128), default="")
    # Herkunft: "manual" (UI) oder eine externe Quelle wie "netbox" –
    # die Netzverwaltung selbst erfolgt in dedizierten Tools, Permitra pflegt das Zonen-Mapping
    source: Mapped[str] = mapped_column(String(32), default="manual")

    zone: Mapped[Zone] = relationship(back_populates="networks")
    vrf: Mapped[Vrf] = relationship()


class ZonePolicy(Base):
    """Zonen-Kommunikationsmatrix: regelt je (von, nach), ob Regeln erlaubt sind.

    Zwischen Zonen steht immer eine Firewall, daher nur Allow/Block –
    ACI wird ausschließlich innerhalb einer Zone eingesetzt.
    """

    __tablename__ = "zone_policies"
    __table_args__ = (UniqueConstraint("from_zone_id", "to_zone_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    from_zone_id: Mapped[int] = mapped_column(ForeignKey("zones.id", ondelete="CASCADE"), index=True)
    to_zone_id: Mapped[int] = mapped_column(ForeignKey("zones.id", ondelete="CASCADE"), index=True)
    policy: Mapped[ZonePolicyType] = mapped_column(Enum(ZonePolicyType), default=ZonePolicyType.block_all)
    temporary: Mapped[bool] = mapped_column(default=False)  # "Temp" in der Matrix
    note: Mapped[str] = mapped_column(Text, default="")

    from_zone: Mapped[Zone] = relationship(foreign_keys=[from_zone_id])
    to_zone: Mapped[Zone] = relationship(foreign_keys=[to_zone_id])


class ComponentType(str, enum.Enum):
    juniper = "juniper"
    checkpoint = "checkpoint"
    aci = "aci"


class SecurityComponent(Base):
    """Sicherheitskomponenten: Firewall-Cluster und ACI-Fabrics, auf denen Regeln umgesetzt werden."""

    __tablename__ = "security_components"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)  # z.B. FW-Cluster-FFM
    type: Mapped[ComponentType] = mapped_column(Enum(ComponentType))
    location: Mapped[str] = mapped_column(String(128), default="")   # Standort/Zone, z.B. "Zone FFM"
    mgmt_address: Mapped[str] = mapped_column(String(256), default="")  # Management-IP/-Hostname
    # Nord-Süd-Ordnung: kleinere Zahl = nördlicher (Internet-nah), größere = südlicher
    ns_tier: Mapped[int] = mapped_column(Integer, default=100)
    description: Mapped[str] = mapped_column(Text, default="")
    active: Mapped[bool] = mapped_column(default=True)


class ZonePolicyChange(Base):
    """Versionierung der Zonen-Kommunikationsmatrix mit Freigabe-Schritt.

    Jede Änderung wird als Antrag protokolliert (wer/wann/was) und erst nach
    Freigabe durch den Betrieb auf die Matrix angewendet (Vier-Augen-Prinzip)."""

    __tablename__ = "zone_policy_changes"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Sammelanträge: alle Einträge eines Antrags teilen sich eine batch_id und
    # werden gemeinsam freigegeben/abgelehnt
    batch_id: Mapped[str] = mapped_column(String(36), default="", index=True)
    # "policy" = Matrix-Zelle; "zone_create" = neue Zone (from_zone = Name,
    # new_policy = P-A-P-Einstufung); "net_add"/"net_update"/"net_delete" =
    # Netzwerk-Zuordnung (from_zone = Zone, to_zone = CIDR, Details in extra)
    change_type: Mapped[str] = mapped_column(String(16), default="policy")
    extra: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    from_zone: Mapped[str] = mapped_column(String(64), index=True)
    to_zone: Mapped[str] = mapped_column(String(64), index=True, default="")
    old_policy: Mapped[str | None] = mapped_column(String(16), nullable=True)  # None = neu
    new_policy: Mapped[str] = mapped_column(String(16))
    old_temporary: Mapped[bool] = mapped_column(default=False)
    new_temporary: Mapped[bool] = mapped_column(default=False)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending/approved/rejected
    requested_by: Mapped[str] = mapped_column(String(64), default="")
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Zonen-/Matrix-Änderungen brauchen ZWEI Freigaben (verschiedene Change Approver)
    first_approved_by: Mapped[str] = mapped_column(String(64), default="")
    first_approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by: Mapped[str] = mapped_column(String(64), default="")
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    comment: Mapped[str] = mapped_column(Text, default="")


class ComponentLink(Base):
    """Dokumentierte Kommunikationsbeziehung zwischen zwei Sicherheitskomponenten
    (ungerichtet), z.B. "ACI-Fabric-FFM <-> FW-Cluster-FFM: PBR Service Graph".

    Normalisierung: component_a_id < component_b_id (wird beim Anlegen erzwungen)."""

    __tablename__ = "component_links"
    __table_args__ = (UniqueConstraint("component_a_id", "component_b_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    component_a_id: Mapped[int] = mapped_column(
        ForeignKey("security_components.id", ondelete="CASCADE"), index=True
    )
    component_b_id: Mapped[int] = mapped_column(
        ForeignKey("security_components.id", ondelete="CASCADE"), index=True
    )
    link_type: Mapped[str] = mapped_column(String(64), default="")  # z.B. "OSPF Routing", "PBR / Service Graph"
    description: Mapped[str] = mapped_column(Text, default="")

    component_a: Mapped["SecurityComponent"] = relationship(foreign_keys=[component_a_id])
    component_b: Mapped["SecurityComponent"] = relationship(foreign_keys=[component_b_id])


class ComponentActualConfig(Base):
    """Ist-Konfiguration einer Komponente für den Soll-Ist-Abgleich (Drift).

    Wird per API hochgeladen/eingefügt; ein Adapter, der sie direkt vom Gerät
    abruft (Check Point Mgmt API, Junos, APIC), kann hier später andocken."""

    __tablename__ = "component_actual_configs"

    id: Mapped[int] = mapped_column(primary_key=True)
    component_id: Mapped[int] = mapped_column(
        ForeignKey("security_components.id", ondelete="CASCADE"), unique=True, index=True
    )
    content: Mapped[str] = mapped_column(Text, default="")
    uploaded_by: Mapped[str] = mapped_column(String(64), default="")
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    component: Mapped["SecurityComponent"] = relationship()


class AddressObject(Base):
    """Wiederverwendbares Adress-Objekt: Name (Alias) -> IP/Netz.

    Ändert sich die IP, werden alle Regel-Einträge mit diesem Alias mitgezogen."""

    __tablename__ = "address_objects"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    ip: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text, default="")


class ServiceObject(Base):
    """Wiederverwendbares Dienst-Objekt, z.B. HTTPS = TCP/443."""

    __tablename__ = "service_objects"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    protocol: Mapped[str] = mapped_column(String(16))
    port: Mapped[str] = mapped_column(String(64), default="")
    description: Mapped[str] = mapped_column(Text, default="")


class Epg(Base):
    """Cisco ACI Endpoint Group: Ziel der EPG-basierten Contract-Modellierung.

    Contracts verbinden EPGs (nicht IPs) – die Zuordnung von Adressen zu EPGs
    erfolgt über AddressEpgMap."""

    __tablename__ = "epgs"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)  # z.B. epg-prod-app
    tenant: Mapped[str] = mapped_column(String(64), default="")
    app_profile: Mapped[str] = mapped_column(String(64), default="")
    bridge_domain: Mapped[str] = mapped_column(String(64), default="")  # verknüpft mit AciGateway
    description: Mapped[str] = mapped_column(Text, default="")


class AddressEpgMap(Base):
    """Zuordnung Adresse/Netz -> EPG (analog zur Komponenten-Zuordnung).

    Auflösung: exakter Treffer oder spezifischstes enthaltendes Netz;
    ip='any' steht für vzAny (alle EPGs im VRF)."""

    __tablename__ = "address_epg_map"
    __table_args__ = (UniqueConstraint("vrf_id", "ip"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    vrf_id: Mapped[int] = mapped_column(ForeignKey("vrfs.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)  # normalisiert
    alias: Mapped[str] = mapped_column(String(128), default="")
    epg_id: Mapped[int] = mapped_column(ForeignKey("epgs.id", ondelete="CASCADE"), index=True)
    created_by: Mapped[str] = mapped_column(String(64), default="")

    epg: Mapped[Epg] = relationship()


class AddressComponentMap(Base):
    """Zuordnung Adresse/Netz -> Komponenten: legt fest, auf welchen Komponenten
    Regeln für diese Quelle/dieses Ziel angelegt werden müssen.

    Wird beim ersten Auftreten einer neuen Adresse einmalig vom Nutzer festgelegt
    und danach automatisch angewendet (auch für enthaltene Einzel-IPs per
    Netz-Containment)."""

    __tablename__ = "address_component_map"
    __table_args__ = (UniqueConstraint("vrf_id", "ip"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    vrf_id: Mapped[int] = mapped_column(ForeignKey("vrfs.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)  # normalisiert, z.B. 10.10.30.0/24 oder "any"
    alias: Mapped[str] = mapped_column(String(128), default="")
    component_ids: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AciGateway(Base):
    """Cisco ACI Anycast Gateways (Bridge-Domain-SVIs), optional mit PBR-Umleitung
    auf einen Check Point Firewall-Cluster (Service Graph / Policy-Based Redirect)."""

    __tablename__ = "aci_gateways"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)  # z.B. GW-PROD-APP
    tenant: Mapped[str] = mapped_column(String(64), default="")
    vrf: Mapped[str] = mapped_column(String(64), default="")
    bridge_domain: Mapped[str] = mapped_column(String(64), default="")
    gateway_ip: Mapped[str] = mapped_column(String(64))  # Anycast-SVI, z.B. 10.10.30.1/24
    zone_name: Mapped[str] = mapped_column(String(64), default="")  # zugehörige Sicherheitszone

    pbr_enabled: Mapped[bool] = mapped_column(default=False)
    pbr_component_id: Mapped[int | None] = mapped_column(
        ForeignKey("security_components.id", ondelete="SET NULL"), nullable=True
    )
    pbr_node_ip: Mapped[str] = mapped_column(String(64), default="")   # Redirect-Ziel (FW-Interface)
    pbr_node_mac: Mapped[str] = mapped_column(String(32), default="")
    pbr_service_graph: Mapped[str] = mapped_column(String(128), default="")  # Service-Graph-Template
    pbr_health_group: Mapped[str] = mapped_column(String(128), default="")

    description: Mapped[str] = mapped_column(Text, default="")
    active: Mapped[bool] = mapped_column(default=True)

    pbr_component: Mapped["SecurityComponent | None"] = relationship()


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    full_name: Mapped[str] = mapped_column(String(128), default="")
    email: Mapped[str] = mapped_column(String(128), default="")
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.architect)
    is_active: Mapped[bool] = mapped_column(default=True)
    # Zwei-Faktor (TOTP): Secret wird beim Setup gesetzt, zählt erst mit enabled
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(default=False)
    # Sitzungs-Invalidierung: vor diesem Zeitpunkt ausgestellte Tokens gelten
    # nicht mehr (gesetzt bei Deaktivierung, Passwortwechsel/-reset)
    token_valid_from: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)

    passkeys: Mapped[list["Passkey"]] = relationship(back_populates="user",
                                                    cascade="all, delete-orphan")


class Setting(Base):
    """Permitra-Einstellungen (Admin-Bereich), z.B. zone_matrix_default."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(256), default="")


class AuthToken(Base):
    """Einmal-Token für Aktivierungs- und Passwort-Reset-Links (nur Hash gespeichert)."""

    __tablename__ = "auth_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    purpose: Mapped[str] = mapped_column(String(16))  # "activate" | "reset"
    token_hash: Mapped[str] = mapped_column(String(64), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped["User"] = relationship()


class Passkey(Base):
    """WebAuthn-Passkey eines Benutzers (Anmeldung ohne Passwort)."""

    __tablename__ = "passkeys"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    credential_id: Mapped[str] = mapped_column(Text)  # base64url
    public_key: Mapped[str] = mapped_column(Text)     # base64
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(64), default="Passkey")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped["User"] = relationship(back_populates="passkeys")


# Zuordnung Regel -> Sicherheitskomponenten, auf denen sie umzusetzen ist
rule_components = Table(
    "rule_components",
    Base.metadata,
    Column("rule_pk", ForeignKey("rules.id", ondelete="CASCADE"), primary_key=True),
    Column("component_id", ForeignKey("security_components.id", ondelete="CASCADE"), primary_key=True),
)


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)  # z.B. SR0855
    vrf_id: Mapped[int] = mapped_column(ForeignKey("vrfs.id", ondelete="RESTRICT"), index=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    application: Mapped[str] = mapped_column(String(128), default="", index=True)   # z.B. Control, ePA
    # Konkrete Komponenten (Firewall-Cluster/ACI-Fabric), auf denen die Regel
    # als Firewall-Regel bzw. ACI Contract angelegt werden muss
    components: Mapped[list["SecurityComponent"]] = relationship(secondary=rule_components)

    # Text statt String: Altdaten enthalten teils mehrzeilige Zonen-Listen
    source_zone: Mapped[str] = mapped_column(Text, default="")
    destination_zone: Mapped[str] = mapped_column(Text, default="")
    # Adress-Einträge: immer IP oder Netz, optional mit Alias (Hostname/Netzwerkname):
    # [{"ip": "10.10.30.5", "alias": "app01.demo.local"}, {"ip": "10.10.20.0/24", "alias": "VPN-Netz"}]
    # Sonderwert ip="any" für beliebige Quellen/Ziele (z.B. Internet)
    source: Mapped[list] = mapped_column(JSON, default=list)
    destination: Mapped[list] = mapped_column(JSON, default=list)
    # Dienste: [{"protocol": "TCP", "port": "443"}, {"protocol": "ICMP", "port": ""}]
    services: Mapped[list] = mapped_column(JSON, default=list)
    action: Mapped[RuleAction] = mapped_column(Enum(RuleAction), default=RuleAction.permit)

    description: Mapped[str] = mapped_column(Text, default="")
    justification: Mapped[str] = mapped_column(Text, default="")      # "Anlass (Administrationsbedarf)"
    business_context: Mapped[str] = mapped_column(String(256), default="")  # "Fachlicher Bezug"
    info: Mapped[str] = mapped_column(Text, default="")
    requestor: Mapped[str] = mapped_column(String(128), default="")
    owner: Mapped[str] = mapped_column(String(128), default="")       # "Bearbeiter"
    change_id: Mapped[str] = mapped_column(String(128), default="")   # z.B. CHN0000273
    valid_from: Mapped[str | None] = mapped_column(String(10), nullable=True)   # ISO-Datum
    valid_until: Mapped[str | None] = mapped_column(String(10), nullable=True)

    status: Mapped[RuleStatus] = mapped_column(Enum(RuleStatus), default=RuleStatus.draft, index=True)
    # {"juniper": "umgesetzt", "aci": "neu"} – nur für Plattformen in `platforms`
    impl_status: Mapped[dict] = mapped_column(JSON, default=dict)

    version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    @property
    def platforms(self) -> list[str]:
        """Abgeleitet aus den Typen der zugeordneten Komponenten (für Export/Prüfungen)."""
        return sorted({c.type.value for c in self.components})

    vrf: Mapped["Vrf"] = relationship()

    versions: Mapped[list["RuleVersion"]] = relationship(
        back_populates="rule", cascade="all, delete-orphan", order_by="RuleVersion.version.desc()"
    )
    comments: Mapped[list["Comment"]] = relationship(
        back_populates="rule", cascade="all, delete-orphan", order_by="Comment.created_at"
    )


class RuleVersion(Base):
    __tablename__ = "rule_versions"
    __table_args__ = (UniqueConstraint("rule_pk", "version"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_pk: Mapped[int] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    snapshot: Mapped[dict] = mapped_column(JSON)
    change_note: Mapped[str] = mapped_column(Text, default="")
    changed_by: Mapped[str] = mapped_column(String(64), default="")
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    rule: Mapped[Rule] = relationship(back_populates="versions")


class Comment(Base):
    __tablename__ = "comments"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_pk: Mapped[int] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), index=True)
    author: Mapped[str] = mapped_column(String(64))
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    rule: Mapped[Rule] = relationship(back_populates="comments")
