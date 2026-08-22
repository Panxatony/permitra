from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .models import ComponentType, RuleAction, RuleStatus, Role, ZonePolicyType
from .validation import validate_ip_entry, validate_service


class Service(BaseModel):
    protocol: str = Field(..., description="TCP, UDP, TCP/UDP, ICMP oder ANY")
    port: str = Field("", description='z.B. "443", "8000-8080", "any"; leer bei ICMP')

    @model_validator(mode="after")
    def check(self):
        validate_service(self.protocol, self.port)
        self.protocol = self.protocol.strip().upper()
        self.port = self.port.strip().lower()
        return self


class AddressEntry(BaseModel):
    """Adress-Eintrag: immer IP/Netz, optional mit Alias (Hostname bzw. Netzwerkname)."""

    ip: str = Field(..., description='IP, Netz (CIDR) oder "any"')
    alias: str = Field("", max_length=128, description="z.B. Hostname bei IP, Netzwerkname bei Netz")

    @field_validator("ip")
    @classmethod
    def check_ip(cls, v):
        return validate_ip_entry(v)

    @field_validator("alias")
    @classmethod
    def strip_alias(cls, v):
        return v.strip()


class ComponentBrief(BaseModel):
    """Kurzform einer Sicherheitskomponente für die Anzeige an einer Regel."""

    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    type: ComponentType
    location: str = ""


class RuleFields(BaseModel):
    """Gemeinsame Felder ohne Validierung – Basis für Ausgabe-Modelle.

    Ausgaben dürfen nicht erneut validieren, damit auch tolerant importierte
    Altdaten (Excel) ausgeliefert werden können.
    """

    name: str = ""
    application: str = ""
    vrf: str = ""              # Umgebung/VRF der Regel
    components: list[ComponentBrief] = []      # Komponenten, auf denen die Regel umzusetzen ist
    platforms: list[str] = []                  # abgeleitet aus den Komponenten-Typen
    source_zone: str = ""
    destination_zone: str = ""
    source: list[dict] = []       # [{"ip": ..., "alias": ...}]
    destination: list[dict] = []
    services: list[dict] = []
    action: RuleAction = RuleAction.permit
    description: str = ""
    justification: str = ""
    business_context: str = ""
    info: str = ""
    requestor: str = ""
    owner: str = ""
    change_id: str = ""
    valid_from: str | None = None
    valid_until: str | None = None
    impl_status: dict[str, str] = {}

    @field_validator("vrf", mode="before")
    @classmethod
    def vrf_to_name(cls, v):
        return getattr(v, "name", v) or ""


class RuleBase(BaseModel):
    """Eingabe-Modell mit Plausibilitätsprüfungen.

    Regeln werden konkreten Komponenten zugeordnet (component_ids) – die Plattform
    ergibt sich aus deren Typ.
    """

    name: str = ""
    application: str = ""
    vrf: str = ""              # Umgebung/VRF; leer = Default (erster VRF)
    component_ids: list[int] = []
    source_zone: str = ""
    destination_zone: str = ""
    source: list[AddressEntry]
    destination: list[AddressEntry]
    services: list[Service]
    action: RuleAction = RuleAction.permit
    description: str = ""
    justification: str = ""
    business_context: str = ""
    info: str = ""
    requestor: str = ""
    owner: str = ""
    change_id: str = ""
    valid_from: str | None = None
    valid_until: str | None = None
    impl_status: dict[str, str] = {}

    @field_validator("source", "destination")
    @classmethod
    def check_addresses(cls, v, info):
        if not v:
            raise ValueError(f"{info.field_name}: mindestens ein Adress-Eintrag erforderlich")
        return v

    @field_validator("services")
    @classmethod
    def check_services(cls, v):
        if not v:
            raise ValueError("Mindestens ein Dienst (Protokoll/Port) ist erforderlich")
        return v

    @model_validator(mode="after")
    def check_validity_period(self):
        if self.valid_from and self.valid_until and self.valid_from > self.valid_until:
            raise ValueError("Gültig-bis liegt vor Gültig-ab")
        return self


class RuleCreate(RuleBase):
    """Die Rule-ID wird immer serverseitig vergeben (fortlaufende SR-Nummer, unveränderlich)."""


class RuleUpdate(RuleBase):
    change_note: str = ""


class CommentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    author: str
    text: str
    created_at: datetime


class RuleVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    version: int
    snapshot: dict
    change_note: str
    changed_by: str
    changed_at: datetime


class RuleOut(RuleFields):
    model_config = ConfigDict(from_attributes=True)
    id: int
    rule_id: str
    status: RuleStatus
    version: int
    created_by: str
    created_at: datetime
    updated_at: datetime


class RuleDetail(RuleOut):
    versions: list[RuleVersionOut] = []
    comments: list[CommentOut] = []


class RuleListOut(BaseModel):
    total: int
    items: list[RuleOut]


class ExpiringOut(BaseModel):
    days: int
    expired: list[RuleOut]
    expiring: list[RuleOut]


class ExtendRequest(BaseModel):
    valid_until: str = Field(..., description="Neues Gültig-bis-Datum (ISO), z.B. 2027-08-20")
    comment: str = ""


class CommentCreate(BaseModel):
    text: str = Field(..., min_length=1)


class ReviewDecision(BaseModel):
    comment: str = ""


class ConflictOut(BaseModel):
    rule_id: str
    other_rule_id: str
    kind: str
    detail: str


PAP_LEVELS = ("extern", "pap", "intern")


CIA_LEVELS = ("normal", "hoch", "sehr hoch")


class ZoneCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    description: str = ""
    pap_level: str = Field("intern", description="BSI P-A-P-Einstufung: extern | pap | intern")
    sort_order: int = 0
    owner: str = Field("", max_length=128, description="Verantwortlicher (Person/Team)")
    cia_c: str = Field("normal", description="Schutzbedarf Vertraulichkeit")
    cia_i: str = Field("normal", description="Schutzbedarf Integrität")
    cia_a: str = Field("normal", description="Schutzbedarf Verfügbarkeit")

    @field_validator("cia_c", "cia_i", "cia_a")
    @classmethod
    def check_cia(cls, v):
        v = v.strip().lower()
        if v not in CIA_LEVELS:
            raise ValueError(f"Schutzbedarf muss einer von {', '.join(CIA_LEVELS)} sein")
        return v

    @field_validator("pap_level")
    @classmethod
    def check_pap(cls, v):
        v = v.strip().lower()
        if v not in PAP_LEVELS:
            raise ValueError(f"pap_level muss eines von {', '.join(PAP_LEVELS)} sein")
        return v


class ZoneOut(ZoneCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    schutzbedarf: str = "normal"  # Maximum aus C/I/A


class ZonePolicySet(BaseModel):
    policy: ZonePolicyType
    temporary: bool = False
    note: str = ""


class ZonePolicyOut(ZonePolicySet):
    from_zone: str
    to_zone: str


class ZoneMatrixOut(BaseModel):
    zones: list[ZoneOut]
    policies: list[ZonePolicyOut]


class ZoneCheckOut(BaseModel):
    allowed: bool
    policy: str | None
    temporary: bool
    messages: list[str]


class ComponentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    type: ComponentType
    location: str = ""
    mgmt_address: str = ""
    ns_tier: int = Field(100, ge=0, le=1000, description="Nord-Süd-Ebene: 0 = nördlich (Internet-nah)")
    description: str = ""
    active: bool = True


class ComponentOut(ComponentCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int


class AciGatewayCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    tenant: str = ""
    vrf: str = ""
    bridge_domain: str = ""
    gateway_ip: str = Field(..., description="Anycast-Gateway mit Präfix, z.B. 10.10.30.1/24")
    zone_name: str = ""
    pbr_enabled: bool = False
    pbr_component_id: int | None = None
    pbr_node_ip: str = ""
    pbr_node_mac: str = ""
    pbr_service_graph: str = ""
    pbr_health_group: str = ""
    description: str = ""
    active: bool = True

    @field_validator("gateway_ip")
    @classmethod
    def check_gateway_ip(cls, v):
        import ipaddress

        v = v.strip()
        try:
            ipaddress.ip_interface(v)
        except ValueError:
            raise ValueError(f"'{v}' ist keine gültige Gateway-Adresse (erwartet z.B. 10.10.30.1/24)")
        return v

    @field_validator("pbr_node_mac")
    @classmethod
    def check_mac(cls, v):
        import re

        v = v.strip()
        if v and not re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", v):
            raise ValueError(f"'{v}' ist keine gültige MAC-Adresse")
        return v.upper()

    @model_validator(mode="after")
    def check_pbr(self):
        if self.pbr_enabled:
            if not self.pbr_component_id:
                raise ValueError("PBR aktiviert: Ziel-Firewall (Komponente) ist erforderlich")
            if not self.pbr_node_ip:
                raise ValueError("PBR aktiviert: PBR-Node-IP ist erforderlich")
        return self


class AciGatewayOut(AciGatewayCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    pbr_component_name: str | None = None


class AddressMapCreate(BaseModel):
    """Einmalige Festlegung: Regeln für diese Adresse werden auf diesen Komponenten angelegt."""

    ip: str
    vrf: str = ""
    alias: str = ""
    component_ids: list[int] = Field(..., min_length=1)

    @field_validator("ip")
    @classmethod
    def check_ip(cls, v):
        return validate_ip_entry(v)


class AddressMapOut(AddressMapCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_by: str = ""


class ResolveRequest(BaseModel):
    source: list[AddressEntry] = []
    destination: list[AddressEntry] = []
    source_zone: str = ""
    destination_zone: str = ""
    vrf: str = ""


class ResolveOut(BaseModel):
    components: list[ComponentBrief]
    unknown: list[AddressEntry]


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    full_name: str
    email: str
    role: Role
    is_active: bool = True
    totp_enabled: bool = False
    notify_email: bool = True


class UserCreate(BaseModel):
    username: str = Field(..., min_length=2, max_length=64)
    # Ohne Passwort wird ein Aktivierungslink erzeugt (Mail bzw. Link für den Admin)
    password: str | None = Field(None, min_length=8)
    full_name: str = ""
    email: str = ""
    role: Role = Role.architect


class UserUpdate(BaseModel):
    full_name: str | None = None
    email: str | None = None
    role: Role | None = None
    is_active: bool | None = None


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut
