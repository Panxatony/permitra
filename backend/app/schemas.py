from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .domain_values import PAP_LEVELS, PROTECTION_LEVELS
from .messages import _, render
from .models import ComponentType, Role, RuleAction, RuleLogging, RuleStatus, ZonePolicyType
from .validation import validate_ip_entry, validate_service

DATE_LABELS = {"valid_from": "Valid from", "valid_until": "Valid until"}


def parse_iso_date(value: str | None, field: str) -> str | None:
    """Validates a date field as an ISO date (YYYY-MM-DD) and returns it
    normalised; empty input becomes None.

    Without this check a value like '2020-02-30' would slip into the database
    unnoticed: the SQL comparison is purely character based and lets it pass,
    and only date.fromisoformat() in the expiry logic crashes over it – taking
    the dashboard, the expiry list and the daily job down for ALL users."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    label = _(DATE_LABELS.get(field, field))
    try:
        return date.fromisoformat(text).isoformat()
    except ValueError as exc:
        raise ValueError(
            _("{label}: '{text}' is not a valid date – expected YYYY-MM-DD, e.g. 2027-03-31",
              label=label, text=text)
        ) from exc


class Service(BaseModel):
    protocol: str = Field(..., description="TCP, UDP, TCP/UDP, ICMP or ANY")
    port: str = Field("", description='e.g. "443", "8000-8080", "any"; empty for ICMP')

    @model_validator(mode="after")
    def check(self):
        validate_service(self.protocol, self.port)
        self.protocol = self.protocol.strip().upper()
        self.port = self.port.strip().lower()
        return self


class AddressEntry(BaseModel):
    """Address entry: always an IP/network, optionally with an alias (host or network name)."""

    ip: str = Field(..., description='IP, network (CIDR) or "any"')
    alias: str = Field("", max_length=128, description="e.g. hostname for an IP, network name for a network")

    @field_validator("ip")
    @classmethod
    def check_ip(cls, v):
        return validate_ip_entry(v)

    @field_validator("alias")
    @classmethod
    def strip_alias(cls, v):
        return v.strip()


class ComponentBrief(BaseModel):
    """Short form of a security component for display on a rule."""

    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    type: ComponentType
    location: str = ""


class RuleFields(BaseModel):
    """Shared fields without validation – base for the output models.

    Output must not validate again so that leniently imported legacy data
    (Excel) can still be served.
    """

    name: str = ""
    application: str = ""
    app_id: str = ""
    vrf: str = ""              # environment/VRF of the rule
    components: list[ComponentBrief] = []      # components the rule has to be rolled out on
    platforms: list[str] = []                  # derived from the component types
    source_zone: str = ""
    destination_zone: str = ""
    source: list[dict] = []       # [{"ip": ..., "alias": ...}]
    destination: list[dict] = []
    services: list[dict] = []
    action: RuleAction = RuleAction.permit
    # What the rule logs when it matches (#37). Defaults to `detailed` because
    # that is what every export produced before this field existed, so an
    # existing rule's configuration does not change under it.
    log_level: RuleLogging = RuleLogging.detailed
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
    """Input model with plausibility checks.

    Rules are assigned to concrete components (component_ids) – the platform
    follows from their type.
    """

    name: str = ""
    application: str = ""
    app_id: str = ""
    vrf: str = ""              # environment/VRF; empty = default (first VRF)
    component_ids: list[int] = []
    source_zone: str = ""
    destination_zone: str = ""
    source: list[AddressEntry]
    destination: list[AddressEntry]
    services: list[Service]
    action: RuleAction = RuleAction.permit
    # What the rule logs when it matches (#37). Defaults to `detailed` because
    # that is what every export produced before this field existed, so an
    # existing rule's configuration does not change under it.
    log_level: RuleLogging = RuleLogging.detailed
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

    @field_validator("valid_from", "valid_until")
    @classmethod
    def check_dates(cls, v, info):
        return parse_iso_date(v, info.field_name)

    @field_validator("source", "destination")
    @classmethod
    def check_addresses(cls, v, info):
        if not v:
            raise ValueError(_("{field}: at least one address entry is required",
                               field=info.field_name))
        return v

    @field_validator("services")
    @classmethod
    def check_services(cls, v):
        if not v:
            raise ValueError(_("At least one service (protocol/port) is required"))
        return v

    @model_validator(mode="after")
    def check_validity_period(self):
        # Both values are already normalised to an ISO date here (check_dates)
        if self.valid_from and self.valid_until and self.valid_from > self.valid_until:
            raise ValueError(_("Valid until is earlier than valid from"))
        return self


class RuleCreate(RuleBase):
    """The rule ID is always assigned server-side (sequential SR number, immutable)."""


class RuleUpdate(RuleBase):
    change_note: str = ""


class EmergencyRuleCreate(RuleBase):
    """A rule that was already opened on the firewall, documented afterwards.

    The reason is mandatory and free text on purpose. A dropdown would collect
    a category; what an auditor needs a year later is what actually happened,
    and only the person who was there at three in the morning can write that.
    """

    emergency_reason: str = Field(min_length=10)

    @field_validator("emergency_reason")
    @classmethod
    def _substantial(cls, value: str) -> str:
        text = value.strip()
        if len(text) < 10:
            raise ValueError(_("Describe what happened - this is the evidence, "
                               "and a year from now it is all there will be"))
        return text


class CommentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    author: str
    text: str
    created_at: datetime


class RuleVersionOut(BaseModel):
    """One history entry, put into words as it is served.

    The entry is stored as an English template plus its values, so the language
    is decided here rather than on the day it was written - see
    messages.render(). change_values is dropped from the response: it is the
    raw material for the sentence, not a second copy of it.
    """

    model_config = ConfigDict(from_attributes=True)
    version: int
    snapshot: dict
    change_note: str
    change_values: dict | None = Field(default=None, exclude=True)
    changed_by: str
    changed_at: datetime

    @model_validator(mode="after")
    def _translate_note(self):
        self.change_note = render(self.change_note, self.change_values)
        return self


class RuleOut(RuleFields):
    model_config = ConfigDict(from_attributes=True)
    id: int
    rule_id: str
    status: RuleStatus
    version: int
    created_by: str
    created_at: datetime
    updated_at: datetime
    # Non-empty when the rule is proposed for removal (e.g. after a network was
    # moved to another zone and the relation has become inadmissible)
    removal_reason: str = ""
    # When somebody last deliberately confirmed the rule is still needed (#35).
    # The auditor's question, answered on the rule rather than through a join.
    last_confirmed_at: datetime | None = None
    last_confirmed_by: str = ""
    # A requestor handover awaiting the successor's confirmation (#requestor).
    pending_requestor: str = ""
    handover_proposed_by: str = ""
    # Emergency change (#36). declared_at is permanent - it is what keeps "how
    # often do we do this?" answerable. approval_due is non-null only while the
    # after-the-fact approval is still outstanding.
    emergency_declared_at: datetime | None = None
    emergency_declared_by: str = ""
    emergency_reason: str = ""
    emergency_approval_due: datetime | None = None


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
    # Rules with an unreadable valid-until date: the expiry check skips them and
    # they would otherwise sit around unnoticed (data quality).
    invalid: list[RuleOut] = []


class ExtendRequest(BaseModel):
    valid_until: str = Field(..., description="New valid-until date (ISO), e.g. 2027-08-20")
    comment: str = ""

    @field_validator("valid_until")
    @classmethod
    def check_date(cls, v):
        parsed = parse_iso_date(v, "valid_until")
        if parsed is None:
            raise ValueError(_("Valid until: a date is required (YYYY-MM-DD)"))
        return parsed


class CommentCreate(BaseModel):
    text: str = Field(..., min_length=1)


class ReviewDecision(BaseModel):
    comment: str = ""


class ConflictOut(BaseModel):
    rule_id: str
    other_rule_id: str
    kind: str
    detail: str


CIA_LEVELS = tuple(PROTECTION_LEVELS)


class ZoneCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    description: str = ""
    pap_level: str = Field("internal", description="BSI P-A-P classification: external | pap | internal")
    sort_order: int = 0
    code: str = Field("", max_length=8, description='Display code, e.g. "Z020"')
    owner: str = Field("", max_length=128, description="Owner (person or team)")
    cia_c: str = Field("normal", description="Protection level for confidentiality")
    cia_i: str = Field("normal", description="Protection level for integrity")
    cia_a: str = Field("normal", description="Protection level for availability")

    @field_validator("cia_c", "cia_i", "cia_a")
    @classmethod
    def check_cia(cls, v):
        v = v.strip().lower()
        if v not in CIA_LEVELS:
            raise ValueError(_("Protection level must be one of {levels}",
                               levels=", ".join(CIA_LEVELS)))
        return v

    @field_validator("pap_level")
    @classmethod
    def check_pap(cls, v):
        v = v.strip().lower()
        if v not in PAP_LEVELS:
            raise ValueError(_("pap_level must be one of {levels}",
                               levels=", ".join(PAP_LEVELS)))
        return v


class ZoneOut(ZoneCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    protection_level: str = "normal"  # maximum of C/I/A


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
    ns_tier: int = Field(100, ge=0, le=1000, description="North-south tier: 0 = northmost (closest to the internet)")
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
    gateway_ip: str = Field(..., description="Anycast gateway with prefix, e.g. 10.10.30.1/24")
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
        except ValueError as exc:
            raise ValueError(_("'{v}' is not a valid gateway address (expected e.g. 10.10.30.1/24)",
                               v=v)) from exc
        return v

    @field_validator("pbr_node_mac")
    @classmethod
    def check_mac(cls, v):
        import re

        v = v.strip()
        if v and not re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", v):
            raise ValueError(_("'{v}' is not a valid MAC address", v=v))
        return v.upper()

    @model_validator(mode="after")
    def check_pbr(self):
        if self.pbr_enabled:
            if not self.pbr_component_id:
                raise ValueError(_("PBR enabled: a target firewall (component) is required"))
            if not self.pbr_node_ip:
                raise ValueError(_("PBR enabled: the PBR node IP is required"))
        return self


class AciGatewayOut(AciGatewayCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    pbr_component_name: str | None = None


class AddressMapCreate(BaseModel):
    """One-time decision: rules for this address are created on these components."""

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
    services: list[Service] = []   # for the live risk assessment
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
    # The primary role, for the badge; `roles` is what the account may actually do.
    role: Role
    roles: list[Role] = []
    is_active: bool = True
    totp_enabled: bool = False
    notify_email: bool = True


class UserCreate(BaseModel):
    username: str = Field(..., min_length=2, max_length=64)
    # Without a password an activation link is generated (mail or link for the admin)
    password: str | None = Field(None, min_length=8)
    full_name: str = ""
    email: str = ""
    # `roles` is authoritative when given; `role` remains accepted so an older
    # client (or a script) that sends a single role keeps working.
    role: Role = Role.architect
    roles: list[Role] | None = None


class UserUpdate(BaseModel):
    full_name: str | None = None
    email: str | None = None
    role: Role | None = None
    roles: list[Role] | None = None
    is_active: bool | None = None


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth2 token type literal, not a secret
    user: UserOut
