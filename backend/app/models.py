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
from .domain_values import IMPL_STATUSES  # noqa: F401  (re-exported for importers)


def utcnow():
    return datetime.now(timezone.utc)


def active_rules(db):
    """Base query for all rules that are NOT deleted.

    Deletion is a soft delete (`Rule.deleted_at`) so that the history is kept as
    compliance evidence. Exactly for that reason every functional query has to
    exclude deleted rules: they retain their last status (typically `approved`)
    and would otherwise keep taking effect – for instance as a supposedly
    permitting match in the path analysis, or as "missing" in the target/actual
    comparison, which would then let the rollback be undone.

    Deliberate exceptions are the guard queries run before deleting a zone or a
    VRF: there deleted rules do count, because they still reference them. Those
    places are marked as such in the code."""
    return db.query(Rule).filter(Rule.deleted_at.is_(None))


class Role(str, enum.Enum):
    architect = "architect"            # plans and requests
    operations = "operations"          # rolls out (rollout status, export, drift)
    change_approver = "change_approver"  # approves (rule reviews, matrix requests)
    admin = "admin"


class RuleStatus(str, enum.Enum):
    """draft → in_review → approved → active, plus the two ways out.

    `approved` and `active` differ in who last acted: approval is the decision
    that the rule *may* exist, active is operations' confirmation that it does
    exist on every component. Keeping them apart is what makes "approved but
    never rolled out" visible instead of indistinguishable from "in service".

    `deleted` is an end state, not a disappearance: a rule that is no longer
    needed keeps its record and stays visible. Nothing removes a rule row."""

    draft = "draft"            # being planned (architect)
    in_review = "in_review"    # submitted for review
    approved = "approved"      # approved, waiting to be rolled out
    active = "active"          # confirmed implemented on every component
    rejected = "rejected"      # rejected, back to the architect
    deactivated = "deactivated"  # rule taken out of service
    deleted = "deleted"        # no longer needed - kept, never removed


# A rule counts as in force once it is approved: it is what the components are
# supposed to carry, whether operations has confirmed the rollout yet or not.
# Exports, drift, path analysis and expiry all mean this set, not `approved`
# alone - checking for `approved` after the split would silently drop every
# rule that is actually in service.
IN_FORCE = (RuleStatus.approved, RuleStatus.active)


class RuleAction(str, enum.Enum):
    permit = "permit"
    deny = "deny"


# Rollout status per platform (matches "Status Juniper"/"Status ACI" in the Excel file)
PLATFORMS = ["juniper", "checkpoint", "aci"]


class ZonePolicyType(str, enum.Enum):
    allow_only = "allow_only"  # communication only via explicit security rules
    block_all = "block_all"    # no security rules permitted between these zones


class Vrf(Base):
    """VRF / routing context (tenant): scoping dimension for networks, address
    mappings and rules – allows overlapping IP ranges between tenants.
    The zone catalogue, the matrix and the components stay global."""

    __tablename__ = "vrfs"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # e.g. GLOBAL, KUNDE-A
    description: Mapped[str] = mapped_column(Text, default="")


# Attachment of a security zone to its firewall clusters (maintained explicitly)
zone_components = Table(
    "zone_components",
    Base.metadata,
    Column("zone_id", ForeignKey("zones.id", ondelete="CASCADE"), primary_key=True),
    Column("component_id", ForeignKey("security_components.id", ondelete="CASCADE"), primary_key=True),
)


class Zone(Base):
    __tablename__ = "zones"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # e.g. D-PRD
    description: Mapped[str] = mapped_column(Text, default="")
    # BSI P-A-P classification: "external" (north of the P-A-P), "pap" (inside the
    # P-A-P layer, e.g. DMZ), "internal" (below the P-A-P structure)
    pap_level: Mapped[str] = mapped_column(String(16), default="internal")
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    # Display identifier, e.g. "Z020" -> shown as "Z020-AUDIT". The internal name
    # stays authoritative (rules, matrix and resolution reference the name).
    code: Mapped[str] = mapped_column(String(8), default="")
    # BSI documentation: owner and protection level per security objective (CIA),
    # each "normal" | "high" | "very high"; overall level = maximum principle
    owner: Mapped[str] = mapped_column(String(128), default="")
    cia_c: Mapped[str] = mapped_column(String(16), default="normal")  # confidentiality
    cia_i: Mapped[str] = mapped_column(String(16), default="normal")  # integrity
    cia_a: Mapped[str] = mapped_column(String(16), default="normal")  # availability

    @property
    def protection_level(self) -> str:
        order = {"normal": 0, "high": 1, "very high": 2}
        return max((self.cia_c, self.cia_i, self.cia_a),
                   key=lambda v: order.get(v, 0))

    # "Attached to": firewall clusters through which this zone is reachable
    components: Mapped[list["SecurityComponent"]] = relationship(secondary=zone_components)
    networks: Mapped[list["ZoneNetwork"]] = relationship(
        back_populates="zone", cascade="all, delete-orphan", order_by="ZoneNetwork.cidr"
    )


class ZoneNetwork(Base):
    """Network assignment: every network belongs to exactly one security zone.

    Rules derive their source/destination zone from it automatically; addresses
    from unassigned networks are rejected. Special value cidr='any' (e.g. internet)."""

    __tablename__ = "zone_networks"
    __table_args__ = (UniqueConstraint("vrf_id", "cidr"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    vrf_id: Mapped[int] = mapped_column(ForeignKey("vrfs.id", ondelete="CASCADE"), index=True)
    cidr: Mapped[str] = mapped_column(String(64), index=True)  # normalised or "any"
    zone_id: Mapped[int] = mapped_column(ForeignKey("zones.id", ondelete="CASCADE"), index=True)
    description: Mapped[str] = mapped_column(String(128), default="")
    # Origin: "manual" (UI) or an external source such as "netbox" – network
    # management itself happens in dedicated tools, Permitra owns the zone mapping
    source: Mapped[str] = mapped_column(String(32), default="manual")

    zone: Mapped[Zone] = relationship(back_populates="networks")
    vrf: Mapped[Vrf] = relationship()


class ZonePolicy(Base):
    """Zone communication matrix: defines per (from, to) whether rules are allowed.

    There is always a firewall between two zones, hence only allow/block –
    ACI is used exclusively within a single zone.
    """

    __tablename__ = "zone_policies"
    __table_args__ = (UniqueConstraint("from_zone_id", "to_zone_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    from_zone_id: Mapped[int] = mapped_column(ForeignKey("zones.id", ondelete="CASCADE"), index=True)
    to_zone_id: Mapped[int] = mapped_column(ForeignKey("zones.id", ondelete="CASCADE"), index=True)
    policy: Mapped[ZonePolicyType] = mapped_column(Enum(ZonePolicyType), default=ZonePolicyType.block_all)
    temporary: Mapped[bool] = mapped_column(default=False)  # "Temp" in the matrix
    note: Mapped[str] = mapped_column(Text, default="")

    from_zone: Mapped[Zone] = relationship(foreign_keys=[from_zone_id])
    to_zone: Mapped[Zone] = relationship(foreign_keys=[to_zone_id])


class ComponentType(str, enum.Enum):
    juniper = "juniper"
    checkpoint = "checkpoint"
    aci = "aci"


class SecurityComponent(Base):
    """Security components: firewall clusters and ACI fabrics on which rules are rolled out."""

    __tablename__ = "security_components"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)  # e.g. FW-Cluster-FFM
    type: Mapped[ComponentType] = mapped_column(Enum(ComponentType))
    location: Mapped[str] = mapped_column(String(128), default="")   # site/zone, e.g. "Zone FFM"
    mgmt_address: Mapped[str] = mapped_column(String(256), default="")  # management IP/hostname
    # North-south ordering: lower number = further north (closer to the internet)
    ns_tier: Mapped[int] = mapped_column(Integer, default=100)
    description: Mapped[str] = mapped_column(Text, default="")
    active: Mapped[bool] = mapped_column(default=True)


class ZonePolicyChange(Base):
    """Versioning of the zone communication matrix with an approval step.

    Every change is logged as a request (who/when/what) and only applied to the
    matrix after operations has approved it (four-eyes principle)."""

    __tablename__ = "zone_policy_changes"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Bulk requests: all entries of one request share a batch_id and are
    # approved/rejected together
    batch_id: Mapped[str] = mapped_column(String(36), default="", index=True)
    # "policy" = matrix cell; "zone_create" = new zone (from_zone = name,
    # new_policy = P-A-P classification); "net_add"/"net_update"/"net_delete" =
    # network assignment (from_zone = zone, to_zone = CIDR, details in extra)
    change_type: Mapped[str] = mapped_column(String(16), default="policy")
    extra: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    from_zone: Mapped[str] = mapped_column(String(64), index=True)
    to_zone: Mapped[str] = mapped_column(String(64), index=True, default="")
    old_policy: Mapped[str | None] = mapped_column(String(16), nullable=True)  # None = new
    new_policy: Mapped[str] = mapped_column(String(16))
    old_temporary: Mapped[bool] = mapped_column(default=False)
    new_temporary: Mapped[bool] = mapped_column(default=False)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending/approved/rejected
    requested_by: Mapped[str] = mapped_column(String(64), default="")
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Zone/matrix changes require TWO approvals (from different change approvers)
    first_approved_by: Mapped[str] = mapped_column(String(64), default="")
    first_approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by: Mapped[str] = mapped_column(String(64), default="")
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    comment: Mapped[str] = mapped_column(Text, default="")


class ComponentLink(Base):
    """Documented communication relation between two security components
    (undirected), e.g. "ACI-Fabric-FFM <-> FW-Cluster-FFM: PBR Service Graph".

    Normalisation: component_a_id < component_b_id (enforced on creation)."""

    __tablename__ = "component_links"
    __table_args__ = (UniqueConstraint("component_a_id", "component_b_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    component_a_id: Mapped[int] = mapped_column(
        ForeignKey("security_components.id", ondelete="CASCADE"), index=True
    )
    component_b_id: Mapped[int] = mapped_column(
        ForeignKey("security_components.id", ondelete="CASCADE"), index=True
    )
    link_type: Mapped[str] = mapped_column(String(64), default="")  # e.g. "OSPF Routing", "PBR / Service Graph"
    description: Mapped[str] = mapped_column(Text, default="")

    component_a: Mapped["SecurityComponent"] = relationship(foreign_keys=[component_a_id])
    component_b: Mapped["SecurityComponent"] = relationship(foreign_keys=[component_b_id])


class ComponentActualConfig(Base):
    """Actual configuration of a component for the target/actual comparison (drift).

    Uploaded/pasted via the API; an adapter fetching it directly from the device
    (Check Point Mgmt API, Junos, APIC) can plug in here later."""

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
    """Reusable address object: name (alias) -> IP/network.

    If the IP changes, all rule entries using that alias are updated along with it."""

    __tablename__ = "address_objects"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    ip: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text, default="")


class ServiceObject(Base):
    """Reusable service object, e.g. HTTPS = TCP/443."""

    __tablename__ = "service_objects"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    protocol: Mapped[str] = mapped_column(String(16))
    port: Mapped[str] = mapped_column(String(64), default="")
    description: Mapped[str] = mapped_column(Text, default="")


class Epg(Base):
    """Cisco ACI endpoint group: target of the EPG-based contract modelling.

    Contracts connect EPGs (not IPs) – addresses are mapped to EPGs through
    AddressEpgMap."""

    __tablename__ = "epgs"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)  # e.g. epg-prod-app
    tenant: Mapped[str] = mapped_column(String(64), default="")
    app_profile: Mapped[str] = mapped_column(String(64), default="")
    bridge_domain: Mapped[str] = mapped_column(String(64), default="")  # linked to AciGateway
    description: Mapped[str] = mapped_column(Text, default="")


class AddressEpgMap(Base):
    """Mapping address/network -> EPG (analogous to the component mapping).

    Resolution: exact match or the most specific containing network;
    ip='any' stands for vzAny (all EPGs in the VRF)."""

    __tablename__ = "address_epg_map"
    __table_args__ = (UniqueConstraint("vrf_id", "ip"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    vrf_id: Mapped[int] = mapped_column(ForeignKey("vrfs.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)  # normalised
    alias: Mapped[str] = mapped_column(String(128), default="")
    epg_id: Mapped[int] = mapped_column(ForeignKey("epgs.id", ondelete="CASCADE"), index=True)
    created_by: Mapped[str] = mapped_column(String(64), default="")

    epg: Mapped[Epg] = relationship()


class AddressComponentMap(Base):
    """Mapping address/network -> components: defines on which components rules
    for this source/destination have to be created.

    Set once by the user when a new address first appears and applied
    automatically afterwards (including single IPs contained in the network)."""

    __tablename__ = "address_component_map"
    __table_args__ = (UniqueConstraint("vrf_id", "ip"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    vrf_id: Mapped[int] = mapped_column(ForeignKey("vrfs.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)  # normalised, e.g. 10.10.30.0/24 or "any"
    alias: Mapped[str] = mapped_column(String(128), default="")
    component_ids: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AciGateway(Base):
    """Cisco ACI anycast gateways (bridge domain SVIs), optionally with a PBR redirect
    to a Check Point firewall cluster (service graph / policy-based redirect)."""

    __tablename__ = "aci_gateways"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)  # e.g. GW-PROD-APP
    tenant: Mapped[str] = mapped_column(String(64), default="")
    vrf: Mapped[str] = mapped_column(String(64), default="")
    bridge_domain: Mapped[str] = mapped_column(String(64), default="")
    gateway_ip: Mapped[str] = mapped_column(String(64))  # anycast SVI, e.g. 10.10.30.1/24
    zone_name: Mapped[str] = mapped_column(String(64), default="")  # associated security zone

    pbr_enabled: Mapped[bool] = mapped_column(default=False)
    pbr_component_id: Mapped[int | None] = mapped_column(
        ForeignKey("security_components.id", ondelete="SET NULL"), nullable=True
    )
    pbr_node_ip: Mapped[str] = mapped_column(String(64), default="")   # redirect target (FW interface)
    pbr_node_mac: Mapped[str] = mapped_column(String(32), default="")
    pbr_service_graph: Mapped[str] = mapped_column(String(128), default="")  # service graph template
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
    # Two-factor (TOTP): the secret is set during setup, it only counts once
    # enabled. Stored encrypted (see app/crypto.py) - in plaintext, read access
    # to the database would be enough to mint valid second factors. The column
    # is wider than a raw seed because ciphertext is.
    totp_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(default=False)
    # The last accepted time step. A code from this step or an earlier one is
    # refused, so a code cannot be used twice inside the tolerance window.
    totp_last_counter: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Session invalidation: tokens issued before this point in time are no longer
    # valid (set on deactivation, password change/reset)
    token_valid_from: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    # Brute-force protection: failed-attempt counter and time-based account lockout
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    # E-mail notifications (reviews, approvals, recertification); opt-out
    notify_email: Mapped[bool] = mapped_column(default=True)

    passkeys: Mapped[list["Passkey"]] = relationship(back_populates="user",
                                                    cascade="all, delete-orphan")


class Setting(Base):
    """Permitra settings (admin area), e.g. zone_matrix_default."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(256), default="")


class NetboxConfig(Base):
    """NetBox connection (single row). The API token is stored encrypted."""

    __tablename__ = "netbox_config"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(String(256), default="")
    token_enc: Mapped[str] = mapped_column(Text, default="")  # Fernet-encrypted
    verify_tls: Mapped[bool] = mapped_column(default=True)
    statuses: Mapped[str] = mapped_column(String(128), default="active,reserved")  # prefix statuses to import
    last_import_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditEvent(Base):
    """Append-only audit log for tamper-evident compliance evidence.

    Entries are written exclusively via INSERT (no UPDATE/DELETE through the
    application). Complements the version/request history with events that
    otherwise have no permanent home (deletions, later auth/admin)."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    category: Mapped[str] = mapped_column(String(24), index=True)  # rule | zone | auth | admin | export
    event: Mapped[str] = mapped_column(String(48))                 # e.g. rule.deleted
    actor: Mapped[str] = mapped_column(String(64), default="")
    object: Mapped[str] = mapped_column(String(128), default="")   # affected object (e.g. SR00042)
    detail: Mapped[str] = mapped_column(Text, default="")
    source_ip: Mapped[str] = mapped_column(String(64), default="")
    extra: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Integrity protection (hash chain, #26): hash = SHA-256 over the content of
    # this event AND the hash of its predecessor. Any later modification of an
    # event or of the ordering breaks the chain.
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64), default="", index=True)

    # Reliable SIEM delivery (durable outbox pattern, #26). These columns are
    # deliberately NOT part of the hashed content – they are mutable operational
    # metadata and may be updated without breaking the chain.
    siem_status: Mapped[str] = mapped_column(String(12), default="skipped", index=True)  # pending | sent | skipped
    siem_attempts: Mapped[int] = mapped_column(Integer, default=0)
    siem_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditCheckpoint(Base):
    """Anchors the end of the chain against later truncation.

    The hash chain detects modifications and gaps *within* the existing records.
    If the MOST RECENT entries are removed, however, the remainder stays
    internally consistent – without a fixed reference point the truncation would
    go unnoticed.

    A checkpoint therefore records how far the chain reached at a given point in
    time (last ID, count, head hash). When verifying, that state must still be
    present and unchanged. The checkpoint only develops its full effect outside
    the database: it is handed to the SIEM through the same reliable delivery
    (`delivered_at`). Whoever tampers with the database cannot reach the copy
    stored there – a comparison exposes the forgery."""

    __tablename__ = "audit_checkpoints"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_event_id: Mapped[int] = mapped_column(Integer)
    event_count: Mapped[int] = mapped_column(Integer)
    head_hash: Mapped[str] = mapped_column(String(64))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)


class RiskyPort(Base):
    """A service the risk analysis flags, maintained by administrators.

    The criteria behind a risk hint are themselves subject to review: an
    approver sees the hint before deciding, and an auditor asks by which
    standard it was raised. A list buried in the source can neither be shown
    nor adapted, so it lives here - seeded from the defaults in
    risk.DEFAULT_RISKY_PORTS on first start, and every change is recorded in
    the audit log."""

    __tablename__ = "risky_ports"

    id: Mapped[int] = mapped_column(primary_key=True)
    port: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(128))


class NetboxPrefix(Base):
    """Prefix imported from NetBox (staging). It is adopted into the zone registry
    as soon as a zone is assigned to it (adopted=True)."""

    __tablename__ = "netbox_prefixes"

    id: Mapped[int] = mapped_column(primary_key=True)
    netbox_id: Mapped[int] = mapped_column(Integer, index=True)
    cidr: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(16), default="")     # active | planned
    description: Mapped[str] = mapped_column(Text, default="")
    vrf: Mapped[str] = mapped_column(String(64), default="")
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    adopted: Mapped[bool] = mapped_column(default=False)  # adopted into the registry


class ApiToken(Base):
    """Read-only service token for automation (Ansible/Terraform).

    Only the hash is stored; the plaintext is shown exactly once on creation.
    Tokens permit read access only (GET)."""

    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    prefix: Mapped[str] = mapped_column(String(16), index=True)  # visible leading part
    token_hash: Mapped[str] = mapped_column(String(64), index=True)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(default=False)


class AuthToken(Base):
    """One-time token for activation and password reset links (only the hash is stored)."""

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
    """WebAuthn passkey of a user (passwordless sign-in)."""

    __tablename__ = "passkeys"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    credential_id: Mapped[str] = mapped_column(Text)  # base64url
    public_key: Mapped[str] = mapped_column(Text)     # base64
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(64), default="Passkey")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped["User"] = relationship(back_populates="passkeys")


# Mapping rule -> security components on which it has to be rolled out
rule_components = Table(
    "rule_components",
    Base.metadata,
    Column("rule_pk", ForeignKey("rules.id", ondelete="CASCADE"), primary_key=True),
    Column("component_id", ForeignKey("security_components.id", ondelete="CASCADE"), primary_key=True),
)


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)  # e.g. SR0855
    vrf_id: Mapped[int] = mapped_column(ForeignKey("vrfs.id", ondelete="RESTRICT"), index=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    application: Mapped[str] = mapped_column(String(128), default="", index=True)   # e.g. Control, ePA
    app_id: Mapped[str] = mapped_column(String(64), default="", index=True)   # application ID (per-app reports)
    # Concrete components (firewall cluster/ACI fabric) on which the rule has to
    # be created as a firewall rule or an ACI contract
    components: Mapped[list["SecurityComponent"]] = relationship(secondary=rule_components)

    # Text instead of String: legacy data sometimes holds multi-line zone lists
    source_zone: Mapped[str] = mapped_column(Text, default="")
    destination_zone: Mapped[str] = mapped_column(Text, default="")
    # Address entries: always an IP or network, optionally with an alias (host/network name):
    # [{"ip": "10.10.30.5", "alias": "app01.demo.local"}, {"ip": "10.10.20.0/24", "alias": "VPN-Netz"}]
    # Special value ip="any" for arbitrary sources/destinations (e.g. internet)
    source: Mapped[list] = mapped_column(JSON, default=list)
    destination: Mapped[list] = mapped_column(JSON, default=list)
    # Services: [{"protocol": "TCP", "port": "443"}, {"protocol": "ICMP", "port": ""}]
    services: Mapped[list] = mapped_column(JSON, default=list)
    action: Mapped[RuleAction] = mapped_column(Enum(RuleAction), default=RuleAction.permit)

    description: Mapped[str] = mapped_column(Text, default="")
    justification: Mapped[str] = mapped_column(Text, default="")      # "Anlass (Administrationsbedarf)"
    business_context: Mapped[str] = mapped_column(String(256), default="")  # "Fachlicher Bezug"
    info: Mapped[str] = mapped_column(Text, default="")
    requestor: Mapped[str] = mapped_column(String(128), default="")
    owner: Mapped[str] = mapped_column(String(128), default="")       # "Bearbeiter"
    change_id: Mapped[str] = mapped_column(String(128), default="")   # e.g. CHN0000273
    valid_from: Mapped[str | None] = mapped_column(String(10), nullable=True)   # ISO date
    valid_until: Mapped[str | None] = mapped_column(String(10), nullable=True)

    status: Mapped[RuleStatus] = mapped_column(Enum(RuleStatus), default=RuleStatus.draft, index=True)
    # {"juniper": "implemented", "aci": "new"} – only for platforms in `platforms`
    impl_status: Mapped[dict] = mapped_column(JSON, default=dict)

    version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    # Soft delete: rules are not removed physically so that the version history
    # (audit trail) is preserved in a tamper-evident way
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Reason why this rule is proposed for removal (empty = not proposed). Arises
    # when an approved change makes a rule inadmissible – for instance when a
    # network was moved to a different zone and the new zone relation is set to
    # block in the matrix. The rule then goes back into review; it can only be
    # approved again once the inadmissibility has been resolved.
    removal_reason: Mapped[str] = mapped_column(String(255), default="")

    @property
    def platforms(self) -> list[str]:
        """Derived from the types of the assigned components (for export/checks)."""
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
    # The English message template and the values it takes, kept apart so the
    # entry can be rendered in whatever language the instance is set to when
    # somebody reads it. A note a person typed is stored here as-is, with no
    # values. See messages.render().
    change_note: Mapped[str] = mapped_column(Text, default="")
    change_values: Mapped[dict | None] = mapped_column(JSON, nullable=True)
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
