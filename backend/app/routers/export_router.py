from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from .. import audit
from ..auth import get_current_user
from ..database import get_db
from ..exporters import aci, aerleon_export, checkpoint, generic, hostfw, juniper
from ..messages import _
from ..models import IN_FORCE, Rule, User
from ..validation import parse_network

router = APIRouter(prefix="/api/export", tags=["export"])

FORMATS = {
    "csv": ("text/csv", generic.export_csv, "rules.csv"),
    "json": ("application/json", generic.export_json, "rules.json"),
    "juniper": ("text/plain", juniper.export, "juniper-srx.conf"),
    "checkpoint-cli": ("text/x-shellscript", checkpoint.export_cli, "checkpoint-mgmt-cli.sh"),
    "checkpoint-api": ("application/json", checkpoint.export_api_json, "checkpoint-api.json"),
    "aci-json": ("application/json", aci.export_json, "aci-apic.json"),
    "aci-yaml": ("application/yaml", aci.export_yaml, "aci-contracts.yaml"),
}


@router.get("/formats")
def formats(_user: User = Depends(get_current_user)):
    return [
        {"key": key, "filename": filename, "media_type": media}
        for key, (media, _fn, filename) in FORMATS.items()
    ]


@router.get("/aerleon-targets")
def aerleon_targets(_user: User = Depends(get_current_user)):
    """Available Capirca/Aerleon target platforms."""
    return [
        {"key": key, "label": label, "zone_based": key in aerleon_export.ZONE_BASED}
        for key, (_tpl, label) in aerleon_export.TARGETS.items()
    ] + [{"key": "policy", "label": "Capirca/Aerleon Policy (YAML)", "zone_based": False}]


@router.get("/aerleon/{target}", response_class=PlainTextResponse)
def aerleon(
    request: Request,
    target: str,
    component_id: int | None = Query(None, description="Only rules of this component"),
    only_approved: bool = Query(True, description="Export approved rules only"),
    download: bool = False,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Capirca/Aerleon export: Permitra rules as the target platform's native
    configuration, or as policy YAML for existing Capirca pipelines."""
    if target != "policy" and target not in aerleon_export.TARGETS:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            _("Unknown target '{target}'. Allowed: policy, {allowed}",
              target=target, allowed=", ".join(aerleon_export.TARGETS)),
        )
    query = db.query(Rule).filter(Rule.deleted_at.is_(None))
    if only_approved:
        query = query.filter(Rule.status.in_(IN_FORCE))
    rules = query.order_by(Rule.rule_id).all()
    if component_id:
        rules = [r for r in rules if any(c.id == component_id for c in r.components)]
    if not rules:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("No matching rules"))
    try:
        if target == "policy":
            content = aerleon_export.export_policy_yaml(rules)
            filename = "permitra-capirca.yaml"
        else:
            content = aerleon_export.export(rules, target)
            filename = f"permitra-{target}.acl"
    except Exception as exc:  # Aerleon reports detailed failures as ACLGeneratorError
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("Aerleon generation failed: {error}", error=exc)) from exc
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    not_approved = [r.rule_id for r in rules if r.status not in IN_FORCE]
    values = {"count": len(rules)}
    if not_approved:
        detail = "{count} rule(s), NOT approved: {rule_ids}"
        values["rule_ids"] = ", ".join(not_approved)
    else:
        detail = "{count} rule(s)"
    audit.record(db, "export", "export.rules", actor=user.username,
                 object=f"aerleon/{target}", detail=detail, detail_values=values,
                 source_ip=audit.client_ip(request))
    return PlainTextResponse(content, media_type="text/plain", headers=headers)


@router.get("/host/{os_name}", response_class=PlainTextResponse)
def host_export(
    request: Request,
    os_name: str,
    ip: str = Query(..., description="Target IP of the server, e.g. 10.10.80.10"),
    vrf: str | None = Query(None, description="Environment/VRF; empty = default"),
    download: bool = False,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Host firewall rules for one target server: every approved permit rule whose
    destination covers the IP, as a local firewall configuration (Debian/RedHat/SLES)."""
    if os_name not in hostfw.HOST_OS:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            _("Unknown host OS '{os_name}'. Allowed: {allowed}",
              os_name=os_name, allowed=", ".join(hostfw.HOST_OS)),
        )
    if parse_network(ip.strip()) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            _("'{ip}' is not a valid IP address", ip=ip))
    from ..vrf import get_vrf

    vrf_obj = get_vrf(db, vrf)
    rules = db.query(Rule).filter(Rule.vrf_id == vrf_obj.id, Rule.deleted_at.is_(None)).order_by(Rule.rule_id).all()
    content, used = hostfw.export(os_name, ip.strip(), rules)
    if not used:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            _("No approved permit rule has {ip} as its destination", ip=ip),
        )
    filename, _label = hostfw.HOST_OS[os_name]
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{ip.replace("/", "_")}-{filename}"'
    audit.record(db, "export", "export.rules", actor=user.username,
                 object=f"host/{os_name}",
                 detail="destination {ip}, {count} rule(s)",
                 detail_values={"ip": ip, "count": len(used)},
                 source_ip=audit.client_ip(request))
    return PlainTextResponse(content, media_type="text/plain", headers=headers)


@router.get("/{fmt}", response_class=PlainTextResponse)
def export(
    request: Request,
    fmt: str,
    ids: str | None = Query(None, description="Comma-separated rule IDs; empty = all matching"),
    component_id: int | None = Query(None, description="Export only rules of this component"),
    app_id: str | None = Query(None, description="Only rules of this application ID (per-app report)"),
    only_approved: bool = Query(True, description="Export approved rules only"),
    platform_filter: bool = Query(True, description="Only rules whose platform matches the format"),
    download: bool = False,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if fmt not in FORMATS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Unknown format '{fmt}'", fmt=fmt))
    media_type, export_fn, filename = FORMATS[fmt]

    query = db.query(Rule).filter(Rule.deleted_at.is_(None))
    wanted: list[str] = []
    if ids:
        wanted = [i.strip() for i in ids.split(",") if i.strip()]
        query = query.filter(Rule.rule_id.in_(wanted))
    # The status filter applies EVEN when IDs are named explicitly: an ID narrows
    # down which rules are meant – not whether their status still counts. Before,
    # ?ids= let a deactivated or expired rule be exported as a ready-to-apply
    # device configuration, and it thereby found its way back onto the firewall.
    if only_approved:
        query = query.filter(Rule.status.in_(IN_FORCE))
    if app_id:
        query = query.filter(Rule.app_id.ilike(f"%{app_id}%"))
    rules = query.order_by(Rule.rule_id).all()

    if component_id:
        rules = [r for r in rules if any(c.id == component_id for c in r.components)]

    # Device-specific formats only for rules belonging to that platform
    platform_of_fmt = {"juniper": "juniper", "checkpoint-cli": "checkpoint",
                       "checkpoint-api": "checkpoint", "aci-json": "aci", "aci-yaml": "aci"}
    if platform_filter and fmt in platform_of_fmt:
        rules = [r for r in rules if platform_of_fmt[fmt] in (r.platforms or [])]

    if not rules:
        detail = _("No matching rules (filters: approved only, matching platform)")
        if wanted and only_approved:
            # Most common case: the named rule exists but is not (yet) approved.
            # Say so, otherwise the user goes looking in entirely the wrong place.
            existing = (db.query(Rule)
                         .filter(Rule.rule_id.in_(wanted), Rule.deleted_at.is_(None))
                         .filter(Rule.status.notin_(IN_FORCE)).all())
            if existing:
                listed = ", ".join(f"{r.rule_id} ({_(r.status.value)})" for r in existing)
                detail = _("Not approved and therefore not exported: {listed}. "
                           "For a preview, turn off 'approved only' (only_approved=false).",
                           listed=listed)
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail)

    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    # ACI exports need DB access (EPG resolution, filter catalogue, PBR gateways)
    if fmt in ("aci-json", "aci-yaml"):
        content = aci.export_json(rules, db) if fmt == "aci-json" else aci.export_yaml(rules, db)
    else:
        content = export_fn(rules)
    not_approved = [r.rule_id for r in rules if r.status not in IN_FORCE]
    # Four spellings written out rather than one assembled from fragments: an
    # audit entry is stored as a template and translated when it is read, so a
    # template has to be a whole sentence. Assembling one at runtime also hides
    # it from the catalogue guard in the tests.
    values = {"count": len(rules)}
    if app_id:
        values["app_id"] = app_id
    if not_approved:
        values["rule_ids"] = ", ".join(not_approved)
    if app_id and not_approved:
        detail = "{count} rule(s), app_id={app_id}, NOT approved: {rule_ids}"
    elif app_id:
        detail = "{count} rule(s), app_id={app_id}"
    elif not_approved:
        detail = "{count} rule(s), NOT approved: {rule_ids}"
    else:
        detail = "{count} rule(s)"
    audit.record(db, "export", "export.rules", actor=user.username,
                 object=fmt, detail=detail, detail_values=values,
                 source_ip=audit.client_ip(request))
    return PlainTextResponse(content, media_type=media_type, headers=headers)
