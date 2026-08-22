from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from .. import audit
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..exporters import aci, aerleon_export, checkpoint, generic, hostfw, juniper
from ..validation import parse_network
from ..models import Rule, RuleStatus, User

router = APIRouter(prefix="/api/export", tags=["export"])

FORMATS = {
    "csv": ("text/csv", generic.export_csv, "regeln.csv"),
    "json": ("application/json", generic.export_json, "regeln.json"),
    "juniper": ("text/plain", juniper.export, "juniper-srx.conf"),
    "checkpoint-cli": ("text/x-shellscript", checkpoint.export_cli, "checkpoint-mgmt-cli.sh"),
    "checkpoint-api": ("application/json", checkpoint.export_api_json, "checkpoint-api.json"),
    "aci-json": ("application/json", aci.export_json, "aci-apic.json"),
    "aci-yaml": ("application/yaml", aci.export_yaml, "aci-contracts.yaml"),
}


@router.get("/formats")
def formats(_: User = Depends(get_current_user)):
    return [
        {"key": key, "filename": filename, "media_type": media}
        for key, (media, _fn, filename) in FORMATS.items()
    ]


@router.get("/aerleon-targets")
def aerleon_targets(_: User = Depends(get_current_user)):
    """Verfügbare Capirca-/Aerleon-Ziel-Plattformen."""
    return [
        {"key": key, "label": label, "zone_based": key in aerleon_export.ZONE_BASED}
        for key, (_tpl, label) in aerleon_export.TARGETS.items()
    ] + [{"key": "policy", "label": "Capirca/Aerleon Policy (YAML)", "zone_based": False}]


@router.get("/aerleon/{target}", response_class=PlainTextResponse)
def aerleon(
    target: str,
    component_id: int | None = Query(None, description="Nur Regeln dieser Komponente"),
    only_approved: bool = Query(True, description="Nur freigegebene Regeln exportieren"),
    download: bool = False,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Capirca-/Aerleon-Export: Permitra-Regeln als native Konfiguration der
    Ziel-Plattform bzw. als Policy-YAML für bestehende Capirca-Pipelines."""
    if target != "policy" and target not in aerleon_export.TARGETS:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"Unbekanntes Ziel '{target}'. Erlaubt: policy, {', '.join(aerleon_export.TARGETS)}",
        )
    query = db.query(Rule).filter(Rule.deleted_at.is_(None))
    if only_approved:
        query = query.filter(Rule.status == RuleStatus.approved)
    rules = query.order_by(Rule.rule_id).all()
    if component_id:
        rules = [r for r in rules if any(c.id == component_id for c in r.components)]
    if not rules:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Keine passenden Regeln")
    try:
        if target == "policy":
            content = aerleon_export.export_policy_yaml(rules)
            filename = "permitra-capirca.yaml"
        else:
            content = aerleon_export.export(rules, target)
            filename = f"permitra-{target}.acl"
    except Exception as exc:  # Aerleon meldet Detailfehler als ACLGeneratorError
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"Aerleon-Generierung fehlgeschlagen: {exc}")
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return PlainTextResponse(content, media_type="text/plain", headers=headers)


@router.get("/host/{os_name}", response_class=PlainTextResponse)
def host_export(
    os_name: str,
    ip: str = Query(..., description="Ziel-IP des Servers, z.B. 10.10.80.10"),
    vrf: str | None = Query(None, description="Umgebung/VRF; leer = Default"),
    download: bool = False,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Host-Firewall-Regeln für einen Ziel-Server: alle freigegebenen permit-Regeln,
    deren Ziel die IP abdeckt, als lokale Firewall-Konfiguration (Debian/RedHat/SLES)."""
    if os_name not in hostfw.HOST_OS:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"Unbekanntes Host-OS '{os_name}'. Erlaubt: {', '.join(hostfw.HOST_OS)}",
        )
    if parse_network(ip.strip()) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"'{ip}' ist keine gültige IP-Adresse")
    from ..vrf import get_vrf

    vrf_obj = get_vrf(db, vrf)
    rules = db.query(Rule).filter(Rule.vrf_id == vrf_obj.id, Rule.deleted_at.is_(None)).order_by(Rule.rule_id).all()
    content, used = hostfw.export(os_name, ip.strip(), rules)
    if not used:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"Keine freigegebene permit-Regel hat {ip} als Ziel",
        )
    filename, _label = hostfw.HOST_OS[os_name]
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{ip.replace("/", "_")}-{filename}"'
    return PlainTextResponse(content, media_type="text/plain", headers=headers)


@router.get("/{fmt}", response_class=PlainTextResponse)
def export(
    request: Request,
    fmt: str,
    ids: str | None = Query(None, description="Kommagetrennte Rule-IDs; leer = alle passenden"),
    component_id: int | None = Query(None, description="Nur Regeln dieser Komponente exportieren"),
    app_id: str | None = Query(None, description="Nur Regeln dieser Anwendungs-ID (Report je App)"),
    only_approved: bool = Query(True, description="Nur freigegebene Regeln exportieren"),
    platform_filter: bool = Query(True, description="Nur Regeln, deren Plattform zum Format passt"),
    download: bool = False,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if fmt not in FORMATS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unbekanntes Format '{fmt}'")
    media_type, export_fn, filename = FORMATS[fmt]

    query = db.query(Rule).filter(Rule.deleted_at.is_(None))
    if ids:
        wanted = [i.strip() for i in ids.split(",") if i.strip()]
        query = query.filter(Rule.rule_id.in_(wanted))
    elif only_approved:
        query = query.filter(Rule.status == RuleStatus.approved)
    if app_id:
        query = query.filter(Rule.app_id.ilike(f"%{app_id}%"))
    rules = query.order_by(Rule.rule_id).all()

    if component_id:
        rules = [r for r in rules if any(c.id == component_id for c in r.components)]

    # Gerätespezifische Formate nur für Regeln der jeweiligen Plattform
    platform_of_fmt = {"juniper": "juniper", "checkpoint-cli": "checkpoint",
                       "checkpoint-api": "checkpoint", "aci-json": "aci", "aci-yaml": "aci"}
    if platform_filter and fmt in platform_of_fmt:
        rules = [r for r in rules if platform_of_fmt[fmt] in (r.platforms or [])]

    if not rules:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Keine passenden Regeln (Filter: nur freigegebene, passende Plattform)",
        )

    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    # ACI-Exporte brauchen DB-Zugriff (EPG-Auflösung, Filter-Katalog, PBR-Gateways)
    if fmt in ("aci-json", "aci-yaml"):
        content = aci.export_json(rules, db) if fmt == "aci-json" else aci.export_yaml(rules, db)
    else:
        content = export_fn(rules)
    audit.record(db, "export", "export.rules", actor=user.username,
                 object=fmt, detail=f"{len(rules)} Regel(n)"
                 + (f", app_id={app_id}" if app_id else ""),
                 source_ip=audit.client_ip(request))
    return PlainTextResponse(content, media_type=media_type, headers=headers)
