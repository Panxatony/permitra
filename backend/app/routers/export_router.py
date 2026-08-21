from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..exporters import aci, checkpoint, generic, hostfw, juniper
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
    rules = db.query(Rule).filter(Rule.vrf_id == vrf_obj.id).order_by(Rule.rule_id).all()
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
    fmt: str,
    ids: str | None = Query(None, description="Kommagetrennte Rule-IDs; leer = alle passenden"),
    component_id: int | None = Query(None, description="Nur Regeln dieser Komponente exportieren"),
    only_approved: bool = Query(True, description="Nur freigegebene Regeln exportieren"),
    platform_filter: bool = Query(True, description="Nur Regeln, deren Plattform zum Format passt"),
    download: bool = False,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    if fmt not in FORMATS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unbekanntes Format '{fmt}'")
    media_type, export_fn, filename = FORMATS[fmt]

    query = db.query(Rule)
    if ids:
        wanted = [i.strip() for i in ids.split(",") if i.strip()]
        query = query.filter(Rule.rule_id.in_(wanted))
    elif only_approved:
        query = query.filter(Rule.status == RuleStatus.approved)
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
    return PlainTextResponse(content, media_type=media_type, headers=headers)
