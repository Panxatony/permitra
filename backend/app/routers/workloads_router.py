"""Workload inventory: the hosts, VMs and services rules are about, with labels.

The inventory is documentation, not policy: an architect or operations
account maintains it directly, and so does an import. What makes it matter
to the rules is the selector groups built on the labels - a label change can
move a workload into or out of a group a rule refers to, so every change here
re-synchronises those groups (see groups.py and rule_recheck.py).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from .. import groups
from ..auth import get_current_user, require_roles
from ..database import get_db
from ..messages import _
from ..models import Role, User, Workload, WorkloadKind
from ..validation import validate_ip_entry
from ..vrf import get_vrf
from .objects_router import resync_groups

router = APIRouter(prefix="/api/workloads", tags=["workloads"])


class WorkloadIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    kind: WorkloadKind = WorkloadKind.vm
    addresses: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    description: str = Field("", max_length=256)
    vrf: str = ""

    @field_validator("addresses")
    @classmethod
    def check_addresses(cls, v):
        cleaned = []
        for ip in v:
            ip = validate_ip_entry(ip)
            if ip.lower() == "any":
                raise ValueError(_("A workload cannot be 'any'"))
            cleaned.append(ip)
        return cleaned

    @field_validator("labels")
    @classmethod
    def check_labels(cls, v):
        out = {}
        for key, value in v.items():
            key, value = key.strip(), str(value).strip()
            if not key or any(ch in key for ch in " ,=!") or len(key) > 64 or len(value) > 128:
                raise ValueError(_("'{key}' is not a valid label key", key=key or "?"))
            out[key] = value
        return out

    @field_validator("name")
    @classmethod
    def single_line(cls, v):
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in v):
            raise ValueError(_("{field} must not contain line breaks or control characters", field="name"))
        return v.strip()


class WorkloadOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    kind: WorkloadKind
    addresses: list[str]
    labels: dict[str, str]
    description: str
    source: str
    vrf_id: int
    rules_updated: list[str] = []


def _out(w: Workload, updated: list[str] | None = None) -> WorkloadOut:
    out = WorkloadOut.model_validate(w)
    out.rules_updated = updated or []
    return out


def _get(db: Session, workload_id: int) -> Workload:
    w = db.get(Workload, workload_id)
    if not w:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Workload not found"))
    return w


@router.get("", response_model=list[WorkloadOut])
def list_workloads(
    label: str | None = Query(None, description="Selector, e.g. app=shop,tier=web"),
    q: str | None = Query(None, description="Substring of name, address or label"),
    vrf: str | None = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    query = db.query(Workload)
    if vrf:
        query = query.filter(Workload.vrf_id == get_vrf(db, vrf).id)
    items = query.order_by(Workload.name).all()
    if label:
        items = [w for w in items if groups.selector_matches(w.labels, label)]
    if q:
        needle = q.lower()
        items = [w for w in items
                 if needle in w.name.lower()
                 or any(needle in ip for ip in w.addresses or [])
                 or any(needle in f"{k}={v}".lower() for k, v in (w.labels or {}).items())]
    return items


@router.post("", response_model=WorkloadOut, status_code=201)
def create_workload(
    payload: WorkloadIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    vrf = get_vrf(db, payload.vrf or None)
    if db.query(Workload).filter(Workload.vrf_id == vrf.id, Workload.name.ilike(payload.name)).first():
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("Workload '{name}' already exists", name=payload.name))
    w = Workload(vrf_id=vrf.id, name=payload.name, kind=payload.kind, addresses=payload.addresses,
                 labels=payload.labels, description=payload.description, source="manual")
    db.add(w)
    db.flush()
    affected = groups.groups_affected_by_labels(db, vrf.id, None, w.labels)
    updated = resync_groups(db, affected, user.username, reset_review=False)
    db.commit()
    db.refresh(w)
    return _out(w, updated)


@router.put("/{workload_id}", response_model=WorkloadOut)
def update_workload(
    workload_id: int,
    payload: WorkloadIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    w = _get(db, workload_id)
    duplicate = (db.query(Workload)
                   .filter(Workload.vrf_id == w.vrf_id, Workload.name.ilike(payload.name),
                           Workload.id != w.id).first())
    if duplicate:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("Workload '{name}' already exists", name=payload.name))
    before_labels, before_name = dict(w.labels or {}), w.name
    affected = groups.groups_affected_by_labels(db, w.vrf_id, before_labels, payload.labels)
    affected |= groups.groups_listing_workload(db, w.vrf_id, before_name)
    w.name, w.kind, w.addresses = payload.name, payload.kind, payload.addresses
    w.labels, w.description = payload.labels, payload.description
    db.flush()
    affected |= groups.groups_listing_workload(db, w.vrf_id, w.name)
    updated = resync_groups(db, affected, user.username, reset_review=False)
    db.commit()
    db.refresh(w)
    return _out(w, updated)


@router.delete("/{workload_id}", status_code=204)
def delete_workload(
    workload_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    w = _get(db, workload_id)
    affected = groups.groups_affected_by_labels(db, w.vrf_id, w.labels, None)
    affected |= groups.groups_listing_workload(db, w.vrf_id, w.name)
    db.delete(w)
    db.flush()
    resync_groups(db, affected, user.username, reset_review=False)
    db.commit()
