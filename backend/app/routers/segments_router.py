"""Segments of a zone and the matrix between them.

A segment is a group that belongs to a zone (segments.py). Creating one is
documentation - "this group is a segment of this zone" - and is done
directly by an architect or operations, like a workload or a group. What
changes what rules may exist is the matrix between the segments and the
zone's intra-zone default, and those go through the same request with two
approvals as the zone matrix (zones_router._create_batch, item types
`segment_policy` and `segment_default`).
"""
from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from .. import audit, groups
from ..auth import get_current_user, require_roles
from ..database import get_db
from ..exporters.common import csv_safe
from ..messages import _
from ..models import AddressGroup, Role, Segment, SegmentPolicy, User, Zone
from ..schemas import SegmentIn, SegmentMatrixOut, SegmentOut, SegmentPolicyOut
from ..segments import rules_touching_segment, zone_segments
from ..zone_check import find_zone, resolve_zone_for_entries, zone_ref

router = APIRouter(prefix="/api/zones", tags=["segments"])


def _zone(db: Session, name: str) -> Zone:
    zone = find_zone(db, name)
    if not zone:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Zone '{name}' not found", name=name))
    return zone


def _segment(db: Session, zone: Zone, segment_id: int) -> Segment:
    seg = db.get(Segment, segment_id)
    if not seg or seg.zone_id != zone.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Segment not found"))
    return seg


def _out(db: Session, seg: Segment) -> SegmentOut:
    return SegmentOut(id=seg.id, zone=zone_ref(seg.zone), name=seg.name, group=seg.group.name,
                      group_kind=seg.group.kind.value, description=seg.description,
                      member_count=len(groups.resolve_group(db, seg.group)))


def _group_in_zone(db: Session, zone: Zone, name: str):
    """The group, which has to lie inside the zone: a segment is a part of
    its zone, and a group with members elsewhere would make the zone's
    matrix speak about traffic it does not govern."""
    group = db.query(AddressGroup).filter(AddressGroup.name.ilike(name.strip())).first()
    if not group:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _("Group '{name}' does not exist", name=name))
    members = groups.resolve_group(db, group)
    if not members:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, _("Group '{name}' has no members", name=group.name))
    _resolved, unassigned, hits = resolve_zone_for_entries(db, members, group.vrf_id)
    outside = {h for h in hits if h.upper() != zone_ref(zone).upper()}
    if unassigned or outside:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            _("Group '{name}' is not entirely inside zone {zone}: {details}",
              name=group.name, zone=zone_ref(zone),
              details=", ".join([*(_("outside: ") + z for z in sorted(outside)),
                                 *(_("unassigned: ") + ip for ip in unassigned)])))
    return group


@router.get("/{name}/segments", response_model=SegmentMatrixOut)
def segment_matrix(name: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    zone = _zone(db, name)
    segments = zone_segments(db, zone)
    ids = [s.id for s in segments]
    policies = db.query(SegmentPolicy).filter(SegmentPolicy.from_segment_id.in_(ids)).all() if ids else []
    return SegmentMatrixOut(
        zone=zone_ref(zone), intra_zone_default=zone.intra_zone_default,
        segments=[_out(db, s) for s in segments],
        policies=[SegmentPolicyOut(from_segment=p.from_segment.name, to_segment=p.to_segment.name,
                                   policy=p.policy, note=p.note) for p in policies],
    )


@router.get("/{name}/segments/matrix.csv")
def segment_matrix_csv(name: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """The segment matrix as a spreadsheet: one row per source segment, one
    column per destination segment, cells Allow / Block / the default."""
    zone = _zone(db, name)
    segments = zone_segments(db, zone)
    cells = {(p.from_segment_id, p.to_segment_id): p.policy.value
             for p in db.query(SegmentPolicy).filter(
                 SegmentPolicy.from_segment_id.in_([s.id for s in segments] or [0])).all()}
    default = "Allow (default)" if (zone.intra_zone_default or "permit") == "permit" else "Block (default)"
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";")
    writer.writerow([csv_safe(f"{zone_ref(zone)} from \\ to"), *(csv_safe(s.name) for s in segments)])
    for a in segments:
        row = [csv_safe(a.name)]
        for b in segments:
            if a.id == b.id:
                row.append("-")
            else:
                cell = cells.get((a.id, b.id))
                row.append({"allow_only": "Allow", "block_all": "Block"}.get(cell, default))
        writer.writerow(row)
    return PlainTextResponse(buffer.getvalue(), media_type="text/csv", headers={
        "Content-Disposition": f'attachment; filename="segments-{zone_ref(zone)}.csv"'})


@router.post("/{name}/segments", response_model=SegmentOut, status_code=201)
def create_segment(
    name: str, payload: SegmentIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    zone = _zone(db, name)
    if any(s.name.lower() == payload.name.lower() for s in zone_segments(db, zone)):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("Segment '{name}' already exists in zone {zone}", name=payload.name, zone=zone.name))
    group = _group_in_zone(db, zone, payload.group)
    if db.query(Segment).filter(Segment.group_id == group.id).first():
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("Group '{name}' is already a segment", name=group.name))
    seg = Segment(zone_id=zone.id, group_id=group.id, name=payload.name, description=payload.description)
    db.add(seg)
    db.flush()
    audit.record(db, "admin", "segment.created", actor=user.username, object=f"{zone_ref(zone)}/{seg.name}",
                 detail="Segment {name} of zone {zone} = group {group}",
                 detail_values={"name": seg.name, "zone": zone_ref(zone), "group": group.name})
    db.commit()
    db.refresh(seg)
    return _out(db, seg)


@router.put("/{name}/segments/{segment_id}", response_model=SegmentOut)
def update_segment(
    name: str, segment_id: int, payload: SegmentIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    zone = _zone(db, name)
    seg = _segment(db, zone, segment_id)
    if any(s.name.lower() == payload.name.lower() and s.id != seg.id for s in zone_segments(db, zone)):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("Segment '{name}' already exists in zone {zone}", name=payload.name, zone=zone.name))
    if payload.group.lower() != seg.group.name.lower():
        # Swapping the group moves the segment's boundary; rules that were
        # checked against the old boundary would be out of policy unnoticed.
        used = rules_touching_segment(db, zone, seg)
        if used:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                _("Segment '{name}' is used by {count} rule(s) – the group cannot be swapped: {rule_ids}",
                                  name=seg.name, count=len(used), rule_ids=", ".join(r.rule_id for r in used[:10])))
        group = _group_in_zone(db, zone, payload.group)
        if db.query(Segment).filter(Segment.group_id == group.id, Segment.id != seg.id).first():
            raise HTTPException(status.HTTP_409_CONFLICT,
                                _("Group '{name}' is already a segment", name=group.name))
        seg.group_id = group.id
    seg.name, seg.description = payload.name, payload.description
    audit.record(db, "admin", "segment.updated", actor=user.username, object=f"{zone_ref(zone)}/{seg.name}",
                 detail="Segment {name} of zone {zone} = group {group}",
                 detail_values={"name": seg.name, "zone": zone_ref(zone), "group": payload.group})
    db.commit()
    db.refresh(seg)
    return _out(db, seg)


@router.delete("/{name}/segments/{segment_id}", status_code=204)
def delete_segment(
    name: str, segment_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.architect, Role.operations)),
):
    zone = _zone(db, name)
    seg = _segment(db, zone, segment_id)
    used = rules_touching_segment(db, zone, seg)
    if used:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            _("Segment '{name}' is used by {count} rule(s) – remove those rules first: {rule_ids}",
                              name=seg.name, count=len(used), rule_ids=", ".join(r.rule_id for r in used[:10])))
    # SQLite does not enforce the cascade unless told to; be explicit.
    db.query(SegmentPolicy).filter((SegmentPolicy.from_segment_id == seg.id)
                                   | (SegmentPolicy.to_segment_id == seg.id)).delete(synchronize_session=False)
    db.delete(seg)
    db.flush()
    if not zone_segments(db, zone):
        # A zone without segments is not segmented: its default is meaningless
        # and must not resurface as "deny" on the next segment.
        zone.intra_zone_default = None
    audit.record(db, "admin", "segment.deleted", actor=user.username, object=f"{zone_ref(zone)}/{seg.name}",
                 detail="Segment {name} of zone {zone} removed",
                 detail_values={"name": seg.name, "zone": zone_ref(zone)})
    db.commit()
