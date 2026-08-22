"""Neubewertung nach dem Umhängen eines Netzes (Audit-Befund H6).

Regeln speichern Quell- und Ziel-Zone als abgeleitete Felder. Wird ein Netz in
eine andere Zone umgehängt, ändert sich die Zonen-Beziehung bestehender Regeln,
ohne dass die Regel selbst angefasst wurde: Aus einer intra-zonalen Regel kann
unbemerkt ein Zonenübergang werden – und der wurde weder neu bewertet noch
angezeigt.

Geforderte Fachlogik: Nach der Umhängung werden alle betroffenen Regeln neu
bewertet. Ergibt sich dadurch Allow → Block, gehen sie in den Review und werden
zur Löschung vorgeschlagen. Die Freigabe bedeutet dann die Löschungsfreigabe –
die Regel wird deaktiviert und je Komponente auf "zu löschen" gesetzt.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import (
    ComponentType,
    Rule,
    RuleAction,
    RuleStatus,
    Role,
    SecurityComponent,
    User,
    Vrf,
    Zone,
    ZoneNetwork,
    ZonePolicy,
    ZonePolicyType,
)
from app.routers.zones_router import (
    _apply_reassessment,
    _preview_network_move,
    reassess_after_network_move,
)


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Vrf(id=1, name="IT"))
    s.add(SecurityComponent(id=1, name="FW-BER", type=ComponentType.juniper))
    s.add(SecurityComponent(id=2, name="ACI-FFM", type=ComponentType.aci))
    s.add(Zone(id=1, code="Z010", name="DEV", sort_order=10))
    s.add(Zone(id=2, code="Z020", name="PROD", sort_order=20))
    s.add(Zone(id=3, code="Z030", name="TEST", sort_order=30))
    # Beide Netze liegen zunächst in DEV -> die Regel ist intra-zonal
    s.add(ZoneNetwork(id=1, zone_id=1, vrf_id=1, cidr="10.0.1.0/24"))
    s.add(ZoneNetwork(id=2, zone_id=1, vrf_id=1, cidr="10.0.2.0/24"))
    s.commit()
    yield s
    s.close()


def set_policy(db, von: int, nach: int, policy: ZonePolicyType):
    db.add(ZonePolicy(from_zone_id=von, to_zone_id=nach, policy=policy))
    db.commit()


def make_rule(db, rule_id="SR00001", components=(1,), src="10.0.1.5", dst="10.0.2.7",
              status=RuleStatus.approved):
    comps = [db.get(SecurityComponent, c) for c in components]
    r = Rule(
        rule_id=rule_id, vrf_id=1, name=rule_id, components=comps,
        source=[{"ip": src, "alias": ""}], destination=[{"ip": dst, "alias": ""}],
        services=[{"protocol": "TCP", "port": "443"}], action=RuleAction.permit,
        status=status, source_zone="Z010", destination_zone="Z010",
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def approver():
    """Der Approver, der die Netz-Umhängung genehmigt hat."""
    return User(username="appr", role=Role.change_approver, is_active=True)


def zweiter_approver():
    """Vier-Augen: die Löschung gibt jemand anderes frei als derjenige, der
    den Löschvorschlag durch die Umhängung ausgelöst hat."""
    return User(username="appr2", role=Role.change_approver, is_active=True)


def move(db, network_id: int, ziel_zone_id: int):
    """Hängt ein Netz um (wie die genehmigte Änderung es tut)."""
    net = db.get(ZoneNetwork, network_id)
    net.zone_id = ziel_zone_id
    db.flush()
    return net


# ---------- Vorschau vor der Entscheidung ----------

def test_preview_shows_consequences_without_changing_anything(db):
    """Die Approver müssen die Folgen kennen, BEVOR sie zustimmen."""
    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db)

    vorschau = _preview_network_move(db, db.get(ZoneNetwork, 2), db.get(Zone, 2), "10.0.2.0/24")

    assert len(vorschau) == 1
    eintrag = vorschau[0]
    assert eintrag["rule_id"] == "SR00001"
    assert eintrag["to_zones"] == ["Z010", "Z020"]
    assert eintrag["admissible"] is False
    # Nichts wurde angefasst
    db.refresh(rule)
    assert rule.destination_zone == "Z010" and rule.status == RuleStatus.approved
    assert db.get(ZoneNetwork, 2).zone_id == 1


def test_unrelated_rules_are_not_affected(db):
    make_rule(db, "SR00001")
    # Regel in einem ganz anderen Netz
    other = Rule(rule_id="SR00002", vrf_id=1, name="andere",
                 source=[{"ip": "192.168.5.5", "alias": ""}],
                 destination=[{"ip": "192.168.5.6", "alias": ""}],
                 services=[{"protocol": "TCP", "port": "443"}],
                 action=RuleAction.permit, status=RuleStatus.approved)
    db.add(other)
    db.commit()

    vorschau = _preview_network_move(db, db.get(ZoneNetwork, 2), db.get(Zone, 2), "10.0.2.0/24")
    assert {e["rule_id"] for e in vorschau} == {"SR00001"}


def test_wider_rule_network_is_not_touched(db):
    """Ein weiter gefasstes Regel-Netz bezieht seine Zone anderswoher."""
    db.add(ZoneNetwork(id=3, zone_id=1, vrf_id=1, cidr="10.0.0.0/16"))
    db.commit()
    make_rule(db, "SR00003", src="10.0.0.0/16", dst="10.0.0.0/16")

    vorschau = _preview_network_move(db, db.get(ZoneNetwork, 2), db.get(Zone, 2), "10.0.2.0/24")
    assert "SR00003" not in {e["rule_id"] for e in vorschau}


# ---------- Neubewertung nach der Umhängung ----------

def test_rule_becomes_inadmissible_and_is_proposed_for_removal(db):
    """Der Kern: Allow (intra-zonal) wird durch die Umhängung zu Block."""
    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db)

    net = move(db, 2, 2)                       # 10.0.2.0/24 nach PROD
    protokoll = _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()
    db.refresh(rule)

    assert rule.status == RuleStatus.in_review, "Regel muss in den Review"
    assert rule.removal_reason, "Regel muss zur Löschung vorgeschlagen sein"
    assert rule.removal_reason.startswith("Z010 → Z020"), rule.removal_reason
    assert "Block" in rule.removal_reason
    assert rule.source_zone == "Z010" and rule.destination_zone == "Z020"
    assert protokoll and protokoll[0]["admissible"] is False


def test_still_allowed_rule_only_gets_its_zones_updated(db):
    """Bleibt die Beziehung erlaubt, wird nur nachgezogen – kein Review."""
    set_policy(db, 1, 2, ZonePolicyType.allow_only)
    rule = make_rule(db)

    net = move(db, 2, 2)
    _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()
    db.refresh(rule)

    assert rule.status == RuleStatus.approved
    assert rule.removal_reason == ""
    assert rule.destination_zone == "Z020", "Zonen müssen nachgezogen werden"


def test_cross_zone_without_firewall_is_inadmissible(db):
    """Zonenübergang nur über ACI ist laut BSI unzulässig – das schlägt in der
    reinen Matrix-Prüfung nicht durch und muss hier greifen."""
    set_policy(db, 1, 2, ZonePolicyType.allow_only)
    rule = make_rule(db, components=(2,))      # nur ACI

    net = move(db, 2, 2)
    _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()
    db.refresh(rule)

    assert rule.status == RuleStatus.in_review
    assert "Firewall" in rule.removal_reason


def test_rule_side_spanning_two_zones_is_inadmissible(db):
    """Nach der Umhängung umfasst die Zielseite zwei Zonen – die Regel muss
    aufgeteilt werden und ist so nicht haltbar."""
    set_policy(db, 1, 2, ZonePolicyType.allow_only)
    rule = make_rule(db, dst="10.0.2.7")
    rule.destination = [{"ip": "10.0.1.9", "alias": ""}, {"ip": "10.0.2.7", "alias": ""}]
    db.commit()

    net = move(db, 2, 2)
    _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()
    db.refresh(rule)

    assert rule.status == RuleStatus.in_review
    assert "mehrere Zonen" in rule.removal_reason


def test_history_and_comment_record_the_reason(db):
    """Der Vorgang muss nachvollziehbar sein – Versionseintrag und Kommentar."""
    from app.models import Comment, RuleVersion

    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db)
    vorher = rule.version

    net = move(db, 2, 2)
    _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()
    db.refresh(rule)

    assert rule.version == vorher + 1
    version = db.query(RuleVersion).filter(RuleVersion.rule_pk == rule.id,
                                           RuleVersion.version == rule.version).one()
    assert "umgehängt" in version.change_note
    kommentar = db.query(Comment).filter(Comment.rule_pk == rule.id).one()
    assert "abc12345" in kommentar.text


def test_draft_rules_are_reassessed_too(db):
    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db, status=RuleStatus.draft)

    net = move(db, 2, 2)
    _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()
    db.refresh(rule)
    assert rule.removal_reason and rule.status == RuleStatus.in_review


def test_deleted_rules_are_ignored(db):
    from app.models import utcnow

    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db)
    rule.deleted_at = utcnow()
    db.commit()

    net = move(db, 2, 2)
    assert _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455") == []


# ---------- Der Review führt zur Löschung ----------

def test_approving_a_proposed_rule_approves_its_removal(db):
    """"Freigeben" heißt bei einer zur Löschung vorgeschlagenen Regel: Löschung
    freigegeben – deaktivieren und auf den Komponenten zurückbauen."""
    from app.routers.rules_router import _decide
    from app.schemas import ReviewDecision

    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db)
    net = move(db, 2, 2)
    _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()

    _decide(db, "SR00001", zweiter_approver(), ReviewDecision(comment="geprüft"),
            RuleStatus.approved, "Freigabe")
    db.refresh(rule)

    assert rule.status == RuleStatus.deactivated
    assert rule.impl_status.get("FW-BER") == "zu löschen"
    assert rule.removal_reason == "", "der Vorschlag ist entschieden"


def test_reworking_the_rule_clears_the_proposal(db):
    """Wird die Regel überarbeitet und besteht die Prüfungen, ist der
    Löschvorschlag gegenstandslos."""
    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db)
    net = move(db, 2, 2)
    _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()
    assert rule.removal_reason

    # Netz zurück nach DEV holen und erneut bewerten
    move(db, 2, 1)
    _apply_reassessment(db, db.get(ZoneNetwork, 2), approver(), "def67890-9f3e-4c21-b7aa-1122334455")
    db.commit()
    db.refresh(rule)
    assert rule.removal_reason == ""
    assert rule.destination_zone == "Z010"


def test_reassessment_is_idempotent(db):
    """Ein zweiter Durchlauf ohne Änderung darf nichts weiter anfassen."""
    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db)
    net = move(db, 2, 2)
    _apply_reassessment(db, net, approver(), "abc12345-9f3e-4c21-b7aa-1122334455")
    db.commit()
    stand = rule.version

    zweitlauf = reassess_after_network_move(db, net)
    assert all(not e["zones_changed"] for e in zweitlauf)
    db.refresh(rule)
    assert rule.version == stand


# ---------- Verdrahtung: läuft die Neubewertung wirklich bei der Freigabe? ----------

def test_reassessment_runs_through_the_real_approval_flow(db):
    """Der wichtigste Test: Die Neubewertung muss im echten Freigabe-Ablauf
    ausgelöst werden, nicht nur als Funktion existieren. Ohne diesen Test
    bestünde die ganze Datei auch dann, wenn die Verdrahtung fehlte."""
    from app.models import ZonePolicyChange
    from app.routers.zones_router import _create_batch, _decide_change

    set_policy(db, 1, 2, ZonePolicyType.block_all)
    rule = make_rule(db)

    architekt = User(username="alex", role=Role.architect, is_active=True)
    _create_batch(db, architekt, [{
        "type": "net_update", "network_id": 2,
        "cidr": "10.0.2.0/24", "zone": "PROD",
    }], "Netz wandert nach PROD")
    change = db.query(ZonePolicyChange).filter(ZonePolicyChange.status == "pending").first()

    _decide_change(db, change.id, approver(), True, "")
    db.refresh(rule)
    assert rule.status == RuleStatus.approved, "vor der zweiten Freigabe darf nichts passieren"

    ergebnis = _decide_change(db, change.id, zweiter_approver(), True, "")
    db.refresh(rule)

    assert db.get(ZoneNetwork, 2).zone_id == 2, "Umhängung wurde angewendet"
    assert rule.status == RuleStatus.in_review
    assert rule.removal_reason
    assert "zur Löschung" in (ergebnis.get("detail") or ""), ergebnis
    assert any(e["rule_id"] == "SR00001" and not e["admissible"]
               for e in ergebnis.get("reassessed", []))


def test_preview_is_offered_on_the_pending_request(db):
    """Die Auswirkungsanalyse muss am offenen Antrag hängen, damit die Approver
    sie sehen – nicht erst nach der Entscheidung."""
    from app.models import ZonePolicyChange
    from app.routers.zones_router import _create_batch, list_changes

    set_policy(db, 1, 2, ZonePolicyType.block_all)
    make_rule(db)
    architekt = User(username="alex", role=Role.architect, is_active=True)
    _create_batch(db, architekt, [{
        "type": "net_update", "network_id": 2,
        "cidr": "10.0.2.0/24", "zone": "PROD",
    }], "")

    eintraege = list_changes(db=db, _=approver())
    offen = [e for e in eintraege if e["status"] == "pending"][0]
    assert offen["affected_count"] == 1
    assert offen["removal_count"] == 1
    assert offen["affected_rules"][0]["rule_id"] == "SR00001"
    assert offen["affected_rules"][0]["admissible"] is False
    # und der Antrag ist noch nicht angewendet
    assert db.get(ZoneNetwork, 2).zone_id == 1
