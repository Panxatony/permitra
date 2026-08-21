"""Tests für die Capirca-/Aerleon-Anbindung (Regeln -> Policy -> native Konfiguration)."""
import pytest

from app.exporters import aerleon_export
from app.models import Rule, RuleAction, RuleStatus


def make_rule(rid, src, dst, services, action=RuleAction.permit,
              src_zone="MGMT", dst_zone="PROD-APP", name="", application=""):
    return Rule(
        rule_id=rid, vrf_id=1, name=name or rid, application=application,
        source=src, destination=dst, services=services, action=action,
        status=RuleStatus.approved, source_zone=src_zone, destination_zone=dst_zone,
    )


@pytest.fixture()
def rules():
    return [
        make_rule(
            "SR0001",
            [{"ip": "10.10.60.0/24", "alias": "NET-MGMT"}],
            [{"ip": "10.10.30.20", "alias": "app20.demo.local"}],
            [{"protocol": "TCP", "port": "443"}, {"protocol": "TCP", "port": "8000-8080"}],
            name="Admin-Zugriff",
        ),
        make_rule(
            "SR0002",
            [{"ip": "any", "alias": ""}],
            [{"ip": "10.10.10.5", "alias": "web01"}],
            [{"protocol": "TCP", "port": "443"}, {"protocol": "UDP", "port": "443"}],
            src_zone="INET", dst_zone="DMZ-WEB",
        ),
        make_rule(
            "SR0003",
            [{"ip": "10.10.60.0/24", "alias": "NET-MGMT"}],
            [{"ip": "10.10.30.21", "alias": ""}],
            [{"protocol": "ICMP", "port": ""}],
            action=RuleAction.deny,
        ),
    ]


def test_build_policy_objects_and_terms(rules):
    policy, definitions = aerleon_export.build_policy(rules, "cisco")
    # Aliasse werden zu Objektnamen, IPs ohne Alias generiert
    assert "NET_MGMT" in definitions["networks"]
    assert "APP20_DEMO_LOCAL" in definitions["networks"]
    assert definitions["networks"]["NET_10_10_30_21"]["values"][0]["address"] == "10.10.30.21/32"
    assert definitions["services"]["TCP_8000_8080"] == [{"protocol": "tcp", "port": "8000-8080"}]

    terms = policy["filters"][0]["terms"]
    by_name = {t["name"]: t for t in terms}
    # tcp:443 + udp:443 -> je Protokoll ein Term (exakte Abbildung)
    assert "sr0002-tcp" in by_name and "sr0002-udp" in by_name
    # any-Quelle: Feld weggelassen
    assert "source-address" not in by_name["sr0002-tcp"]
    # deny + icmp ohne Port
    assert by_name["sr0003"]["action"] == "deny"
    assert by_name["sr0003"]["protocol"] == "icmp"
    assert "destination-port" not in by_name["sr0003"]


def test_zone_based_target_groups_by_zone_pair(rules):
    policy, _ = aerleon_export.build_policy(rules, "srx")
    headers = [f["header"]["targets"]["srx"] for f in policy["filters"]]
    assert "from-zone MGMT to-zone PROD-APP" in headers
    assert "from-zone INET to-zone DMZ-WEB" in headers
    # SR0001 und SR0003 teilen sich das Zonen-Paar
    mgmt = next(f for f in policy["filters"]
                if f["header"]["targets"]["srx"] == "from-zone MGMT to-zone PROD-APP")
    assert {t["name"] for t in mgmt["terms"]} == {"sr0001", "sr0003"}


def test_generate_cisco_and_srx(rules):
    cisco = aerleon_export.export(rules, "cisco")
    assert "ip access-list extended permitra" in cisco
    assert "range 8000 8080" in cisco
    assert "deny icmp" in cisco

    srx = aerleon_export.export(rules, "srx")
    assert "from-zone MGMT to-zone PROD-APP" in srx
    assert "policy sr0001" in srx


def test_policy_yaml_roundtrip(rules):
    import yaml

    out = aerleon_export.export_policy_yaml(rules)
    docs = list(yaml.safe_load_all(out))
    assert len(docs) == 2
    assert "networks" in docs[0] and "services" in docs[0]
    assert docs[1]["filters"][0]["terms"]
