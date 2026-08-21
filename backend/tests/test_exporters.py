"""Tests für Validierung, Konflikt-Erkennung und die drei Geräte-Exporter."""
import pytest

from app.conflicts import find_conflicts
from app.exporters import aci, checkpoint, generic, juniper
from app.models import ComponentType, Rule, RuleAction, RuleStatus, SecurityComponent
from app.validation import validate_ip_entry, validate_service


def demo_components() -> list[SecurityComponent]:
    return [
        SecurityComponent(id=1, name="FW-Cluster-BER", type=ComponentType.juniper),
        SecurityComponent(id=2, name="FW-Cluster-FFM", type=ComponentType.checkpoint),
        SecurityComponent(id=3, name="ACI-Fabric-FFM", type=ComponentType.aci),
    ]


def make_rule(**overrides) -> Rule:
    defaults = dict(
        id=1,
        rule_id="SR0900",
        name="HTTPS-Webserver",
        application="Control",
        components=demo_components(),
        source_zone="trust",
        destination_zone="untrust",
        source=[{"ip": "10.0.1.0/24", "alias": ""}],
        destination=[{"ip": "192.168.1.0/24", "alias": ""}],
        services=[{"protocol": "TCP", "port": "443"}],
        action=RuleAction.permit,
        justification="Erlaubt HTTPS-Verkehr für Webserver",
        change_id="CHN0001000",
        status=RuleStatus.approved,
        impl_status={},
    )
    defaults.update(overrides)
    rule = Rule(**defaults)
    return rule


def test_validate_service():
    validate_service("TCP", "443")
    validate_service("TCP/UDP", "53")
    validate_service("ICMP", "")
    validate_service("TCP", "8000-8080")
    with pytest.raises(ValueError):
        validate_service("TCP", "70000")
    with pytest.raises(ValueError):
        validate_service("XXX", "80")
    with pytest.raises(ValueError):
        validate_service("TCP", "")


def test_validate_ip_entry():
    assert validate_ip_entry("10.0.1.0/24") == "10.0.1.0/24"
    assert validate_ip_entry("10.40.72.5") == "10.40.72.5"
    assert validate_ip_entry("2a0f:2687:9::/64") == "2a0f:2687:9::/64"
    assert validate_ip_entry("ANY") == "any"
    with pytest.raises(ValueError):
        validate_ip_entry("10.0.1.999/24")
    with pytest.raises(ValueError):
        validate_ip_entry("host.example.de")  # Hostnamen gehören in den Alias
    with pytest.raises(ValueError):
        validate_ip_entry("")


def test_juniper_export():
    out = juniper.export([make_rule()])
    assert "set security zones security-zone trust address-book address net-10.0.1.0-24 10.0.1.0/24" in out
    assert "set applications application tcp-443 protocol tcp" in out
    assert "set applications application tcp-443 destination-port 443" in out
    assert (
        "set security policies from-zone trust to-zone untrust policy HTTPS-Webserver"
        " match source-address net-10.0.1.0-24" in out
    )
    assert "then permit" in out


def test_juniper_multi_service_and_any():
    rule = make_rule(
        source=[{"ip": "any", "alias": "Internet"}],
        services=[{"protocol": "TCP", "port": "22/443"}, {"protocol": "ICMP", "port": ""}],
    )
    out = juniper.export([rule])
    assert "match source-address any" in out
    assert "match application tcp-22" in out
    assert "match application tcp-443" in out
    assert "match application junos-icmp-all" in out


def test_checkpoint_export():
    out_json = checkpoint.export_api_json([make_rule()])
    assert '"type": "network"' in out_json
    assert '"subnet": "10.0.1.0"' in out_json
    assert '"action": "Accept"' in out_json
    out_cli = checkpoint.export_cli([make_rule()])
    assert "mgmt_cli add network" in out_cli
    assert "mgmt_cli add access-rule" in out_cli
    assert "mgmt_cli publish" in out_cli


def test_checkpoint_host_object():
    # Alias wird zum Objektnamen, die IP zum Host-Objekt
    rule = make_rule(destination=[{"ip": "10.40.72.5", "alias": "web01.example.de"}])
    out = checkpoint.export_api_json([rule])
    assert '"type": "host"' in out
    assert '"ip-address": "10.40.72.5"' in out
    assert '"name": "web01.example.de"' in out


def test_aci_export_legacy_fallback():
    # Ohne DB/EPG-Zuordnung: Einzel-Contract-Fallback je Regel
    out_json = aci.export_json([make_rule()])
    assert '"fvTenant"' in out_json
    assert '"vzBrCP"' in out_json
    assert 'con-SR0900' in out_json
    assert '"dFromPort": "443"' in out_json
    out_yaml = aci.export_yaml([make_rule()])
    assert "legacy_rules_ohne_epg:" in out_yaml
    assert "SR0900" in out_yaml


def test_generic_csv():
    out = generic.export_csv([make_rule()])
    assert out.splitlines()[0].startswith("Rule-ID;Application")
    assert "SR0900" in out


def test_conflict_detection():
    a = make_rule()
    duplicate = make_rule(id=2, rule_id="SR0901")
    overlap = make_rule(
        id=3, rule_id="SR0902", source=[{"ip": "10.0.1.128/25", "alias": ""}],
        services=[{"protocol": "TCP", "port": "400-500"}],
    )
    unrelated = make_rule(
        id=4, rule_id="SR0903",
        source=[{"ip": "172.16.0.0/24", "alias": ""}],
        destination=[{"ip": "172.17.0.0/24", "alias": ""}],
    )
    deny = make_rule(id=5, rule_id="SR0904", action=RuleAction.deny)

    conflicts = find_conflicts(a, [duplicate, overlap, unrelated, deny])
    kinds = {c["other_rule_id"]: c["kind"] for c in conflicts}
    assert kinds["SR0901"] == "duplicate"
    assert kinds["SR0902"] == "overlap"
    assert kinds["SR0904"] == "shadowing"
    assert "SR0903" not in kinds


def test_host_firewall_exports():
    from app.exporters import hostfw

    rule = make_rule(
        source=[{"ip": "10.10.20.0/24", "alias": "NET-VPN"}],
        destination=[{"ip": "10.10.80.10", "alias": "jump01"}],
        services=[{"protocol": "TCP", "port": "22"}, {"protocol": "ICMP", "port": ""}],
    )
    other = make_rule(id=2, rule_id="SR0901", destination=[{"ip": "10.10.99.5", "alias": ""}])
    draft = make_rule(id=3, rule_id="SR0902", status=RuleStatus.draft)

    content, used = hostfw.export("debian", "10.10.80.10", [rule, other, draft])
    assert used == ["SR0900"]  # nur freigegebene Regel mit passendem Ziel
    assert "tcp dport 22 accept" in content and "10.10.20.0/24" in content
    assert "policy drop" in content

    content, _ = hostfw.export("redhat", "10.10.80.10", [rule])
    assert "firewall-cmd --permanent --add-rich-rule=" in content
    assert 'port port="22" protocol="tcp"' in content and "firewall-cmd --reload" in content

    content, _ = hostfw.export("sles", "10.10.80.10", [rule])
    assert "iptables -A INPUT -s 10.10.20.0/24 -p tcp --dport 22" in content
    assert "iptables -P INPUT DROP" in content

    # Netz-Ziel deckt Host ab (Containment)
    net_rule = make_rule(id=4, rule_id="SR0903",
                         destination=[{"ip": "10.10.80.0/24", "alias": "NET-MGMT"}])
    _, used = hostfw.export("debian", "10.10.80.10", [net_rule])
    assert used == ["SR0903"]
