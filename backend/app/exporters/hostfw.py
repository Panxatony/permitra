"""Host firewall export: builds the local firewall rules of a server for a given
target IP from all approved permit rules whose destination covers that IP.

Formats:
  - debian:  nftables rule set (/etc/nftables.conf, Debian 10+)
  - redhat:  firewalld script with rich rules (RHEL/CentOS/Rocky)
  - sles:    iptables script (classic; SLES 15 uses firewalld -> RedHat export)

Every line carries the SR ID as a comment (traceability/drift).
"""
from ..messages import _
from ..models import IN_FORCE, Rule, RuleAction
from ..validation import parse_network
from .common import icmp_echo_only, service_ports, split_protocols

HOST_OS = {
    "debian": ("nftables.conf", "Debian (nftables)"),
    "redhat": ("firewalld-rules.sh", "RedHat (firewalld)"),
    "sles": ("iptables-rules.sh", "SLES (iptables)"),
}


def matching_rules(rules: list[Rule], target_ip: str) -> list[tuple[Rule, bool]]:
    """Approved permit rules whose destination covers the IP; flag = only via 'any'."""
    net = parse_network(target_ip)
    result = []
    for rule in rules:
        if rule.status not in IN_FORCE or rule.action != RuleAction.permit:
            continue
        direct = via_any = False
        for entry in rule.destination or []:
            ip = (entry.get("ip") or "").strip()
            if ip.lower() == "any":
                via_any = True
                continue
            entry_net = parse_network(ip)
            if entry_net and net and entry_net.version == net.version and entry_net.overlaps(net):
                direct = True
        if direct or via_any:
            result.append((rule, not direct))
    return result


def _sources(rule: Rule) -> list[str | None]:
    """Source CIDRs of the rule; None = any source ('any')."""
    sources = []
    for entry in rule.source or []:
        ip = (entry.get("ip") or "").strip()
        if not ip:
            continue
        if ip.lower() == "any":
            sources.append(None)
        else:
            net = parse_network(ip)
            if net:
                sources.append(str(net))
    return sources or [None]


def _services(rule: Rule) -> list[tuple[str, str]]:
    """[(protocol, port-or-empty)] with multi-port specifications resolved."""
    result = []
    for svc in rule.services or []:
        for proto in split_protocols(svc.get("protocol", "")):
            if proto == "icmp":
                # "ping" travels with the service so the emitters below can
                # narrow to echo-request; empty stays every ICMP type.
                result.append(("icmp", "ping" if icmp_echo_only(svc) else ""))
                continue
            ports = service_ports(svc.get("port", ""))
            if not ports:
                result.append((proto, ""))
            for port in ports:
                result.append((proto, port))
    return result


def _comment(rule: Rule) -> str:
    return f"{rule.rule_id} {rule.justification or rule.name}".strip()[:80]


def export_debian(target_ip: str, matched: list[tuple[Rule, bool]]) -> str:
    lines = [
        "#!/usr/sbin/nft -f",
        _("# Permitra host firewall for {target_ip} (Debian/nftables)", target_ip=target_ip),
        f"# Rules: {', '.join(r.rule_id for r, _ in matched)}",
        "flush ruleset",
        "table inet filter {",
        "  chain input {",
        "    type filter hook input priority 0; policy drop;",
        '    iif "lo" accept',
        "    ct state established,related accept",
        "    ip protocol icmp icmp type echo-request accept",
        "    meta l4proto ipv6-icmp accept",
    ]
    for rule, only_any in matched:
        lines.append(f"    # {_comment(rule)}{' (destination via any)' if only_any else ''}")
        for src in _sources(rule):
            saddr = ""
            if src:
                family = "ip6" if ":" in src else "ip"
                saddr = f"{family} saddr {src} "
            for proto, port in _services(rule):
                if proto == "icmp":
                    icmp_type = " icmp type echo-request" if port == "ping" else ""
                    lines.append(f"    {saddr}ip protocol icmp{icmp_type} accept "
                                 f"comment \"{rule.rule_id}\"")
                    continue
                dport = f" dport {port.replace('/', '-')}" if port else ""
                lines.append(f"    {saddr}{proto}{dport} accept comment \"{rule.rule_id}\"")
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


def export_redhat(target_ip: str, matched: list[tuple[Rule, bool]]) -> str:
    lines = [
        "#!/bin/bash",
        _("# Permitra host firewall for {target_ip} (RHEL/firewalld, rich rules)", target_ip=target_ip),
        f"# Rules: {', '.join(r.rule_id for r, _ in matched)}",
        "set -e",
    ]
    for rule, only_any in matched:
        lines.append(f"# {_comment(rule)}{' (destination via any)' if only_any else ''}")
        for src in _sources(rule):
            family = "ipv6" if (src and ":" in src) else "ipv4"
            src_part = f' source address="{src}"' if src else ""
            for proto, port in _services(rule):
                if proto == "icmp":
                    rich = (f'rule family="{family}"{src_part} icmp-type name="echo-request" accept'
                            if port == "ping"
                            else f'rule family="{family}"{src_part} protocol value="icmp" accept')
                else:
                    rich = (f'rule family="{family}"{src_part} '
                            f'port port="{port or "1-65535"}" protocol="{proto}" accept')
                lines.append(f"firewall-cmd --permanent --add-rich-rule='{rich}'  # {rule.rule_id}")
    lines += ["firewall-cmd --reload"]
    return "\n".join(lines) + "\n"


def export_sles(target_ip: str, matched: list[tuple[Rule, bool]]) -> str:
    lines = [
        "#!/bin/bash",
        _("# Permitra host firewall for {target_ip} (SLES/iptables)", target_ip=target_ip),
        "# Note: SLES 15 uses firewalld – use the RedHat export there.",
        f"# Rules: {', '.join(r.rule_id for r, _ in matched)}",
        "set -e",
        "iptables -F INPUT",
        "ip6tables -F INPUT",
        "iptables -A INPUT -i lo -j ACCEPT",
        "ip6tables -A INPUT -i lo -j ACCEPT",
        "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT",
        "ip6tables -A INPUT -p ipv6-icmp -j ACCEPT",
    ]
    for rule, only_any in matched:
        lines.append(f"# {_comment(rule)}{' (destination via any)' if only_any else ''}")
        for src in _sources(rule):
            cmd = "ip6tables" if (src and ":" in src) else "iptables"
            src_part = f" -s {src}" if src else ""
            for proto, port in _services(rule):
                if proto == "icmp":
                    icmp_type = " --icmp-type echo-request" if port == "ping" else ""
                    lines.append(
                        f"{cmd} -A INPUT{src_part} -p icmp{icmp_type} "
                        f"-m comment --comment \"{rule.rule_id}\" -j ACCEPT"
                    )
                    continue
                dport = f" --dport {port.replace('-', ':')}" if port else ""
                lines.append(
                    f"{cmd} -A INPUT{src_part} -p {proto}{dport} "
                    f"-m comment --comment \"{rule.rule_id}\" -j ACCEPT"
                )
    lines += ["iptables -P INPUT DROP", "ip6tables -P INPUT DROP"]
    return "\n".join(lines) + "\n"


EXPORTERS = {"debian": export_debian, "redhat": export_redhat, "sles": export_sles}


def export(os_name: str, target_ip: str, rules: list[Rule]) -> tuple[str, list[str]]:
    """Returns (content, list of the rule IDs used)."""
    matched = matching_rules(rules, target_ip)
    content = EXPORTERS[os_name](target_ip, matched)
    return content, [r.rule_id for r, _ in matched]
