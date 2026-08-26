# Exports

Permitra never writes to a device. It produces the configuration to apply, and
these are the formats it produces — plus the rules about *which* rules are allowed
into an export at all, which is the part with security consequences.

## ACI contracts (EPG-based)

The ACI export models contracts idiomatically instead of "one contract per rule":

- **EPG catalog** (maintained on the objects page): EPGs with tenant, application profile and bridge domain, plus an **address→EPG mapping** (exact match or most specific containing network; `any` → **vzAny**). Multiple addresses can be assigned to the same EPG (comma-separated bulk entry in the form).
- **Aggregation**: source → consumer, target → provider; all rules of a (consumer EPG, provider EPG) pair become **one contract** with one subject per filter — avoiding contract/TCAM explosion in the fabric.
- **Filter reuse**: services are resolved against the service object catalog (`flt-https` instead of one duplicate per rule) and deduplicated across contracts.
- **Service graph / PBR**: if the provider EPG's bridge domain carries an anycast gateway with PBR, the subject references its service graph template.
- **EPG bindings**: the APIC JSON export contains `fvAp`/`fvAEPg` with provider/consumer references; SR IDs are kept in subject descriptions for traceability/drift. Rules without an EPG mapping fall back to single contracts and are listed in the warnings.

## ICMP: echo is not "every ICMP type"

ICMP has no ports, so a rule states its restriction in the service's port field:
`ping` (also `ping6`, `echo`, `echo-request`) means the echo request alone, an
empty value means every ICMP type there is. Every exporter reads that
distinction, because on each platform these are different permissions —
`junos-ping` vs `junos-icmp-all`, Check Point `echo-request` vs `icmp-proto`, an
ACI filter entry with `icmpv4T: echo` vs one without, `--icmp-type echo-request`
vs a bare `-p icmp`, and an `icmp-type` on the Aerleon term. The drift comparison
uses the same distinction: a device answering every ICMP type where an approval
says echo is reported as a widening, not as a match. This is what makes a [ping
baseline](CONCEPTS.md#the-rule-workflow) mean on the device what it says in
Permitra.

Exports always apply the approval filter, **including when explicit `ids=` are given** — a rule ID narrows *which* rules are meant, not whether their status still counts. A deactivated or draft rule is therefore not exported by accident; a deliberate preview needs `only_approved=false`, and that export is marked as such in the audit trail. Every export path (device formats, Capirca/Aerleon, host firewall) writes an audit entry with actor, format and rule count.

## Host firewall export

For a **target IP**, Permitra generates the server's local firewall rules (`GET /api/export/host/{debian|redhat|sles}?ip=`), based on all approved permit rules whose destination covers the IP. Formats: **Debian** = nftables ruleset (default drop, loopback, established/related, ICMP), **RedHat** = firewalld script with rich rules, **SLES** = iptables script. Every line carries the SR ID as a comment; IPv6 sources are handled correctly.

## Capirca/Aerleon integration

The built-in [Aerleon](https://github.com/aerleon/aerleon) integration (the maintained Apache-2.0 fork of Google's Capirca) translates Permitra rules into Capirca policies: aliases/IPs become network objects, services become service objects (TCP/UDP is split per protocol), rules become terms with their SR ID as the term name; zone-based targets (SRX, Palo Alto) get one filter per zone pair. Endpoints: `GET /api/export/aerleon/{target}` with targets `cisco`, `ciscoasa`, `juniper`, `srx`, `paloalto`, `iptables` — and `policy`, which emits definitions + policy as YAML for existing Capirca/Aerleon pipelines. Check Point and ACI intentionally keep their specialized exporters (Capirca does not cover them).

## Reports & printing

- **Per-APP-ID report**: filter the rule list by APP-ID and export a CSV report of all its rules (`GET /api/export/csv?app_id=…`; the APP-ID column is included in CSV/JSON). The `app_id` filter also works on `GET /api/rules`.
- **Print / PDF of the analysis**: the analysis page offers a print button that renders a clean, print-optimized view (source→destination, timestamp, matching rules) for saving as PDF.
