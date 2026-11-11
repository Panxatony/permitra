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
- **EPG bindings**: the APIC JSON export contains `fvAp`/`fvAEPg` with provider/consumer references; SR IDs are kept in subject descriptions for traceability/drift. Rules without an EPG mapping are **not exported**: a contract no EPG provides or consumes enforces nothing, and because it carried the SR ID the drift comparison used to read it as implemented. They are named in the warnings, in the tenant description of the APIC JSON and under `not_exported_without_epg` in the YAML, and the drift report lists them as *missing* until their addresses are mapped.

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

### Only the open implementation work

`impl=pending` on `GET /api/export/{fmt}` and `GET /api/export/aerleon/{target}` narrows the export to what still has to be configured: rules in force whose implementation status on the component is missing, `open`, `new` or `to change`. Rules that are `implemented` or `deactivated` there are left out, so the file is the work package for the next change window rather than the whole rule base. Which component's status counts:

- with `component_id=`, the status on that component;
- without it, for a device format, the status on the components that format is for (a rule already implemented on every Juniper firewall is not in the Juniper export, even if a Check Point gateway is still open);
- for `csv`, `json`, a Capirca/Aerleon target or `platform_filter=false`, the status on any of the rule's components.

A rule in `to change` is exported in its current, approved form. The export does not say which entries were dropped since the device was configured; the rule page does, see [What changed since the implementation](#what-changed-since-the-implementation). `to remove` is not part of this export, because Permitra does not generate removal configuration. If nothing is open the endpoint answers 404, so an automation cannot mistake "nothing to do" for an empty configuration. The audit entry names the export as one of open implementation work. In the interface the option is *Open implementation only* on the export page; the rule list filtered to *To implement* links to it.

### What changed since the implementation

When an implemented rule is approved again, its components go to `to change`. The generated configuration then describes the rule as it stands now, which is enough to add what is new and not enough to notice what is gone: an address that left the rule is simply absent. For each component in `to change`, the rule page (and `GET /api/rules/{id}/implementation`) therefore names the version operations last confirmed as implemented there and the difference to the current rule: sources, destinations and services to add, those to take off the device, and a changed name, action, zone or environment.

- The comparison is per component. Two firewalls confirmed at different versions get different lists.
- The confirmed version is the one at which operations last reported the component as `implemented`; for an imported rule, the version it arrived with.
- It compares what the rule says, not configuration lines. Permitra still generates no removal statements: what is listed as removed has to be taken off the device by hand.
- A renewed approval that changes nothing on the device (a new expiry date, a reworded justification) is shown as such, so the implementation can be confirmed straight away.
- If no confirmed version is on record, the view says so instead of showing an empty difference.
- The logging level is not part of a version snapshot and is not compared.

## Host firewall export

For a **target IP**, Permitra generates the server's local firewall rules (`GET /api/export/host/{debian|redhat|sles}?ip=`), based on all approved permit rules whose destination covers the IP. Formats: **Debian** = nftables ruleset (default drop, loopback, established/related, ICMP), **RedHat** = firewalld script with rich rules, **SLES** = iptables script. Every line carries the SR ID as a comment; IPv6 sources are handled correctly.

## Capirca/Aerleon integration

The built-in [Aerleon](https://github.com/aerleon/aerleon) integration (the maintained Apache-2.0 fork of Google's Capirca) translates Permitra rules into Capirca policies: aliases/IPs become network objects, services become service objects (TCP/UDP is split per protocol), rules become terms with their SR ID as the term name; zone-based targets (SRX, Palo Alto) get one filter per zone pair. Endpoints: `GET /api/export/aerleon/{target}` with targets `cisco`, `ciscoasa`, `juniper`, `srx`, `paloalto`, `iptables` — and `policy`, which emits definitions + policy as YAML for existing Capirca/Aerleon pipelines. Check Point and ACI intentionally keep their specialized exporters (Capirca does not cover them).

## Reports & printing

- **Per-APP-ID report**: filter the rule list by APP-ID and export a CSV report of all its rules (`GET /api/export/csv?app_id=…`; the APP-ID column is included in CSV/JSON). The `app_id` filter also works on `GET /api/rules`.
- **Print / PDF of the analysis**: the analysis page offers a print button that renders a clean, print-optimized view (source→destination, timestamp, matching rules) for saving as PDF.

## Free text in generated configuration

A justification, a rule name, a change ID or an address alias is typed by a rule author and reaches the exports. What reaches a **text or script format** (Juniper set commands, Check Point `mgmt_cli` script, host firewall scripts, Aerleon policies) goes through two helpers in `exporters/common.py`: `comment_text()` collapses line breaks and every other control character to one space and cuts the text to a length a comment can carry - a line break would otherwise end the comment and turn the rest into the next statement; `shell_word()` turns the one free-text value that sits on a command line (the Check Point rule name) into a single-quoted shell word, because inside double quotes `$(...)` and backticks are live. Zone references in Aerleon headers go through `sanitize_name()` like policy names. JSON and YAML outputs are escaped by their serializers, CSV by `csv_safe()`. On the way in, one-line rule fields (name, application, APP-ID, requestor, owner, change ID, business context, zones) refuse control characters and are bounded to their column widths; justification, description and info keep their line breaks and are flattened only in the export.
