# Changelog

Notable changes to Permitra. Dates use ISO format (YYYY-MM-DD).

## Unreleased

- **Operations may have one broad rule: a ping baseline.** When a system stops
  answering, the first question is not *which port* but *does the network reach
  it at all* - and nothing in a rule catalogue answers it, so the search starts
  at the firewall, the one place that could have answered it already. A rule
  can now declare itself the ping baseline between two zones: any-to-any,
  carrying ICMP echo and nothing else. It turns "the network is broken" into
  "the path is open, the service is down", without a change request to find out.
  The exemption is checked rather than claimed - **internal zones only**, **on a
  relation the matrix already permits** (it rides on one, it never creates one),
  **echo only** and **one direction**. Since `any` has no network to derive a
  zone from, a baseline names its two zones, and its components follow from
  those zones and the topology between them, transit clusters included. The risk
  assessment names it at low severity instead of reporting it as too broad; an
  ordinary any-to-any rule still is.
- **Fixed: an ICMP rule limited to ping exported as every ICMP type.** `port:
  ping` was recorded, and every exporter ignored it - Juniper emitted
  `junos-icmp-all`, Check Point `icmp-proto`, ACI a filter entry without a type,
  the host firewalls a bare `-p icmp`. That documented redirects and timestamps
  the rule never granted. They now emit `junos-ping`, `echo-request`,
  `icmpv4T: echo` and `--icmp-type echo-request`, and the drift comparison reads
  "every ICMP type" on a device as a widening of an approval for echo. The
  Aerleon export additionally generated an unresolvable `port: ping` service
  object; ICMP now travels as an `icmp-type` on the term, where it belongs.

- **The path analysis routes over the topology instead of sorting by tier.**
  The hops used to come from the address mapping, ordered by each component's
  north-south tier - which holds while an estate is one straight stack and can
  never say whether there is a way from here to there at all. The component
  links (OSPF, BGP, transfer networks) were already recorded and nothing read
  them; now they are the graph. Three answers follow that ordering could not
  give: **no route** is a finding rather than an invented sequence, **every
  shortest route** is reported because a rule on one redundant path and not the
  other holds until the failover, and a transit cluster appears on its own
  instead of having to be listed on every address behind it. "Nobody documented
  the links" stays distinct from "there is no way".
- **Fixed:** the ACI fabric is listed on nearly every zone because it segments
  *inside* one. Treated as an attachment point it made both endpoints share it,
  and the analysis reported that VPN reaches the production databases without
  crossing a firewall.
- **The demo shows a path across four firewall clusters** - monitoring in the
  data centre polling a partner-facing gateway, across FFM-DC → FFM → BER →
  Extranet. New zone EXTRANET and cluster FW-Cluster-Extranet (the second filter
  of the BSI P-A-P chain). Every hop is derived from the topology; the seed
  distributes each rule along the route the analysis computes, so it cannot show
  a rule missing on a transit cluster the analysis then reports as uncovered.

- **An account can hold several roles**, and its permission is their union
  (#78). Small teams do not have four people for four roles. Separation of
  duties is untouched, because the four-eyes checks key on the acting *account*
  rather than on a role — and `_decide` now also refuses the rule's
  **requestor**, not just its creator and submitter, which is exactly the hat
  that would otherwise have slipped through on a multi-role account.
- **The admin is installation and administration only.** It no longer reaches
  recertification or the reports, in the navigation *and* in the endpoints, and
  campaigns are started and closed by the change approver alone. Notification
  mails follow: an admin is no longer told about a review it would get a 403 on.
  The frontend's `role === X || role === 'admin'` bypasses went with it — they
  contradicted the backend, which has required the named role since #71.
- **Retiring an application proposes its rules for removal** (#85). The
  application is switched off, the holes it needed stay — one of the most common
  ways a ruleset rots. It proposes rather than decides: each rule goes back into
  review and is decided one at a time, the dry run is the default, and whoever
  starts it becomes the submitter and so cannot approve the removals.
- **An evidence report for audits** (#86): every change in a period, optionally
  by zone or application, with requester, approver, justification and date —
  the document an audit asks for, instead of an API to query one record at a
  time. Matrix changes name both approvers, and the report states whether the
  audit log still covers the window rather than looking complete over a gap.
- **Rules and zones are created where they live**, as overlays, and documenting
  an emergency change is an *option* on the new-rule form rather than a second
  entry point. A new rule is prefilled to expire in a year — recertification
  asks whether a rule is still needed, and an open-ended rule never gets asked.
- **Fixed:** the matrix history showed only the approver who finished a change,
  hiding the first of the two approvals that are the control; the help "?"
  navigated to the help page and left you there; overlays inherited the
  typography of whatever opened them; the derived zone on the rule form wore a
  green *approved* badge instead of its protection level; a zone rejected as a
  duplicate reported the error behind the dialogue where nobody could see it.

- **Drift now checks that a rule matches its approval, not just that it claims
  one.** Coverage proved a device rule carried an approved SR ID; it did not
  prove the rule still permitted only what was approved. A rule widened during
  an incident — one host on port 443 opened to `any` — kept its ID and read
  green. The comparison now parses what each rule permits (Juniper, Check Point)
  and reports the ones **wider than approved**; narrower is fine, since
  operations may implement less. A rule that cannot be resolved to compare is
  reported as unverified, never as a pass. (#48)
- **Demo:** two accounts per role, and rules split across both architects, so
  the four-eyes approval and the requestor handover are demonstrable.
- **Fixed:** proposing or confirming a requestor handover greyed the rule page
  (the endpoints return the rule without its history, which the page needs); it
  reloads the full rule after each step now.
- **A rule's requestor can be handed over.** An architect who changes department
  or company proposes a successor for the rules they requested; the requestor
  changes only once that successor confirms — an accountable person is not
  assigned a rule without their consent. An admin may propose for a requestor
  whose account is already gone (the case the recertification worklist flags),
  but not while they are still active. Incoming handovers surface on the
  successor's dashboard.
- **Fixed:** recertification campaigns keyed the worklist by a rule's owner
  (the Bearbeiter who rolled it out), not its requestor. Recertification asks
  "is this still needed?" — a question for the requester, not the implementer.
- **The audit log has a retention period now.** It held usernames and source
  IPs and grew without bound, which GDPR Art. 5(1)(e) and BSI CON.6 make a
  problem — and the hash chain was the reason it could not be solved, since
  deleting one event breaks verification forever. Expired prefixes are now
  collapsed behind a sealed anchor: the segment is deleted, a seal records the
  boundary hash the survivors link back to, and verification resumes from the
  seal. Default is keep-forever; with a SIEM configured nothing is deleted
  before it has been delivered there. (#34)
- **A fresh instance says what it still needs.** First start used to end at a
  login form; what a working instance needs next was scattered and unspoken,
  and a new operator hit "network not assigned to any zone" before the mental
  model arrived. A checklist on the dashboard and admin page now names the
  essentials in dependency order — language, zones, networks, components,
  matrix, accounts, first rule — each step saying why the next one needs it,
  every step linking to the normal page, nothing blocking anything. It
  disappears once the essentials exist. Fewer than two active change approvers
  is warned about permanently: the matrix workflow silently cannot complete
  without them, and approvers leave after setup too.
- **Fixed:** `PERMITRA_INITIAL_ADMIN_PASSWORD` was documented but never passed
  through docker-compose.yml, so setting it in `.env` silently did nothing.
- **Recertification is a review, not just expiry control.** Campaigns ask the
  actual question rule by rule — still needed, still correct, still owned — with
  a fixed scope, a cut-off, a per-owner worklist and three recorded decisions
  (confirm / rework / retire). The report shows who confirmed what and what is
  outstanding; a decision is refused rather than overwritten; owners matching no
  active user are flagged. "When did somebody last deliberately confirm this
  rule?" is answered on the rule itself (`last_confirmed_at`/`by`).
- **The drift comparison counts what is on the device, not just what it
  recognises.** It only ever looked for SR IDs, which answers "did my rules
  arrive?" and misses the question Permitra exists for. A rule somebody opened by
  hand carries no ID, so it produced nothing to find — not reported as
  unjustified, not reported at all — and the report said `in_sync: true` while it
  sat on the firewall. The report now names the unjustified rules by identifier
  and line, and the dashboard carries one coverage figure for the estate together
  with what it could not measure, because an aggregate improves by looking away.
  A configuration in an unreadable format is reported as unreadable, never as
  clean.
- **An emergency change has a way in.** Approval by somebody else holds until the
  application is down and the only approver is unreachable; then the rule gets
  opened on the firewall and a tool without a fast path does not prevent that, it
  only prevents it from being recorded. `POST /api/rules/emergency` documents it:
  mandatory reason, straight into review, and it deactivates itself if nobody
  approves within the window. Its own audit event, because how often it happens
  is what separates a control from a habit.
- **A rule can be rolled back to an earlier version.** As a new version, so the
  history stays complete. This was already the case and was listed as missing.
- **Log and history entries follow the instance language, including their past.**
  They used to be translated as they were written, which froze each one in
  whichever language was configured that day — an instance switched to German
  kept reading English forever. They are stored as the English template plus
  their values now and rendered when read. The implementation status also stopped
  arriving as a Python dict repr.
- **Fixed:** the Check Point pattern in the coverage scan was written against the
  management API spelling and never tried against what Permitra's own exporter
  writes, so a genuine Check Point script scanned as an unreadable format and the
  component silently had no coverage figure.
- **Fixed:** the Juniper exporter carried the rule ID only in an export comment,
  which never reaches the device — so a real SRX dump showed every policy as
  unjustified. It is written into the policy description now.
- **Fixed:** the demo showed a state the application cannot produce — rules
  implemented on every component while still `approved` rather than `active`,
  making the dashboard contradict itself.

## 0.7.4-alpha — 2026-08-23

First public release. **Alpha**: the feature set is complete enough to work with
end to end, and the security audit's critical and high findings are closed — but
it has not been run in production anywhere, the API may still change without a
deprecation path, and no upgrade is supported except forward through the
migrations. Try it, deploy it in a lab, report what breaks. Do not put your
production communication matrix in it yet.

Known gaps, stated plainly rather than left to be discovered:

- List queries load all rules and paginate in memory; with the risk filter on,
  each rule additionally triggers two zone scans. Fine for thousands of rules,
  not for hundreds of thousands.
- Downloads (CSV/JSON export) bypass the central error handling: with an expired
  session the browser saves the error message as if it were the file.
- The containers run as root and without a read-only root filesystem.
- Single instance only: background jobs (expiry, SIEM delivery, checkpoints) are
  not coordinated across replicas, so `replicas: 1` is deliberate.

### Added
- **Core prototype**: rule management with server-assigned `SR#####` IDs (5 digits, up to 99999 rules), structured addresses (IP/CIDR + optional alias), multiple services per rule, review workflow (draft → in review → approved → active, with rejected/deactivated/deleted as the ways out), version history with snapshots, comments, conflict detection (overlap, duplicate, shadowing).
- **Rollout is a status, not a footnote**: a rule becomes `active` automatically once operations confirms it as *implemented* on every assigned component, and falls back to `approved` when one no longer does — so "approved but never rolled out" is visible instead of indistinguishable from "in service". Both states count as in force for exports, drift, path analysis and expiry.
- **Rules are never deleted**: a rule that is no longer needed takes the status `deleted` and stays visible in the overview with its full history; it stops taking effect (no export, no path analysis, no drift, no recertification) but is never removed.
- **Roles**: architect, operations, change approver (one approval for rule reviews, two different approvers for zone/matrix/network requests, four-eyes principle), admin with a focused administration area.
- **Security zones**: zone catalog with BSI P-A-P classification, BSI documentation per zone (owner, protection level per C/I/A goal with maximum principle), zone communication matrix (allow/block) maintained via batch requests with dual approval, hard-enforced BSI principle that zone transitions require a firewall (ACI is intra-zone only), north-south P-A-P diagram.
- **Least privilege**: configurable default-deny for zone relationships without a matrix entry (admin setting `zone_matrix_default`).
- **Network registry**: every network belongs to exactly one zone; rule zones are derived automatically; network→zone mapping changes go through the dual-approval workflow; NetBox import hook prepared.
- **Components**: security components (Check Point, Juniper SRX, Cisco ACI) with automatic component resolution from source/destination, persistent address mappings, component links with link types, SVG topology, ACI anycast gateways with PBR, implementation status per component ("to change" after re-approval, dashboard tile for operations).
- **Analysis**: combined address search and multi-hop path analysis (ordered hops, PBR hops, per-component rule verdicts).
- **Risk hints**: rules are checked for risky patterns (any-to-any, `any` source, very broad networks, risky services with port ranges expanded, `any` service across zones); severity is raised by the target zone's protection level and by an exposed source zone. The criteria are visible to every role (`GET /api/risk/criteria`, shown in the admin area and behind "By which criteria?" on the rule detail page) and the service list is maintainable by admins, with every change written to the audit log.
- **Exports**: Juniper SRX set commands, Check Point mgmt_cli + Management API JSON, EPG-based aggregated ACI contracts (APIC JSON/YAML, vzAny, PBR service graphs), host firewalls (nftables/firewalld/iptables), CSV/JSON, and Capirca/Aerleon integration (Cisco IOS/ASA, zone-based SRX, Palo Alto, iptables, policy YAML for existing pipelines).
- **Drift comparison** between approved rules and uploaded device configurations via SR IDs.
- **Recertification**: validity monitoring with automatic deactivation and extension without losing approval.
- **Accounts & security**: admin user management with activation links, optional SMTP email delivery (activation/reset mails), forgot-password flow, TOTP two-factor authentication, WebAuthn passkeys.
- **Audit & compliance evidence**: unified audit log (`GET /api/audit-log`) over rule versions, zone/matrix/network requests and an append-only event store for sign-in, administration and data-access events — each with actor and source IP; rules are soft-deleted so deletion never destroys the trail. Events are chained with SHA-256 hashes so tampering, reordering or removal is detectable (`GET /api/audit-log/verify`, "Verify integrity" in the admin area), and are delivered to a SIEM at-least-once via a durable outbox that survives restarts and sink outages (`GET /api/audit-log/siem-status`; syslog UDP/TCP or webhook).
- **Integrations**: optional change-management webhook (ServiceNow-ready), full REST API with OpenAPI docs.
- **UI**: German or English interface, set by the administrator for the whole instance (setting `ui_language`) so every user sees the same wording; server-side messages follow the same setting. Light and dark theme, mobile-optimized layout, dashboard, focused approvals page for change approvers.
- **Infrastructure**: Docker Compose stack, Kubernetes manifests, Alembic migrations (auto-run at startup), deterministic fictional demo dataset, public demo with nightly reset, static project website (permitra.de, bilingual).

### Security

Findings from the internal code audit, closed before this release:

- **Backups are encrypted and the restore path is tested.** The dump holds
  password hashes, TOTP seeds, API token hashes and the whole audit chain, and
  was written as plain SQL — reading the backup directory was as good as reading
  the database. `scripts/backup.sh` now refuses to write an unencrypted dump
  unless `PERMITRA_BACKUP_PLAINTEXT=1` is set deliberately, in which case it says
  so on every run; and it refuses a passphrase stored inside the backup directory
  it protects.
  `scripts/restore.sh` plays one back, refuses to overwrite a populated database
  without `--force`, and re-verifies the audit hash chain afterwards. CI runs the
  whole round trip on every pull request, including a check that the encrypted
  file holds no readable SQL.

- **Audit chain anchored externally**: a hash chain is still intact after its
  newest entries are cut off, so checkpoints record the chain end and are
  delivered to the SIEM. What the chain does *not* protect against — an attacker
  with database write access — is stated in the README rather than glossed over.
- **Deleted rules stopped taking effect**: a soft-deleted rule kept its
  `approved` status and still counted as a permitting match in the path analysis
  and as "missing" in the drift report, which would have undone its rollback.
- **Source IP no longer forgeable**: `X-Forwarded-For` is evaluated only for
  proxies listed in `PERMITRA_TRUSTED_PROXIES`; the default ignores it entirely.
- **TOTP codes are single use** and the seed is encrypted at rest. A code used to
  be valid for the whole ±90 s tolerance window, and the seed sat in the database
  in plaintext — read access was enough to mint valid second factors.
- **Sign-in no longer confirms that an account exists**: the password is always
  verified (against a decoy hash for unknown names, so the timing matches), the
  account lockout is only reported once the password proved correct, and the
  passkey endpoint answers identically for unknown, deactivated and
  passkey-less accounts.
- **SSRF through the NetBox address closed**: the URL is validated on save
  (http/https only, no loopback, link-local or metadata targets), redirects are
  no longer followed (urllib carried the Authorization header along), and the
  paginating `next` field must stay on the configured host.
- **Reverse proxy hardened**: Content-Security-Policy, `nosniff`,
  `X-Frame-Options: DENY`, Referrer-Policy and Permissions-Policy, plus a
  configurable rate limit on the sign-in (`PERMITRA_LOGIN_RATE`). HSTS is
  deliberately left to the TLS-terminating proxy in front.
- **Bounded inputs**: the actual-configuration upload is capped (4 MB in the
  application, 8 MB at the proxy) instead of being unbounded.
- **Background jobs off the event loop**: an unreachable SIEM used to stall the
  whole API; delivery, anchoring and expiry now run in worker threads with a
  backoff.

### License
- Apache License 2.0.
