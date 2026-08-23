# Changelog

Notable changes to Permitra. Dates use ISO format (YYYY-MM-DD).

## Unreleased — 2026-08

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

### License
- Apache License 2.0.
