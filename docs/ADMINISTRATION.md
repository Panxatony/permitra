# Administration

Settings, accounts and the integrations an administrator configures once. The
audit trail has its own document, [AUDIT.md](AUDIT.md), because it is the evidence
rather than a setting.

## Settings (admin area)

- **Risk hints** (GitLab issue 10): rules are checked for risky patterns (source and destination both `any`, very broad networks ≤/8, risky services like RDP/Telnet/SMB/DB-direct — weighted higher from exposed source zones, `any` service across zones). Port **ranges and lists are expanded**, so `20-25` is flagged for the FTP and Telnet it contains and the finding names the concrete port (`Port 23 in 20-25`) instead of leaving you to search the range. Severity is raised by the target zone's protection level (a simple risk matrix). Non-blocking; shown on the rule detail page and filterable in the rule list (`risk=flagged`). API: `GET /api/rules/{id}/risk`.
  - **The criteria are visible and maintainable**: a hint is shown to an approver *before* they decide, so the yardstick it was raised by is part of the evidence — and an absent hint must not be mistaken for "harmless" when it only means "not on the list". `GET /api/risk/criteria` (every signed-in role) returns all patterns with their severity, the `/8` threshold, the protection-level weighting and the service list; the admin area shows it in full and the rule detail page has it behind **"By which criteria?"**. The service list is data (`risky_ports`, seeded from the shipped defaults) and maintainable by admins via `PUT`/`DELETE /api/risk/ports/{port}` — every change is written to the audit log, because moving the yardstick is itself subject to review. Shipped default labels follow the instance language; a label an admin types is kept verbatim.
- **Least privilege / default-deny** (`zone_matrix_default`): behaviour for zone relationships without a matrix entry. `permit` = allowed with a hint (legacy behaviour, default), `deny` = rules are rejected (422) until the relationship is explicitly set to Allow via a matrix request with two approvals — BSI recommendation, active in the demo dataset. API: `GET/PUT /api/settings`.
- **Mandatory fields for rules** (`require_justification`, `require_requestor`, `require_valid_until`): justification, requestor and expiry date are **mandatory by default** (BSI documentation duties) — the admin area offers a deactivation option per field. Enforced server-side (422 with field list), marked with `*` in the rule form.

## User management, email & sign-in security

- **What the admin is for**: installing and administering Permitra — users, settings, audit log, integrations. Deliberately **not a superuser**: no rule views in the interface, no approvals, no recertification, no reports. Deciding when rules are re-examined belongs to the change approver, kept separate from operating the tool.
- **Admin area** (`/admin`, role admin): create/update/deactivate users, assign roles, trigger password resets. An account holds a **set** of roles and its permission is their union, so the roles are checkboxes rather than a single choice — a small team runs one person as architect *and* operations. The badge shows a primary role derived from the set; authorisation always asks the set. An admin cannot remove their own admin role, and an account cannot be left with none. New users without a password receive an **activation link** (valid 72h) — by email if SMTP is configured; the link is also shown to the admin.
- **Email notifications** (GitLab issue 5): on rule submission (→ change approvers), approval/rejection (→ requester), implementation/decommission required (→ operations) and recertification (→ operations, from the daily expiry job). Recipients are derived from the role set — deliberately **not** "and the admins too": an admin reaches neither the reviews nor the recertification, so mailing them about a rule waiting for approval would point them at a page that answers 403. Someone who does both jobs holds both roles and is reached through the working one. Each user can opt out on the account page (`notify_email`). Requires SMTP and a stored email address; silently does nothing otherwise.
- **Email delivery**, disabled while `SMTP_HOST` is empty:

  ```bash
  SMTP_HOST=… SMTP_PORT=587 SMTP_USER=… SMTP_PASSWORD=… SMTP_FROM=…
  PERMITRA_BASE_URL=https://permitra.example.org   # base for links in emails
  ```

- **Forgot password** on the login page (reset link, valid 2h; responses never reveal whether an account exists, not even when a request was dropped for rate limiting). A new link replaces the previous unused one. A reset link only changes the password: a **deactivated account stays deactivated** and gets no link at all, so the flow cannot undo an admin's decision. The admin's *send reset* on an inactive account therefore issues an activation link instead. Account page: change password.
- **2FA (TOTP)**: self-service on the account page (secret for authenticator apps, activation by code); login then asks for the code as a second factor. Implemented per RFC 6238 without extra dependencies.
- **Passkeys (WebAuthn)**: registration on the account page, passwordless sign-in on the login page. Requires HTTPS (or localhost); configured via `PERMITRA_RP_ID`/`PERMITRA_ORIGIN` (default derived from `PERMITRA_BASE_URL`).

## Excel import (one-off migration)

`backend/import_excel.py` reads an existing communication matrix (one sheet, the AP0400 column layout) straight into the database. It is a migration tool, not an API: it runs on the server, skips the rule form's checks (zone derivation, zone matrix, mandatory fields) and writes `created_by = excel-import`.

- **Status mapping is a trust decision**: rows marked *umgesetzt* are imported as **approved without a review**, *neu* goes straight into review, *deaktivieren*/*deaktiviert* become deactivated, anything else is a draft. The sheet is treated as the record of what was already decided; run a recertification campaign after the import if that is not the case.
- **The requestor column is resolved to an account.** The four-eyes check keys on the requestor as an account username, so a typed name is matched against username, full name and e-mail address (case-insensitive) and stored as the username. A name that matches no account is kept as typed and listed at the end of the import; for such rules the requestor exclusion does not apply, and the recertification shows them as *requestor unknown* until a requestor handover assigns an account. `--requestor-map "Max Mustermann=mmustermann"` (repeatable) settles names the lookup cannot.
- Rule IDs from the sheet are kept; a row whose ID already exists is skipped. `--wipe` removes all rules first. Rules go into the VRF named with `--vrf`, or the default (first) VRF.

## NetBox import (networks)

Permitra manages only the **network→zone mapping**; the networks themselves live in a
dedicated IPAM. Prefixes can be imported from **NetBox** (status *active* and *planned*):
configure the NetBox URL and API token in the admin area (token stored encrypted), run the
import (`POST /api/netbox/import`), then adopt prefixes into the zone registry on the Networks
page — assigning each a zone, which goes through the normal approval workflow (source `netbox`).
