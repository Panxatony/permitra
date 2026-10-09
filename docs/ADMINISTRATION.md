# Administration

Settings, accounts and the integrations an administrator configures once. The
audit trail has its own document, [AUDIT.md](AUDIT.md), because it is the evidence
rather than a setting.

## Settings (admin area)

- **Risk hints** (GitLab issue 10): rules are checked for risky patterns (source and destination both `any`, very broad networks ≤/8, risky services like RDP/Telnet/SMB/DB-direct — weighted higher from exposed source zones, `any` service across zones). Port **ranges and lists are expanded**, so `20-25` is flagged for the FTP and Telnet it contains and the finding names the concrete port (`Port 23 in 20-25`) instead of leaving you to search the range. Severity is raised by the target zone's protection level (a simple risk matrix). Non-blocking; shown on the rule detail page and filterable in the rule list (`risk=flagged`). API: `GET /api/rules/{id}/risk`.
  - **The criteria are visible and maintainable**: a hint is shown to an approver *before* they decide, so the yardstick it was raised by is part of the evidence — and an absent hint must not be mistaken for "harmless" when it only means "not on the list". `GET /api/risk/criteria` (every signed-in role) returns all patterns with their severity, the `/8` threshold, the protection-level weighting and the service list; the admin area shows it in full and the rule detail page has it behind **"By which criteria?"**. The service list is data (`risky_ports`, seeded from the shipped defaults) and maintainable by admins via `PUT`/`DELETE /api/risk/ports/{port}` — every change is written to the audit log, because moving the yardstick is itself subject to review. Shipped default labels follow the instance language; a label an admin types is kept verbatim.
- **Least privilege / default-deny** (`zone_matrix_default`): behaviour for zone relationships without a matrix entry. `permit` = allowed with a hint (legacy behaviour, default), `deny` = rules are rejected (422) until the relationship is explicitly set to Allow via a matrix request with two approvals — BSI recommendation, active in the demo dataset. API: `GET/PUT /api/settings`.
- **Mandatory fields for rules** (`require_justification`, `require_valid_until`): justification and expiry date are **mandatory by default** (the requestor is always the account that created the rule) (BSI documentation duties) — the admin area offers a deactivation option per field. Enforced server-side (422 with field list), marked with `*` in the rule form.

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
- **Passwords**: at least 8 and at most 128 characters, not one of the 10,000 most common passwords (SecLists list bundled under `backend/app/wordlists/`, MIT), and not containing the username or the local part of the e-mail address - enforced wherever a password is set (activation and reset link, account page, admin-created account). Hashes are PBKDF2-HMAC-SHA256 with 600,000 iterations, stored as `pbkdf2_sha256$<iterations>$<salt>$<digest>`; a hash made at a lower cost or in the older `<salt>$<digest>` format is rewritten on its owner's next successful login, so raising the cost needs no migration. About 0.4 s of CPU per login on a small VM. `PERMITRA_PBKDF2_ITERATIONS` overrides the count (the test suite lowers it); do not lower it in production.
- **2FA (TOTP)**: self-service on the account page (secret for authenticator apps, activation by code); login then asks for the code as a second factor. Implemented per RFC 6238 without extra dependencies. An admin can **reset a user's 2FA** in the admin area (`POST /api/users/{username}/reset-totp`, audited as `user.totp_reset`, not on the admin's own account): the user signs in with the password and sets 2FA up again. The admin list marks a seed that no configured key can read (⚠), which is what a key rotation without `SECRET_KEY_PREVIOUS` leaves behind; such a login is refused with a message naming the reset, and does not count towards the lockout.
- **Passkeys (WebAuthn)**: registration on the account page, passwordless sign-in on the login page. Requires HTTPS (or localhost); configured via `PERMITRA_RP_ID`/`PERMITRA_ORIGIN` (default derived from `PERMITRA_BASE_URL`).

## Excel import (one-off migration)

`backend/import_excel.py` reads an existing communication matrix (one sheet, the AP0400 column layout) straight into the database. It is a migration tool, not an API: it runs on the server, skips the rule form's checks (zone derivation, zone matrix, mandatory fields) and writes `created_by = excel-import`.

- **Status mapping is a trust decision**: rows marked *umgesetzt* are imported as **approved without a review**, *neu* goes straight into review, *deaktivieren*/*deaktiviert* become deactivated, anything else is a draft. The sheet is treated as the record of what was already decided; run a recertification campaign after the import if that is not the case.
- **The requestor column is resolved to an account.** The four-eyes check keys on the requestor as an account username, so a typed name is matched against username, full name and e-mail address (case-insensitive) and stored as the username. A name that matches no account is kept as typed and listed at the end of the import; for such rules the requestor exclusion does not apply, and the recertification shows them as *requestor unknown* until a requestor handover assigns an account. `--requestor-map "Max Mustermann=mmustermann"` (repeatable) settles names the lookup cannot.
- Rule IDs from the sheet are kept; a row whose ID already exists is skipped. `--wipe` removes all rules first. Rules go into the VRF named with `--vrf`, or the default (first) VRF.

## Rotating SECRET_KEY

`SECRET_KEY` signs session tokens and, through a per-purpose derivation (HKDF), encrypts the TOTP seeds and the NetBox token. Rotating it used to lock every 2FA user out and blank the NetBox token. The supported way:

1. Set `SECRET_KEY_PREVIOUS` to the current key (comma-separated list, newest first, if several) and `SECRET_KEY` to the new one (`openssl rand -hex 32`).
2. Restart. At startup every TOTP seed and the NetBox token are re-encrypted under the new key (`permitra.keys` logs how many); sessions signed with the previous key keep working until they expire (`TOKEN_LIFETIME_HOURS`, default 8). `python -m app.key_rotation` runs the same re-encryption on demand.
3. After the sessions have expired, remove `SECRET_KEY_PREVIOUS` and restart.

A seed that cannot be read under any configured key is logged per user at ERROR, left untouched (the right key may still be in a backup), shown in the admin list, and the user's login says that an admin has to reset 2FA. Values written before this version (one key for everything, derived as sha256 of the secret) are read and re-encrypted the same way, so the upgrade itself needs nothing.

## NetBox import (networks)

Permitra manages only the **network→zone mapping**; the networks themselves live in a
dedicated IPAM. Prefixes can be imported from **NetBox** (status *active* and *planned*):
configure the NetBox URL and API token in the admin area (token stored encrypted), run the
import (`POST /api/netbox/import`), then adopt prefixes into the zone registry on the Networks
page — assigning each a zone, which goes through the normal approval workflow (source `netbox`).

**Workloads** can be imported from the same NetBox connection (`POST /api/netbox/import-workloads`,
or the *Import from NetBox* button on the Workloads page): devices and virtual machines with a
primary IP become workloads (source `netbox`), their role, tenant, site, platform, cluster, device
type and status become labels (`role=web-server`), tags become `tag.<slug>=true`. A re-import
updates by NetBox ID and removes workloads that vanished; selector groups built on the labels are
re-synchronised afterwards, and one rule the import would leave inadmissible refuses the whole
import (see [Workloads, groups and segments](CONCEPTS.md#workloads-groups-and-segments)).
