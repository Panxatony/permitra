# Audit log, integrity and SIEM

What Permitra records, how it detects that a record was altered, and what that
protection is actually worth. The last part matters most: a claim about tamper
evidence is only useful if its limits are stated with it.

## What is recorded

(GitLab issues 11, 24, 25, 26) Unified, machine-readable change log at `GET /api/audit-log` (admin only; `since`/`type`/`limit`). It merges rule versions and zone/matrix/network requests with an **append-only event store** covering sign-in (success, failure, lockout, password change, 2FA), administration (users, settings, API tokens, NetBox) and data access (exports) — each with actor and **source IP** (taken from `X-Forwarded-For` only when the request comes from a proxy listed in `PERMITRA_TRUSTED_PROXIES`; otherwise the immediate peer, which cannot be forged). Rules are **soft-deleted** so deletion never destroys the trail. A viewer is on the admin page.
## Integrity

(GitLab issue 26) Every stored event carries a SHA-256 `hash` over its content *and* its predecessor's hash (hash chain, genesis = 64 zeros). Editing an event, reordering, or removing one breaks the chain. Because a chain is also intact after its *newest* entries are cut off, **checkpoints** (`audit_checkpoints`) periodically anchor the chain end (last id, count, head hash) — hourly by default (`AUDIT_CHECKPOINT_INTERVAL`), or on demand via `POST /api/audit-log/checkpoint`. `GET /api/audit-log/verify` (admin) re-computes the whole chain, compares it against the newest checkpoint, and reports `ok`, entries checked, and the first `broken_at_id` with a reason. The admin page has **"Verify integrity"** and **"Anchor now"** buttons. Delivery columns are excluded from the hash, so operational updates never invalidate it.
## What this does and does not protect against

Stated plainly, because the wording matters for an audit. The hash is **keyless** — anyone who can *write* to the database can alter an event and recompute the chain from there with the same public function, and by also deleting the checkpoints make it undetectable *within the database*. The chain alone therefore protects against accidental corruption and against tampering without recomputation — not against an attacker with database write access. The load-bearing protection is **externalisation**: events *and* checkpoints are reliably delivered to a SIEM, where they are out of reach of database access, and a comparison exposes any later forgery. Without a configured SIEM sink the protection stays limited to the above — a deliberate operational choice, not a property of the application.
## The log reads in the instance's language, including its past

History and audit entries are stored as the English message template plus its values and put into words when somebody reads them. English stays what the database holds, which is also right for a SIEM — it has no language. Translating on the way in froze each entry in whatever the instance happened to be set to that day, so switching to German translated the interface and left the past behind.
## Retention — deleting personal data without breaking the proof

(GDPR Art. 5(1)(e), BSI CON.6) Audit events hold usernames and source IPs, so a retention period is a legal duty — and the hash chain is the reason it was impossible to meet: deleting one event breaks verification from that point forever. The resolution is to collapse whole **prefixes** rather than individual entries. Once the oldest segment is past the configured period, it is deleted and replaced by a **retention seal** recording the boundary hash the first surviving event links back to; verification then starts from the newest seal instead of genesis. The chain stays provable, the personal data is gone.

Set the period in the admin area (`audit_retention_days`, default `0` = keep forever — deletion is an operator decision, never a surprise on upgrade). A background pass on the checkpoint cadence anchors the chain head, then collapses the expired start.

**With a SIEM configured, nothing is collapsed until it has been delivered there.** Retention externalises evidence; it must not destroy it. The seals are delivered to the SIEM too — a seal is the only remaining proof its collapsed segment ever linked up. `GET /api/audit-log/siem-status` reports `events_collapsed`, `seals` and `seals_pending`.

## Reliable delivery

(GitLab issue 26) When a SIEM sink is configured, events are persisted as `pending` and delivered by a background worker in strict order, **at-least-once** — the state lives in the database, so a crash or restart loses nothing, and a sink outage simply queues events until it returns. Delivery stops at the first failure to preserve ordering, and each delivered event carries its `hash` so the SIEM can re-verify the chain independently. All background jobs (delivery, anchoring, expiry) run their blocking work in a worker thread, so an unreachable sink never stalls the API — verified: request latency stays at ~3 ms while delivery runs into its timeouts. While a sink stays unreachable the retry interval backs off from 10 s up to 5 minutes instead of hammering it every cycle. Status: `GET /api/audit-log/siem-status`. Sinks: webhook (`AUDIT_WEBHOOK_URL`, 2xx = acknowledged) and syslog (`AUDIT_SYSLOG_HOST`/`AUDIT_SYSLOG_PORT`, `AUDIT_SYSLOG_PROTO=udp|tcp`; TCP uses RFC 6587 octet framing and is acknowledged, UDP is best-effort).
