# Security policy

Permitra manages firewall rules. A flaw here does not only affect Permitra — it
can affect what the firewalls in front of a network are configured to allow. We
would rather hear about a problem early and awkwardly than late and politely.

## Reporting a vulnerability

Please report privately first, not as a public issue:

- GitHub: **Security → Report a vulnerability** on
  <https://github.com/Panxatony/permitra/security/advisories/new>
- or email **security@permitra.de**

Useful in a report: what you did, what happened, what you expected, and the
version or commit. A proof of concept helps; a full exploit chain is not
required. If you are unsure whether something counts, report it anyway.

We aim to acknowledge within **3 working days** and to describe the intended fix
and a timeline within **10 working days**. This is a small project — if a reply
is slow, a nudge is welcome rather than rude.

Reporters are credited in the release notes unless they ask not to be.

## Supported versions

| Version | Supported |
|---|---|
| 0.7.x-alpha | ✅ current alpha, fixes land on `main` |
| older | ❌ |

There is no long-term support branch yet. Until 1.0, security fixes are made on
`main` and released as a new alpha.

## What this release does and does not protect against

An alpha invites deployment, so the limits belong here rather than in a footnote.

**Held:** role-based access control including separation of duties; append-only,
hash-chained audit events with external anchoring and at-least-once SIEM
delivery; soft deletion so nothing is destroyed; encrypted secrets at rest
(NetBox token, TOTP seed); no forgeable source IPs; single-use TOTP codes; a
sign-in that does not confirm whether an account exists.

**Not held, deliberately or not yet:**

- The audit hash chain is **keyless**. Anyone who can *write* to the database can
  alter an event and recompute the chain from that point using the same public
  function, and by also deleting the checkpoints make it undetectable within the
  database. The load-bearing protection is externalisation to a SIEM. Without a
  configured SIEM sink, the chain protects against accidental corruption and
  careless tampering — not against an attacker with database write access.
- **TLS is not terminated by Permitra.** The shipped container speaks plain HTTP
  and expects a reverse proxy in front of it. Run it without one and the session
  token crosses the network in the clear.
- The session token lives in **localStorage**, so it is reachable by script
  injection. The Content-Security-Policy is the mitigation, not a guarantee.
- **Backups are unencrypted** and contain password hashes and API tokens.
- The containers **run as root** and without a read-only root filesystem.
- Permitra **never writes to network devices**. It produces configuration to
  apply; a compromise cannot change a firewall directly, but it can change what
  people believe the firewall should be doing — which is its own kind of damage,
  and why the audit trail matters.

## Scope

In scope: the application, its API, the shipped container images and deployment
manifests.

Out of scope: the public demo's data (it is fictional and reset regularly),
findings that require an account you were given for testing to attack itself,
and reports from automated scanners without a demonstrated impact.
