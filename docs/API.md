# API and automation

Permitra is API-first, so external tools can use it as the source of truth.
Full interactive documentation is at `/docs` on a running instance (OpenAPI).

## Key API endpoints

| Method & path | Purpose |
|---|---|
| `POST /api/auth/login` | Login (OAuth2 form, optional `otp` field), returns JWT |
| `GET /api/rules?q=&source=&destination=&port=&protocol=&status=&component=&impl=&vrf=` | Search/filter with pagination |
| `POST /api/rules` · `PUT /api/rules/{id}` | Create/update (architect), versioned. A new rule is prefilled to expire in a year |
| `POST /api/rules/emergency` | Document a rule already opened on the device (architect, operations) — mandatory reason, into review, time-limited |
| `POST /api/rules` with `ping_baseline: true` | The one broad rule that is allowed: any-to-any, ICMP echo only, between two **internal** zones the matrix already permits. It names its two zones (`source_zone`/`destination_zone`) instead of deriving them — its addresses are `any`, which has no network to derive from — and its components follow from those zones and the topology between them. A declaration that does not hold is a 422 naming every reason |
| `POST /api/rules/{id}/submit\|approve\|reject\|deactivate` | Review workflow. `approve`/`reject` are change-approver only, and four eyes are enforced on the acting **account**: whoever requested, created, edited or submitted the rule in the current review cycle cannot approve it, whichever roles that account holds |
| `GET /api/rules/applications/summary` | The applications rules were opened for, with their in-force counts |
| `POST /api/rules/applications/{app_id}/retire` | Propose every in-force rule of a retired application for removal (architect). **`dry_run` defaults to `true`** — a call without it reports what would happen and changes nothing |
| `PUT /api/rules/{id}/impl-status` | Implementation status per component (operations) |
| `GET /api/rules/{id}/conflicts` | Conflict warnings — overlap, duplicate, permit/deny shadowing. Only against rules on the **same zone transition**, directional: two rules enforced on different policies cannot shadow each other, however their addresses look. Rules carrying no zones (legacy imports) are compared on their addresses alone |
| `GET /api/rules/path-search?src=&dst=` | All rules touching an address, in both directions |
| `GET /api/rules/path-analysis?src=&dst=` | Which firewalls the traffic crosses and whether it gets through. The hops are **routed over the documented component links**, not ordered by tier: `routing` is `routed`, `no_route` (the links connect no way between them — a finding) or `not_documented` (no links recorded, so the order falls back to the north-south tiering). `routes` lists every shortest route, because a rule present on one redundant route and missing on the other holds until the failover; `route_gaps` names the clusters on a route that no approved rule covers. A hop neither address sits behind is marked `transit` |
| `GET /api/zones/…` | Zones, overview, matrix, batch requests, network mapping |
| `GET /api/recertification/campaigns` · `POST …` · `POST …/{id}/close` | Recertification. Reading is open to the working roles; **starting and closing a campaign is change-approver only** — not the admin |
| `GET /api/reports/evidence` · `/evidence.csv` | Evidence report for an audit: every change in a period, optionally by zone or application, with requester, approver, justification and date, plus the chain-integrity statement |
| `GET /api/export/{fmt}` | `csv`, `json`, `juniper`, `checkpoint-cli`, `checkpoint-api`, `aci-json`, `aci-yaml` |
| `GET /api/export/aerleon/{target}` | Capirca/Aerleon targets incl. `policy` YAML |
| `GET /api/export/host/{os}?ip=` | Host firewall config for a target server |

## Read-only API tokens (Ansible/Terraform)

Create a **read-only API token** in the admin area (shown once). Tokens allow only `GET` requests
(writes return 403) and never expose admin endpoints. Use `updated_since` for efficient polling.

Ask for `status=approved,active`, not `approved` alone: a rule becomes `active` as soon as
operations marks it implemented, and it is still in force. `status` takes several values,
comma-separated. For a complete, unpaginated set per component or application, `GET
/api/export/json?component_id=&app_id=` applies the same in-force filter.

```yaml
# Ansible
- name: Read the rules in force from Permitra
  ansible.builtin.uri:
    url: "https://permitra.example.org/api/rules?status=approved,active&component=FW-Cluster-BER"
    headers:
      Authorization: "Bearer {{ permitra_token }}"
  register: permitra
# permitra.json.items is the source of truth for templates/modules
```

```hcl
# Terraform
data "http" "permitra_rules" {
  url             = "https://permitra.example.org/api/rules?status=approved,active"
  request_headers = { Authorization = "Bearer ${var.permitra_token}" }
}
locals { rules = jsondecode(data.http.permitra_rules.response_body).items }
```

Endpoints: `GET/POST/DELETE /api/api-tokens` (admin). The token itself is authenticated via
`Authorization: Bearer pat_…`.

## Change management integration (optional)

Permitra sends a JSON webhook on the steps of a rule's life a change process cares about. Delivery runs on a thread, never blocks the operation, retries twice (after 10 s and 60 s) and then gives up with an error in the log - so an adapter that must not miss anything reconciles by polling `GET /api/rules?updated_since=`.

```bash
CHANGE_WEBHOOK_URL=https://instance.service-now.com/api/x_permitra/change   # empty = off
CHANGE_WEBHOOK_TOKEN=…    # optional, sent as "Authorization: Bearer"
CHANGE_WEBHOOK_SECRET=…   # optional; body signed with HMAC-SHA256, sent as "X-Permitra-Signature: sha256=<hex>"
```

Events: `rule.submitted`, `rule.approved`, `rule.rejected`, `rule.deactivated`, `rule.delete_approved`, `rule.emergency_declared`, `rule.implementation` (the implementation status changed; `status` says whether the rule is `active` now), `rule.removal_proposed` (an application was retired, or a network move made the rule inadmissible), `rule.expired`, `rule.emergency_expired`, `zone_change.approved`, `zone_change.rejected`. Payload: `{"event": …, "source": "permitra", "timestamp": …, "data": {…}}` - for rules this includes rule ID, zones, addresses, services, components, their `enforcement` (firewall / micro-segmentation) and `change_id`; for batch requests the batch ID and individual changes.

**Writing the ticket number back**: `PATCH /api/rules/{id}/change-id` with `{"change_id": "CHG0042"}` (roles architect, operations or change approver). It changes that one field, records a version and an audit event (`rule.change_id_set`), and leaves the approval standing - unlike `PUT /api/rules/{id}`, which is a content edit and resets an approved rule to draft. Use a dedicated service account with the operations role for the adapter. Implementation: `backend/app/change_management.py`. The complete functionality is also available as a REST API (`/docs`) for CMDB/ticket integrations.
