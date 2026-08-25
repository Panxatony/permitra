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
| `POST /api/rules/{id}/submit\|approve\|reject\|deactivate` | Review workflow. `approve`/`reject` are change-approver only, and four eyes are enforced on the acting **account**: whoever requested, created or submitted the rule cannot approve it, whichever roles that account holds |
| `GET /api/rules/applications/summary` | The applications rules were opened for, with their in-force counts |
| `POST /api/rules/applications/{app_id}/retire` | Propose every in-force rule of a retired application for removal (architect). **`dry_run` defaults to `true`** — a call without it reports what would happen and changes nothing |
| `PUT /api/rules/{id}/impl-status` | Implementation status per component (operations) |
| `GET /api/rules/{id}/conflicts` | Conflict warnings |
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

```yaml
# Ansible
- name: Read approved rules from Permitra
  ansible.builtin.uri:
    url: "https://permitra.example.org/api/rules?status=approved&component=FW-Cluster-BER"
    headers:
      Authorization: "Bearer {{ permitra_token }}"
  register: permitra
# permitra.json.items is the source of truth for templates/modules
```

```hcl
# Terraform
data "http" "permitra_rules" {
  url             = "https://permitra.example.org/api/rules?status=approved"
  request_headers = { Authorization = "Bearer ${var.permitra_token}" }
}
locals { rules = jsondecode(data.http.permitra_rules.response_body).items }
```

Endpoints: `GET/POST/DELETE /api/api-tokens` (admin). The token itself is authenticated via
`Authorization: Bearer pat_…`.

## Change management integration (optional)

Permitra sends a JSON webhook on approval events (fire-and-forget, never blocks):

```bash
CHANGE_WEBHOOK_URL=https://instance.service-now.com/api/x_permitra/change   # empty = off
CHANGE_WEBHOOK_TOKEN=…   # optional, sent as "Authorization: Bearer"
```

Events: `rule.submitted`, `rule.approved`, `rule.rejected`, `zone_change.approved`, `zone_change.rejected`. Payload: `{"event": …, "source": "permitra", "timestamp": …, "data": {…}}` — for rules this includes rule ID, zones, addresses, services, components and `change_id`; for batch requests the batch ID and individual changes. A ServiceNow adapter can create the change ticket and write the ticket number back into `change_id` via `PUT /api/rules/{id}`. Implementation: `backend/app/change_management.py`. The complete functionality is also available as a REST API (`/docs`) for CMDB/ticket integrations.
