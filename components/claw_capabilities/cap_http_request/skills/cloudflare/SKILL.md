---
{
  "name": "cloudflare",
  "description": "Manage Cloudflare (zones, DNS records, cache purge, Workers, Tunnels, R2, Pages, analytics) through the configured cloudflare API profile; also learns new Cloudflare endpoints.",
  "metadata": {
    "cap_groups": [
      "cap_http_request",
      "cap_files",
      "cap_skill",
      "cap_web_search"
    ],
    "manage_mode": "readonly"
  }
}
---

# Cloudflare API

Use this skill when the user asks about their Cloudflare account: domains/zones, DNS records, cache, Workers, Tunnels, R2, Pages, traffic analytics, or the API token.

## First steps
1. If the runtime skill `cloudflare_custom` exists (see `list_skill`), activate it too. It holds endpoints learned earlier and cached ids (account id, zone ids). Prefer its notes over guessing.
2. Call `http_profiles` to confirm a profile named `cloudflare` exists. If it does not, tell the user to add it to `api_profiles` in the device config. Never ask the user to paste a token into the chat.

## How to call
Always call `http_request` with `"profile": "cloudflare"` and a `path` relative to the profile's `base_url` (`https://api.cloudflare.com/client/v4`). The device injects the API token itself.

```json
{"profile": "cloudflare", "path": "/zones?per_page=50"}
```

- Never send an `Authorization` header or a token; the device drops it.
- `GET`/`HEAD` run immediately. `POST`/`PUT`/`PATCH`/`DELETE` ask the user for confirmation in Telegram (✅ Einmal / ❌ Abbrechen) and only work in an allowed Telegram chat. Explain what you are about to change before calling. "abgelehnt vom Benutzer" means: stop, do not retry.
- JSON bodies are sent as a string in `body`; `Content-Type: application/json` is added automatically.
- Use `max_body_bytes` (up to 65535) for large lists, or narrow the query with filters.

## Account id and token check
The token is an account-owned API token. `GET /user/tokens/verify` fails for it; that is expected.
1. `GET /accounts` returns the account(s); take `result[0].id` as `{account_id}` (ask the user if several).
2. Store the account id in the notes of `cloudflare_custom` (see "Learning new endpoints") so later turns can skip this call.
3. Token check: `GET /accounts/{account_id}/tokens/verify` (`result.status` should be `active`).

## Response format
Every v4 REST response is an envelope:

```json
{"success": true, "errors": [], "messages": [], "result": [...],
 "result_info": {"page": 1, "per_page": 20, "count": 20, "total_count": 42, "total_pages": 3}}
```

- Check `success`. On failure read `errors[].code` and `errors[].message`. Common cases: `HTTP 403` with code `10000` means the token lacks the permission for this resource; `HTTP 400` usually means a bad parameter; `HTTP 404`/code `7003` means a wrong id or path.
- Pagination: `page` (from 1) and `per_page` query parameters; follow `result_info.total_pages`. Some newer endpoints use a cursor instead (`result_info.cursor`; pass it back as `cursor=`).

## Core endpoints
`{zone_id}` comes from the zone list, `{account_id}` from `/accounts`.

| Purpose | Method | Path | Notes |
|---|---|---|---|
| List accounts | GET | `/accounts` | gives `{account_id}` |
| Verify token | GET | `/accounts/{account_id}/tokens/verify` | account-owned token |
| List zones | GET | `/zones?per_page=50` | filter `name=example.com`, `status=active` |
| Zone details | GET | `/zones/{zone_id}` | |
| List DNS records | GET | `/zones/{zone_id}/dns_records?per_page=100` | filter `type=A`, `name=www.example.com` (full name), `content=` |
| Create DNS record | POST | `/zones/{zone_id}/dns_records` | body `{"type":"A","name":"www","content":"203.0.113.10","ttl":1,"proxied":true}`; `ttl` 1 = automatic |
| Update DNS record | PATCH | `/zones/{zone_id}/dns_records/{record_id}` | send only the changed fields; PUT replaces the whole record |
| Delete DNS record | DELETE | `/zones/{zone_id}/dns_records/{record_id}` | |
| Purge cache | POST | `/zones/{zone_id}/purge_cache` | `{"purge_everything":true}` or `{"files":["https://example.com/a.css"]}` |
| List Workers scripts | GET | `/accounts/{account_id}/workers/scripts` | |
| List Tunnels | GET | `/accounts/{account_id}/cfd_tunnel?is_deleted=false` | `status`: `healthy`, `degraded`, `down`, `inactive` |
| Tunnel status | GET | `/accounts/{account_id}/cfd_tunnel/{tunnel_id}` | connections: `.../cfd_tunnel/{tunnel_id}/connections` |
| List R2 buckets | GET | `/accounts/{account_id}/r2/buckets` | cursor pagination; objects are not listed via this API (S3 API) |
| List Pages projects | GET | `/accounts/{account_id}/pages/projects` | deployments: `.../pages/projects/{project_name}/deployments` |
| Traffic analytics | POST | `/graphql` | GraphQL, see below |

### Analytics (GraphQL)
The old REST zone analytics endpoints are retired; use the GraphQL Analytics API at `POST /graphql` with `{"query": "...", "variables": {...}}`. Because it is a POST, the device asks for Telegram confirmation even though it only reads. Example (daily requests, last days):

```json
{"profile": "cloudflare", "method": "POST", "path": "/graphql",
 "body": "{\"query\":\"query($zone:String!,$since:Date!){viewer{zones(filter:{zoneTag:$zone}){httpRequests1dGroups(limit:7,filter:{date_geq:$since}){dimensions{date} sum{requests bytes threats} uniq{uniques}}}}}\",\"variables\":{\"zone\":\"<zone_id>\",\"since\":\"2026-01-01\"}}"}
```

GraphQL errors arrive as `HTTP 200` with an `errors` array; available datasets depend on the plan.

## Learning new endpoints
When the user needs something not covered above or in `cloudflare_custom`:
1. Look up the official docs: `web_search` with `site:developers.cloudflare.com <topic> API`, then read the page with a plain `http_request` GET (no profile) to `https://developers.cloudflare.com/api/...` if the HTTP allowlist permits it. Use only documented endpoints.
2. Try the endpoint through the profile, read-only (`GET`) first when possible.
3. After a successful call, record it in the runtime skill `cloudflare_custom`:
   - If `skills/cloudflare_custom/SKILL.md` does not exist, create it with `write_file` at `<data root>/skills/cloudflare_custom/SKILL.md` (data root is usually `/fatfs`; check with `list_files` if unsure) using the template below, then call `register_skill` with `{"skill_id":"cloudflare_custom","file":"cloudflare_custom/SKILL.md"}`.
   - If it exists, `read_file` it, add or update one table row (no duplicates), `write_file` it back, and call `register_skill` again to refresh.
   - Also keep stable ids there (account id, zone ids by name).
4. Tell the user which endpoint was learned.

Learning only adds documentation. It never changes credentials, hosts or profiles; those are configured natively on the device by the user and cannot be edited from chat. Never write tokens, Authorization headers or secrets into the custom skill, and only record endpoints on the profile's hosts.

Template for `cloudflare_custom/SKILL.md`:

````md
---
{
  "name": "cloudflare_custom",
  "description": "Cloudflare endpoints and ids learned on this device; use together with the cloudflare skill.",
  "metadata": {
    "cap_groups": ["cap_http_request"],
    "manage_mode": "runtime"
  }
}
---

# Cloudflare: learned endpoints

Call with `http_request` and `"profile": "cloudflare"` as described in the `cloudflare` skill.

## Notes
- account_id: <id>

## Endpoints
| Purpose | Method | Path | Key params | Example | Verified |
|---|---|---|---|---|---|
| List Workers routes | GET | /zones/{zone_id}/workers/routes | | `{"profile":"cloudflare","path":"/zones/<zone_id>/workers/routes"}` | 2026-10-10 |
````
