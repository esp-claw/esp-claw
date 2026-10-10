---
{
  "name": "gcloud",
  "description": "Inspect and manage Google Cloud (Compute Engine VMs, Cloud Run, Cloud Logging, Cloud Storage, billing budgets) through the configured gcloud API profile; also learns new Google Cloud endpoints.",
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

# Google Cloud API

Use this skill when the user asks about their Google Cloud project: VMs, Cloud Run services, logs/errors, storage buckets, budgets or costs.

## First steps
1. If the runtime skill `gcloud_custom` exists (see `list_skill`), activate it too. It holds endpoints learned earlier and cached ids (project id, zones, regions, billing account).
2. Call `http_profiles` to confirm a profile named `gcloud` exists. If not, tell the user to add a `google_service_account` profile to `api_profiles` in the device config. Never ask the user to paste keys into the chat.
3. You need the project id. Use the one in `gcloud_custom`; otherwise ask the user or list projects (`GET https://cloudresourcemanager.googleapis.com/v1/projects`, needs permission) and store it in `gcloud_custom`.

## How to call
Call `http_request` with `"profile": "gcloud"`. The device signs a service-account JWT, exchanges it for an OAuth access token (cached about one hour) and injects it.
- Use `path` for the profile's `base_url` (`https://compute.googleapis.com`), or a full `url` on another `*.googleapis.com` host (Cloud Run, Logging, Storage, Billing Budgets).

```json
{"profile": "gcloud", "path": "/compute/v1/projects/<project>/aggregated/instances?maxResults=50"}
{"profile": "gcloud", "url": "https://run.googleapis.com/v2/projects/<project>/locations/-/services"}
```

- Never send an `Authorization` header; the device drops it.
- `GET`/`HEAD` run immediately. `POST`/`PUT`/`PATCH`/`DELETE` ask the user for confirmation in Telegram (✅ Einmal / ❌ Abbrechen) and only work in an allowed Telegram chat. This includes read-only POST calls such as `entries:list`, unless the profile lists them in `read_only_posts`. "abgelehnt vom Benutzer" means: stop, do not retry.
- JSON bodies go as a string in `body`; `Content-Type: application/json` is added automatically.
- "system clock is not set yet" means the device has no SNTP time yet; wait and retry later.
- "token endpoint returned HTTP 400 invalid_grant" usually means a wrong/revoked key or a clock skew.

## Response format
- Errors: `{"error": {"code": 403, "message": "...", "status": "PERMISSION_DENIED", "details": [...]}}`. `SERVICE_DISABLED` / "API has not been used in project" means the user must enable that API in the service account's project. `PERMISSION_DENIED` means the service account lacks an IAM role. Report the `message`.
- Pagination: pass `pageToken=<nextPageToken>` until `nextPageToken` is absent. Page size is `maxResults` (Compute, Storage) or `pageSize` (Run, Logging, Budgets).
- Responses can be large: use `fields=` (partial response, e.g. `fields=items(name,status)`), filters and `max_body_bytes` (up to 65535).
- Compute and Cloud Run changes return a long-running operation; check its `status`/`done` later if the user asks.

## Core endpoints
| Purpose | Method | Host + path | Notes |
|---|---|---|---|
| List all VMs (all zones) | GET | compute: `/compute/v1/projects/{project}/aggregated/instances` | `items` is a map `zones/<zone>` -> `{instances:[...]}`; add `returnPartialSuccess=true`, `filter=status%20%3D%20RUNNING` (URLs must not contain spaces: percent-encode) |
| List VMs in a zone | GET | compute: `/compute/v1/projects/{project}/zones/{zone}/instances` | |
| Get VM | GET | compute: `/compute/v1/projects/{project}/zones/{zone}/instances/{name}` | `status`: RUNNING, TERMINATED, ... |
| Start VM | POST | compute: `/compute/v1/projects/{project}/zones/{zone}/instances/{name}/start` | no body; returns an operation |
| Stop VM | POST | compute: `/compute/v1/projects/{project}/zones/{zone}/instances/{name}/stop` | no body; returns an operation |
| List Cloud Run services | GET | `https://run.googleapis.com/v2/projects/{project}/locations/{region}/services` | `-` as region lists all regions |
| Get Cloud Run service | GET | `https://run.googleapis.com/v2/projects/{project}/locations/{region}/services/{service}` | `uri`, `latestReadyRevision`, `conditions` |
| Read logs | POST | `https://logging.googleapis.com/v2/entries:list` | body below; needs confirmation (POST) unless listed in `read_only_posts` |
| List buckets | GET | `https://storage.googleapis.com/storage/v1/b?project={project}` | |
| List objects | GET | `https://storage.googleapis.com/storage/v1/b/{bucket}/o?prefix=&maxResults=100` | URL-encode `/` in names as `%2F` when used in a path |
| List budgets | GET | `https://billingbudgets.googleapis.com/v1/billingAccounts/{billing_account_id}/budgets` | needs Billing Account viewer rights for the service account on that billing account; billing account id format `XXXXXX-XXXXXX-XXXXXX` |

Logging body example (last errors, newest first; set the timestamp to a recent time):

```json
{"profile": "gcloud", "method": "POST", "url": "https://logging.googleapis.com/v2/entries:list",
 "body": "{\"resourceNames\":[\"projects/<project>\"],\"filter\":\"severity>=ERROR AND timestamp>=\\\"2026-10-10T00:00:00Z\\\"\",\"orderBy\":\"timestamp desc\",\"pageSize\":20}"}
```

Uncertain, verify on first use and record the result in `gcloud_custom`: the `locations/-` wildcard for Cloud Run v2, and whether billing budgets need an `x-goog-user-project` header for this service account.

## Learning new endpoints
When the user needs something not covered above or in `gcloud_custom`:
1. Look up the official docs: `web_search` with `site:cloud.google.com <service> REST API <method>`, then read the reference page with a plain `http_request` GET (no profile) to `https://cloud.google.com/...` if the HTTP allowlist permits it. Use only documented endpoints on `*.googleapis.com`.
2. Try the endpoint through the profile, read-only (`GET`) first when possible.
3. After a successful call, record it in the runtime skill `gcloud_custom`:
   - If `skills/gcloud_custom/SKILL.md` does not exist, create it with `write_file` at `<data root>/skills/gcloud_custom/SKILL.md` (data root is usually `/fatfs`; check with `list_files` if unsure) using the template below, then call `register_skill` with `{"skill_id":"gcloud_custom","file":"gcloud_custom/SKILL.md"}`.
   - If it exists, `read_file` it, add or update one table row (no duplicates), `write_file` it back, and call `register_skill` again to refresh.
   - Also keep stable ids there (project id, regions, zones, billing account id).
4. Tell the user which endpoint was learned.

Learning only adds documentation. It never changes credentials, hosts, scopes or profiles; those are configured natively on the device by the user and cannot be edited from chat. Never write tokens, keys, Authorization headers or secrets into the custom skill, and only record endpoints on the profile's hosts.

Template for `gcloud_custom/SKILL.md`:

````md
---
{
  "name": "gcloud_custom",
  "description": "Google Cloud endpoints and ids learned on this device; use together with the gcloud skill.",
  "metadata": {
    "cap_groups": ["cap_http_request"],
    "manage_mode": "runtime"
  }
}
---

# Google Cloud: learned endpoints

Call with `http_request` and `"profile": "gcloud"` as described in the `gcloud` skill.

## Notes
- project: <project-id>

## Endpoints
| Purpose | Method | Host + path | Key params | Example | Verified |
|---|---|---|---|---|---|
| List Cloud SQL instances | GET | https://sqladmin.googleapis.com/v1/projects/{project}/instances | | `{"profile":"gcloud","url":"https://sqladmin.googleapis.com/v1/projects/<project>/instances"}` | 2026-10-10 |
````
