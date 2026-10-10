---
{
  "name": "cap_http_request",
  "description": "Call allowlisted HTTP or HTTPS endpoints directly and return response status plus body text, or stream the response body to a file.",
  "metadata": {
    "cap_groups": [
      "cap_http_request"
    ],
    "manage_mode": "readonly"
  }
}
---

# HTTP Request

Use this skill when the task needs a direct HTTP or HTTPS request to a known endpoint instead of search-engine results.

## When to use
- The user needs raw API or file content from a specific URL.
- A workflow already knows the target endpoint and only needs a guarded fetch.
- The request should stay inside the device allowlist policy.

## Available capability
- `http_request`: send standard HTTP requests to allowlisted domains or IPs and return status plus body text, or save the response body directly to a file.
- `http_profiles`: list the configured API credential profiles (name, base_url, hosts). Secrets are never shown.

## API profiles (credentials)
- Never put API tokens into `headers`. For APIs with a configured profile, pass `profile` and either `path` (appended to the profile's `base_url`) or a full https `url` on one of the profile's `hosts`. The device injects the credentials.
- With `profile`, the profile's `hosts` replace the global allowlist, `Authorization` (and the profile's own auth header) supplied in `headers` is dropped, and redirects must stay on https and the profile's hosts. On a redirect to another host (e.g. a signed download URL) the credentials are not forwarded.
- `GET`/`HEAD` run directly. `POST`/`PUT`/`PATCH`/`DELETE` with a profile ask the user to confirm in Telegram and are refused outside an allowed Telegram chat.
- Exception: a `POST` whose path matches the profile's `read_only_posts` (configured by the user for read-only endpoints such as GraphQL queries or search) runs directly, everywhere.
- Service-specific guidance lives in the `cloudflare` and `gcloud` skills.

## Calling rules
- Only call `http_request` when the target host is expected to be in the configured allowlist.
- Input must be a JSON object:

```json
{
  "url": "https://api.example.com/v1/data",
  "method": "GET",
  "headers": {
    "Accept": "application/json"
  },
  "body": "",
  "timeout_ms": 15000,
  "max_body_bytes": 16384,
  "save_path": "/spiffs/download.bin",
  "max_file_bytes": 1048576
}
```

- `url` is required without `profile` and must start with `http://` or `https://`.
- JSON bodies (object or array) get `Content-Type: application/json` unless `headers` sets a content type.
- `method` defaults to `GET`.
- `body` is only valid for methods that accept a request body.
- `save_path` is optional. When present, the response body is streamed directly to this file and is not returned in memory.
- `max_body_bytes` applies only when returning the response body as text.
- `max_file_bytes` is optional and applies only when `save_path` is present.
- Redirects are allowed only when the redirect target also matches the allowlist.

## Output shape
- The capability returns plain text, not JSON.
- Success format:
  - `HTTP <status>`
  - followed by the response body text
- File-save success format:
  - `HTTP <status>`
  - `Saved response body to <path> (<bytes> bytes)`
- Common error strings include:
  - `Error: HTTP allowlist is empty; configure search_http_allowlist first`
  - `Error: host '...' is not in allowlist`
  - `Error: method must be GET/POST/PUT/PATCH/DELETE/HEAD`
  - `Error: save_path must be a non-empty string`
  - `Error: failed to open save_path`
  - `Error: http request failed (...)`
  - `Error: unknown API profile '...' (see http_profiles)`
  - `Error: host '...' is not allowed for profile '...'`
  - `Error: abgelehnt vom Benutzer` (mutation rejected in Telegram; do not retry)

## Examples

```json
{
  "url": "https://skills-lab.esp-claw.com/raw/tags.json"
}
```

```json
{
  "url": "https://api.example.com/v1/items",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json"
  },
  "body": "{\"name\":\"demo\"}"
}
```

```json
{
  "profile": "cloudflare",
  "path": "/zones?per_page=50"
}
```

```json
{
  "url": "https://example.com/file.bin",
  "save_path": "/spiffs/file.bin",
  "max_file_bytes": 10485760
}
```
