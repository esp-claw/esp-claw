---
{
  "name": "cap_ssh",
  "description": "Run shell commands on configured SSH hosts after the user confirms each command in Telegram.",
  "metadata": {
    "cap_groups": [
      "cap_ssh"
    ],
    "manage_mode": "readonly"
  }
}
---

# SSH Command Execution

Use this skill when the user asks to run a command on, inspect, or administer one of the configured SSH hosts.

## Available capability
- `ssh_exec`: run one shell command on a configured host and return its exit code and output.

## Calling rules
- Input is a JSON object with two required fields:

```json
{
  "host": "configured host name",
  "command": "uptime"
}
```

- `host` must be one of the names listed in the `ssh_exec` tool description. Do not pass IP addresses or hostnames.
- Every call sends the exact command to the user's Telegram chat and waits up to 60 seconds for the user to approve it. Tell the user what you are about to run and why before calling.
- Only works for requests that came from Telegram. Other channels, scheduled jobs and sub-agents get an error.
- Prefer one short, non-interactive command per call. Commands that wait for input or run longer than 30 seconds are cut off.

## Output shape
- On success: JSON with `host`, `exit_code`, `stdout`, `stderr`, `truncated` (output is capped at 8 KB) and `timed_out` when the 30 s limit was hit.
- Errors start with `Error:`, for example `abgelehnt vom Benutzer` (the user pressed cancel), `Zeitüberschreitung` (no answer in 60 s), a host key fingerprint mismatch, or failed public key authentication.

## Common failure causes
- The user rejected the command: do not retry the same command unless the user asks.
- Public key authentication failed: the user must add the device key (Telegram `/ssh pubkey`) to the host's `authorized_keys`.
- Host key mismatch: the host key changed or the configured fingerprint is wrong. Do not work around it.
