---
{
  "name": "cap_wol",
  "description": "Wake configured machines on the local network with a Wake-on-LAN magic packet.",
  "metadata": {
    "cap_groups": [
      "cap_wol"
    ],
    "manage_mode": "readonly"
  }
}
---

# Wake-on-LAN

Use this skill when the user asks to wake up, power on, or start one of the configured machines.

## Available capability
- `wol_wake`: send a Wake-on-LAN magic packet to a configured target.

## Calling rules
- Input is a JSON object with one required field:

```json
{
  "target": "configured target name"
}
```

- `target` must be one of the names listed in the `wol_wake` tool description. Do not pass MAC or IP addresses.
- The packet is sent three times about 100 ms apart. There is no reply from the target, so `sent: true` only means the packet left the device, not that the machine is up.
- To check whether the machine woke up, wait 30 to 60 seconds and use another tool (for example `ssh_exec`) if one is available.

## Output shape
- On success: JSON with `target`, `mac`, `broadcast`, `port` and `sent: true`.
- Errors start with `Error:`, for example an unknown target name or an invalid entry in the configuration.

## Common failure causes
- The target is on Wi-Fi only, is fully powered off without WoL support, or has WoL disabled in BIOS/OS.
- The router or access point blocks broadcasts between clients (client isolation) or does not forward them to the wired LAN.
