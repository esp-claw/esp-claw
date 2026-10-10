---
{
  "name": "cap_system",
  "description": "Read live device status: CPU load, tasks, memory, Wi-Fi, network, reset cause, storage, temperature and claw runtime counts.",
  "metadata": {
    "cap_groups": [
      "cap_system"
    ],
    "manage_mode": "readonly"
  }
}
---

# Device status

Use this skill when the user asks how the device is doing: load, memory, connectivity, why it rebooted, free space, temperature, or what the agent runtime is running.

## Available capability
- `get_system_info`: returns live JSON. Never guess values; call the tool.

## Calling rules
- Input: `{"sections": ["cpu", "tasks"]}`. Omit `sections` for a summary (chip, uptime, version, memory, cpu, wifi, ip, reset, storage).
- Request only the sections you need. `cpu` and `tasks` block for about 500 ms to measure load; requesting both shares one window.

## Sections
- `memory`: `internal_*`, `dma_*`, `psram_*` free / `min_free` (lowest since boot) / `largest_free_block` in bytes. A largest block far below free means fragmentation.
- `cpu`: `usage_percent` (average of both cores), `per_core_percent` [core0, core1] over the last 500 ms, `since_boot_percent` (null after ~71 min uptime).
- `tasks`: top 25 tasks by CPU: `name`, `state`, `priority`, `core` (0, 1 or "any"), `cpu_percent` (of one core), `stack_min_free_bytes`. Under ~512 bytes of stack headroom is a crash risk.
- `wifi`: `ssid`, `bssid`, `rssi`, `channel`, `phy_mode`, `disconnect_count` (since boot), `ap_active`, `ap_stations`.
- `ip` / `network`: address info; `network` adds `sockets_open`/`sockets_max`, `gateway`, `netmask`, `dns`.
- `reset`: `reason` (e.g. `power_on`, `software`, `panic`, `task_watchdog`, `brownout`), `boot_count`, `coredump` ("disabled" or crash summary).
- `storage`: `fs_total`/`fs_free` of the data partition, `inbox_bytes`/`inbox_files` (IM attachments), `nvs` entries, `app` partition and image size, `ota_slot_available`.
- `temperature`: `chip_celsius` (internal sensor, not ambient; reads warmer than the room).
- `claw`: `capabilities`, `cap_groups`, `skills`, `lua_async_jobs`, `session_subagents` (sub-agents of the current session only).
