---
{
  "name": "cap_ssh",
  "description": "Run shell commands on configured SSH hosts after the user confirms them in Telegram or an allow rule covers them, and read, write, list and delete work files in a host's workdir over SFTP.",
  "metadata": {
    "cap_groups": [
      "cap_ssh"
    ],
    "manage_mode": "readonly"
  }
}
---

# SSH Command Execution

Use this skill when the user asks to run a command on, inspect, or administer one of the configured SSH hosts, and whenever you need to store work files (code, prototypes, downloads, generated data): those go to a host's workdir, not to the device flash.

## Available capabilities
- `ssh_exec`: run one shell command on a configured host and return its exit code and output.
- `remote_write_file`, `remote_read_file`, `remote_list`, `remote_mkdir`, `remote_delete`: file access over SFTP inside the host's workdir (see "Remote files").

## Calling rules
- Input is a JSON object with two required fields:

```json
{
  "host": "configured host name",
  "command": "uptime"
}
```

- `host` must be one of the names listed in the `ssh_exec` tool description. Do not pass IP addresses or hostnames.
- A call sends the exact command to the user's Telegram chat and waits up to 60 seconds for the user to approve it, unless the host's allow rules cover it. Tell the user what you are about to run and why before calling.
- The tool description lists each host's allow rules ("no prompt: df *, free *, uptime"). Prefer commands in exactly those forms; they run at once and the user only gets a notice.
- Only works for requests that came from Telegram, including sub-agents working for one (the prompt then names the sub-agent). Other channels and scheduled jobs, and their sub-agents, get an error.
- Prefer one short, non-interactive command per call. Commands that wait for input or run longer than 30 seconds are cut off.

## Allow rules
- A rule is a program plus an args pattern for one host: exact args, `*` for any args, or a glob with `*` and `?` matched against the arguments joined by single spaces (`*` also matches spaces). The program is compared as typed: `/usr/bin/df` and `df` are different.
- The command is tokenized like a shell (quotes, backslashes, collapsed whitespace) and split on `;`, `&&`, `||` and `|`. It runs without confirmation only if every part is covered by a rule and no part is hardline.
- Never auto-approved and without rule buttons: `$`, backticks, `(`, `)`, `<`, heredocs, process substitution, a lone `&`, newlines, unbalanced quotes, `VAR=value` prefixes, globs or braces in the program name, more than 8 parts, and output redirection other than to `/dev/null`, `&1` or `&2`.
- The confirmation offers "✅ Einmal", "🔁 Genau so" (an exact rule for each part not covered yet), "🔁 Immer: <prog> *" (a `*` rule per part) and "❌ Abbrechen".
- Telegram `/ssh allowed`, `/ssh allow <host> <program> [args|*]`, `/ssh revoke <n>` and `/ssh revoke all` manage the rules (at most 32 for all hosts).
- Hardline programs (compared by their name without path) always need confirmation, get no rule buttons, cannot get rules, and existing rules never match them: rm, rmdir, dd, mkfs*, shred, wipefs, fdisk, parted, chmod, chown, chattr, sudo, su, doas, pkexec, runuser, kill, killall, pkill, reboot, shutdown, poweroff, halt, init, telinit, mv, cp, tee, truncate, ln, tar, crontab, at, useradd, userdel, usermod, passwd, iptables, nft, ufw, firewall-cmd, apt, apt-get, dnf, yum, rpm, pip*, npm, snap, flatpak, curl, wget, nc, ncat, socat, ssh, scp, rsync, python*, perl, ruby, node, php, lua*, bash, sh, dash, zsh, ksh, fish, csh, tcsh, busybox, eval, exec, source, `.`, command, builtin, env, xargs, find, nohup, timeout, nice, ionice, stdbuf, time, watch, strace, chroot, setsid, unshare, nsenter, systemd-run, sed, awk, gawk, mawk, git, and the shell keywords and builtins `!`, if, then, else, elif, fi, case, esac, for, select, while, until, do, done, function, coproc, alias, export, declare, typeset, readonly, local, set, unset, shopt, hash, enable, trap.
- Hardline except for some subcommands: `docker`/`podman` unless the first argument is ps, logs, inspect, images or stats; `systemctl` unless it is status, is-active, is-enabled or list-units; `service` unless the second argument is status. Rules for them name the subcommand, for example `systemctl status *`. `journalctl` is allowed.

## Yolo mode
- The owner toggles it in Telegram with `/yolo`; the state is kept in NVS and survives reboots.
- It is global: while active, every confirmation is approved automatically, not only SSH. That covers `ssh_exec` (hardline programs and commands that cannot be parsed included), `remote_delete`, `http_request`, and WASM app installs and updates including firmware.
- `/yolo cron` is a second, independent toggle for work started by the scheduler. While it is on, scheduler-started agents (and their subagents) may use these tools too and are approved automatically, even with `/yolo` off. The notice goes to the request's Telegram chat if it has one, else to the first allowed chat. Without it, scheduler jobs get the "only available for requests from an allowed Telegram chat" error as before.
- Telegram still shows each prompt as a "⚡ Yolo" notice, without buttons and without rule buttons.
- Only the `/yolo` command from an allowed Telegram chat toggles them; the agent, Lua and router rules cannot, and cannot publish events as `cap_scheduler`.

## Remote files
- Only hosts with a `workdir` support them; the `remote_write_file` description lists them as `name (workdir)`. Other hosts get an error.
- `path` is relative to the workdir (`proto/main.py`), or absolute but inside it. `..` segments and control characters are rejected, and symlinks must resolve inside the workdir. `remote_list` without `path` lists the workdir.
- `remote_write_file {"host","path","content","append"?}` creates missing directories, overwrites the file or appends with `"append": true`. At most 64 KB of UTF-8 text per call; write larger files in parts with `append`. Returns `OK: wrote N bytes to host:path`.
- `remote_read_file {"host","path","offset"?,"max_bytes"?}` returns JSON with `size`, `offset`, `next_offset`, `eof` and `content`, at most 16 KB per call; continue with `offset` = `next_offset` until `eof`. Only UTF-8 text without NUL bytes is returned; binary files are refused with an error.
- `remote_list` returns `entries`, one per line: `name/` for directories, `name@` for symlinks, `name size` for files.
- `remote_mkdir` creates a directory and its missing parents.
- `remote_delete` removes a file, symlink or empty directory after the user confirms it in Telegram ("🗑 Löschen" / "❌ Abbrechen", 60 s).
- Writing, reading, listing and creating directories run without confirmation. Like `ssh_exec`, all remote tools work only for Telegram requests and their sub-agents.
- If the host is off or unreachable (connect failed), wake it with `wol_wake` (cap_wol skill), wait about a minute and retry.
- Use these tools instead of `ssh_exec` with redirections or heredocs, which always need confirmation.

## Output shape
- On success: JSON with `host`, `exit_code`, `stdout`, `stderr`, `truncated` (output is capped at 8 KB) and `timed_out` when the 30 s limit was hit.
- Errors start with `Error:`, for example `abgelehnt vom Benutzer` (the user pressed cancel), `Zeitüberschreitung` (no answer in 60 s), a host key fingerprint mismatch, or failed public key authentication.

## Common failure causes
- The user rejected the command: do not retry the same command unless the user asks.
- Public key authentication failed: the user must add the device key (Telegram `/ssh pubkey`) to the host's `authorized_keys`.
- Host key mismatch: the host key changed or the configured fingerprint is wrong. Do not work around it.
