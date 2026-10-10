# Security policy

This policy covers the firmware in [esp-claw/esp-claw](https://github.com/esp-claw/esp-claw), an unofficial community fork of [espressif/esp-claw](https://github.com/espressif/esp-claw) that is not affiliated with Espressif. The organization-wide policy, including the threat model and known limitations, is in [esp-claw/.github](https://github.com/esp-claw/.github/blob/main/SECURITY.md).

## Reporting a vulnerability

Do not open a public issue. Report privately through GitHub: go to **Security > Advisories** in this repository and click **Report a vulnerability** ([GitHub documentation](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)).

Please include the firmware version (`/fw` shows it) or commit, the board, the configuration involved (without secrets) and the steps to reproduce. This is a volunteer project: expect an acknowledgement within a few days. We will coordinate a fix and a disclosure date with you.

## Scope

In scope:

- the firmware: all code this fork adds or changes, and upstream code as it is shipped here
- the signing tooling (`tools/fwsign.py`) and the on-device verification of firmware images and WASM app packages
- the web UI and its API, WebDAV, and the Telegram login (`/web`)
- the Telegram gateway: sender allowlist, commands and confirmations
- the release and CI workflows in `.github/workflows`

Out of scope:

- vulnerabilities in upstream code that this fork does not change: report them to Espressif through [espressif/esp-claw](https://github.com/espressif/esp-claw) (if the fork ships the same code, tell us as well)
- attacks that need physical access to the device; flash encryption and secure boot are not enabled by default
- vulnerabilities in third-party services (Telegram, LLM providers, GitHub and others) or in vendored libraries that are not caused by how esp-claw uses them
- the LLM doing something an allowed Telegram user asked it to do

## Supported versions

Only the latest release is supported. Fixes go into `master` and the next release; there are no backports. Devices can update with `/fw update`.

## Firmware signing key

Release images are signed with Ed25519. Devices install an OTA image only if its detached signature (`edge_agent.bin.sig.json`) verifies against a key in `app_trusted_keys`.

| | |
|---|---|
| Key ID | `7087d6a8` |
| Public key (base64, raw 32 bytes) | `XHQYDdKaRZ6pNzXYcrGAB8bTyPa3D22NU+lVzAt2Acw=` |

The maintainer keeps the private key outside the repositories. It is never stored in this repository, in GitHub secrets or in CI: CI builds the unsigned image and the maintainer signs it locally with `tools/fwsign.py`. To check a release by hand:

```bash
python tools/fwsign.py verify edge_agent.bin edge_agent.bin.sig.json --pub XHQYDdKaRZ6pNzXYcrGAB8bTyPa3D22NU+lVzAt2Acw=
```

If the key is ever compromised or replaced, the new public key will be announced in a release note and in this file, and the old key should be removed from `app_trusted_keys`.
