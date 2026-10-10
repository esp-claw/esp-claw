#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 esp-claw contributors
# SPDX-License-Identifier: Apache-2.0
"""Check an app's manifest.json against the rules the esp-claw firmware applies.

  manifest_check.py <manifest.json | app_dir> [--dir-name NAME]

Keep in sync with the firmware (esp-claw, components/claw_capabilities/cap_wasm_apps/src/):
  cap_wasm_manifest.c  cap_wasm_manifest_parse(), cap_wasm_parse_permissions(), cap_wasm_name_valid()
  cap_wasm_manifest.h  CAP_WASM_*_MAX / _MIN / _DEFAULT limits
  cap_wasm_pkg.c/.h    cap_wasm_version_parse() (installer version order), CAP_WASM_MANIFEST_MAX
--dir-name additionally checks that name equals the device directory apps/<name>/ (the installer
always uses the manifest name, so this only matters for files copied by hand).
"""
import argparse
import json
import os
import re
import sys

MANIFEST_MAX = 4096          # CAP_WASM_MANIFEST_MAX (package entry limit)
NAME_MAX = 24                # CAP_WASM_APP_NAME_MAX
VERSION_MAX = 16             # CAP_WASM_VERSION_MAX
DESC_MAX = 200               # CAP_WASM_DESC_MAX (bytes)
PROFILE_NAME_MAX = 31        # CAP_WASM_PROFILE_NAME_MAX
MAX_PROFILES = 4             # CAP_WASM_MAX_PROFILES
MEMORY_KB = (64, 512)        # 64 .. CAP_WASM_MEMORY_KB_MAX, multiple of 64
CALL_MS = (100, 30000)       # CAP_WASM_CALL_MS_MIN .. CAP_WASM_CALL_MS_MAX

KEYS = {"name", "version", "description", "permissions", "limits"}
BOOL_PERMS = {"log", "kv", "confirm", "ping"}
PERMS = BOOL_PERMS | {"http_profiles"}
LIMIT_KEYS = {"memory_kb", "call_timeout_ms"}

NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
VERSION_CHARS_RE = re.compile(r"^[A-Za-z0-9.+-]+$")
# cap_wasm_version_parse(): N.N.N, optional -PRE (no '+'), optional +BUILD (non-empty).
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[^+]+)?(\+.+)?$")
PROFILE_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def is_int(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and float(v).is_integer()


def check(manifest, dir_name=None):
    """Returns a list of error strings (empty when the manifest is valid)."""
    if not isinstance(manifest, dict):
        return ["manifest.json is not a JSON object"]
    errors = [f"unknown manifest key '{k}'" for k in manifest if k not in KEYS]

    for field, limit, required in (("name", NAME_MAX, True), ("version", VERSION_MAX, True),
                                   ("description", DESC_MAX, False)):
        value = manifest.get(field)
        if value is None:
            if required:
                errors.append(f"{field} is required")
        elif not isinstance(value, str) or (required and not value) or len(value.encode()) > limit:
            errors.append(f"{field} must be a string of {'' if required else '0/'}1-{limit} bytes")

    name, version = manifest.get("name"), manifest.get("version")
    if isinstance(name, str) and name and not NAME_RE.match(name):
        errors.append(f"name must be 1-{NAME_MAX} chars of [a-z0-9_] starting with a letter")
    if dir_name is not None and name != dir_name:
        errors.append(f"name '{name}' does not match the app directory '{dir_name}'")
    if isinstance(version, str) and version:
        if not VERSION_CHARS_RE.match(version):
            errors.append("version may only contain [A-Za-z0-9.+-]")
        elif not SEMVER_RE.match(version):
            errors.append("version must be MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD] (installer, ecapp.py)")

    perms = manifest.get("permissions")
    if perms is not None:
        if not isinstance(perms, dict):
            errors.append("permissions must be an object")
        else:
            errors += [f"unknown permission '{k}'" for k in perms if k not in PERMS]
            errors += [f"permissions.{k} must be a boolean"
                       for k in sorted(BOOL_PERMS) if k in perms and not isinstance(perms[k], bool)]
            profiles = perms.get("http_profiles")
            if profiles is not None:
                if not isinstance(profiles, list) or not 1 <= len(profiles) <= MAX_PROFILES:
                    errors.append(f"permissions.http_profiles must be an array of 1-{MAX_PROFILES} profile names")
                else:
                    for p in profiles:
                        if not isinstance(p, str) or len(p) > PROFILE_NAME_MAX or not PROFILE_RE.match(p):
                            errors.append("permissions.http_profiles entries must be profile names "
                                          f"(1-{PROFILE_NAME_MAX} chars of [A-Za-z0-9_-])")
                    dups = sorted({p for p in profiles if isinstance(p, str) and profiles.count(p) > 1})
                    errors += [f"permissions.http_profiles lists '{p}' twice" for p in dups]

    limits = manifest.get("limits")
    if limits is not None:
        if not isinstance(limits, dict):
            errors.append("limits must be an object")
        else:
            errors += [f"unknown limit '{k}'" for k in limits if k not in LIMIT_KEYS]
            for key, (lo, hi) in (("memory_kb", MEMORY_KB), ("call_timeout_ms", CALL_MS)):
                v = limits.get(key)
                if v is not None and (not is_int(v) or not lo <= v <= hi):
                    errors.append(f"limits.{key} must be an integer in [{lo}, {hi}]")
            mem = limits.get("memory_kb")
            if is_int(mem) and MEMORY_KB[0] <= mem <= MEMORY_KB[1] and mem % 64:
                errors.append("limits.memory_kb must be a multiple of 64 (one WASM page)")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", help="manifest.json or the directory containing it")
    parser.add_argument("--dir-name", help="require name to equal this device directory name")
    args = parser.parse_args()
    path = os.path.join(args.path, "manifest.json") if os.path.isdir(args.path) else args.path
    with open(path, "rb") as f:
        raw = f.read()
    errors = [f"manifest.json is {len(raw)} bytes, the package limit is {MANIFEST_MAX}"] if len(raw) > MANIFEST_MAX else []
    try:
        errors += check(json.loads(raw), args.dir_name)
    except ValueError as e:
        errors.append(f"not valid JSON: {e}")
    for e in errors:
        print(f"{path}: {e}", file=sys.stderr)
    if errors:
        sys.exit(1)
    print(f"{path}: OK")


if __name__ == "__main__":
    main()
