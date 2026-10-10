#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 esp-claw contributors
# SPDX-License-Identifier: Apache-2.0
"""Check a built app.wasm against what the esp-claw runtime accepts.

  wasm_check.py <build_dir>     build_dir holds app.wasm and manifest.json (build-app.sh output)

Checks: wasm magic/version and size (<= 256 KB, CAP_WASM_WASM_MAX); every import is a function from
module "claw" declared in include/claw.h, and its permission is granted by the manifest (mirrors
cap_wasm_host_import_perm() in esp-claw cap_wasm_host.c); exports app_init/app_alloc/tool_call with
the right signatures; no __heap_base/__data_end/__stack_pointer export; exactly one memory, not
imported, with initial == maximum == limits.memory_kb. No dependencies besides Python 3.
"""
import json
import os
import re
import sys

WASM_MAX = 256 * 1024
HEADER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "include", "claw.h")
I32, I64 = 0x7F, 0x7E
EXPORTS = {"app_init": ((), ()), "app_alloc": ((I32,), (I32,)), "tool_call": ((I32, I32, I32), (I32,))}
FORBIDDEN_EXPORTS = {"__heap_base", "__data_end", "__stack_pointer"}
# Host function -> manifest permission; functions not listed need none (cap_wasm_host.c).
IMPORT_PERMS = {"log": "log", "kv_get": "kv", "kv_set": "kv", "kv_del": "kv", "confirm": "confirm",
                "ping": "ping", "http_profile_request": "http_profiles", "http_response_read": "http_profiles"}
KINDS = {0: "function", 1: "table", 2: "memory", 3: "global", 4: "tag"}


class Reader:
    def __init__(self, data, pos=0, end=None):
        self.data, self.pos, self.end = data, pos, len(data) if end is None else end

    def byte(self):
        if self.pos >= self.end:
            raise ValueError("unexpected end of section")
        self.pos += 1
        return self.data[self.pos - 1]

    def uleb(self):
        result = shift = 0
        while True:
            b = self.byte()
            result |= (b & 0x7F) << shift
            if not b & 0x80:
                return result
            shift += 7

    def name(self):
        n = self.uleb()
        if self.pos + n > self.end:
            raise ValueError("name runs past the section")
        self.pos += n
        return self.data[self.pos - n:self.pos].decode("utf-8", "replace")

    def limits(self):
        flags = self.byte()
        if flags not in (0, 1):
            raise ValueError(f"unsupported limits flags 0x{flags:x} (shared or 64-bit memory)")
        lo = self.uleb()
        return lo, self.uleb() if flags else None

    def vec(self, fn):
        return [fn() for _ in range(self.uleb())]


def parse(data):
    if data[:8] != b"\0asm\1\0\0\0":
        raise ValueError("not a WebAssembly module (version 1)")
    r = Reader(data, 8)
    m = {"types": [], "imports": [], "funcs": [], "memories": [], "exports": []}
    while r.pos < len(data):
        sid, size = r.byte(), r.uleb()
        s = Reader(data, r.pos, r.pos + size)
        if s.end > len(data):
            raise ValueError(f"section {sid} runs past the end of the file")
        if sid == 1:
            def functype():
                if s.byte() != 0x60:
                    raise ValueError("bad function type")
                return tuple(s.vec(s.byte)), tuple(s.vec(s.byte))
            m["types"] = s.vec(functype)
        elif sid == 2:
            def imp():
                mod, field, kind = s.name(), s.name(), s.byte()
                if kind == 0:
                    desc = s.uleb()
                elif kind == 1:
                    desc = (s.byte(), s.limits())
                elif kind == 2:
                    desc = s.limits()
                elif kind == 3:
                    desc = (s.byte(), s.byte())
                else:
                    raise ValueError(f"import {mod}.{field} has unsupported kind {kind}")
                return mod, field, kind, desc
            m["imports"] = s.vec(imp)
        elif sid == 3:
            m["funcs"] = s.vec(s.uleb)
        elif sid == 5:
            m["memories"] = s.vec(s.limits)
        elif sid == 7:
            m["exports"] = s.vec(lambda: (s.name(), s.byte(), s.uleb()))
        r.pos = s.end
    return m


def header_imports(path):
    with open(path, encoding="utf-8") as f:
        return set(re.findall(r'CLAW_IMPORT\("([a-z_]+)"\)', f.read()))


def check(data, manifest, declared):
    errors = []
    if len(data) > WASM_MAX:
        errors.append(f"app.wasm is {len(data)} bytes, the limit is {WASM_MAX}")
    try:
        m = parse(data)
    except (ValueError, IndexError) as e:
        return errors + [f"cannot parse app.wasm: {e}"]
    perms = manifest.get("permissions") or {}
    granted = {k for k, v in perms.items() if v is True} | ({"http_profiles"} if perms.get("http_profiles") else set())

    func_types = []
    for mod, field, kind, desc in m["imports"]:
        where = f"import {mod}.{field}"
        if mod != "claw":
            errors.append(f"{where}: only module 'claw' may be imported")
        elif kind != 0:
            errors.append(f"{where}: imports a {KINDS.get(kind, kind)}, only functions are allowed")
        elif field not in declared:
            errors.append(f"{where}: not a host function declared in claw.h")
        elif IMPORT_PERMS.get(field, "") and IMPORT_PERMS[field] not in granted:
            errors.append(f"{where}: needs permission '{IMPORT_PERMS[field]}', which the manifest does not grant")
        if kind == 0:
            func_types.append(desc)
    func_types += m["funcs"]

    exports = {name: (kind, idx) for name, kind, idx in m["exports"]}
    for name, sig in EXPORTS.items():
        kind, idx = exports.get(name, (None, None))
        if kind != 0:
            errors.append(f"missing function export '{name}'")
            continue
        try:
            got = m["types"][func_types[idx]]
        except IndexError:
            errors.append(f"export '{name}' refers to an unknown function or type")
            continue
        if got != sig:
            errors.append(f"export '{name}' has signature {got}, expected {sig} (0x7f = i32)")
    for name in sorted(FORBIDDEN_EXPORTS & exports.keys()):
        errors.append(f"exports '{name}': WAMR would split the app stack between threads and halve it")

    mem_kb = (manifest.get("limits") or {}).get("memory_kb", 64)
    pages = mem_kb // 64 if isinstance(mem_kb, int) else None
    if len(m["memories"]) != 1:
        errors.append(f"expects exactly one defined memory, found {len(m['memories'])} (imported memory is not allowed)")
    else:
        lo, hi = m["memories"][0]
        if lo != pages or hi != pages:
            errors.append(f"memory is {lo}..{hi} pages, limits.memory_kb {mem_kb} needs initial = maximum = {pages} "
                          "(64 KB pages; build with build-app.sh)")
    return errors


def main():
    if len(sys.argv) != 2 or sys.argv[1] in ("-h", "--help"):
        sys.exit(__doc__)
    build = sys.argv[1]
    with open(os.path.join(build, "app.wasm"), "rb") as f:
        data = f.read()
    with open(os.path.join(build, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    errors = check(data, manifest, header_imports(HEADER))
    for e in errors:
        print(f"{build}/app.wasm: {e}", file=sys.stderr)
    if errors:
        sys.exit(1)
    print(f"{build}/app.wasm: OK ({len(data)} bytes)")


if __name__ == "__main__":
    main()
