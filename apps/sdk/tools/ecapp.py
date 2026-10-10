#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
"""Build, sign and check esp-claw WASM app packages (.ecapp).

  ecapp.py pack <dir> --key <ed25519.pem> [-o out.ecapp]   dir holds manifest.json + app.wasm
  ecapp.py verify <file.ecapp> --pub <base64> [--pub ...]
  ecapp.py pubkey <ed25519.pem>                            prints the base64 public key + key_id

Format (see components/claw_capabilities/cap_wasm_apps/src/cap_wasm_pkg.h): "ECAP", u8 format 1,
u8 entry count 3, u16 0, then per entry u8 name length, name, u32 LE length, data; entries are
manifest.json, app.wasm and signature.json. The signature covers the canonical bytes of
signature.json's "signed" object: fixed key order name, version, manifest_sha256, wasm_sha256,
no whitespace. Signing uses the `cryptography` package, or `openssl pkeyutl` without it.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

SDK_VERSION = 1
ENTRIES = ("manifest.json", "app.wasm", "signature.json")
MAX = {"manifest.json": 4096, "app.wasm": 256 * 1024, "signature.json": 1024}
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,23}$")
VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")  # DER SubjectPublicKeyInfo for a raw Ed25519 key

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    serialization = None


def fail(msg):
    sys.exit(f"ecapp: {msg}")


def canonical(name, version, manifest_sha, wasm_sha):
    return (f'{{"name":"{name}","version":"{version}","manifest_sha256":"{manifest_sha}",'
            f'"wasm_sha256":"{wasm_sha}"}}').encode()


def key_id(pub_raw):
    return hashlib.sha256(pub_raw).hexdigest()[:8]


def version_key(version):
    """Sort key matching cap_wasm_version_cmp() on the device."""
    m = VERSION_RE.match(version)
    if not m:
        raise ValueError(f"version '{version}' is not MAJOR.MINOR.PATCH[-PRE][+BUILD]")
    pre = m.group(4)
    ids = [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")] if pre else []
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), pre is None, ids)


def openssl(args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


def private_key(pem_path):
    if serialization is None:
        return None
    with open(pem_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def public_raw(pem_path):
    key = private_key(pem_path)
    if key is not None:
        return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    der = openssl(["pkey", "-in", pem_path, "-pubout", "-outform", "DER"])
    if not der.startswith(SPKI_PREFIX) or len(der) != len(SPKI_PREFIX) + 32:
        fail(f"{pem_path} is not an Ed25519 private key")
    return der[len(SPKI_PREFIX):]


def sign(pem_path, data):
    key = private_key(pem_path)
    if key is not None:
        return key.sign(data)
    with tempfile.NamedTemporaryFile() as msg:
        msg.write(data)
        msg.flush()
        return openssl(["pkeyutl", "-sign", "-rawin", "-inkey", pem_path, "-in", msg.name])


def verify_sig(pub_raw, sig, data):
    if serialization is not None:
        try:
            Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig, data)
            return True
        except InvalidSignature:
            return False
    with tempfile.TemporaryDirectory() as d:
        paths = {n: os.path.join(d, n) for n in ("pub.der", "msg", "sig")}
        for n, content in (("pub.der", SPKI_PREFIX + pub_raw), ("msg", data), ("sig", sig)):
            with open(paths[n], "wb") as f:
                f.write(content)
        try:
            openssl(["pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", paths["pub.der"],
                     "-in", paths["msg"], "-sigfile", paths["sig"]])
            return True
        except subprocess.CalledProcessError:
            return False


def check_manifest(manifest_bytes):
    try:
        manifest = json.loads(manifest_bytes)
        name, version = manifest["name"], manifest["version"]
    except (ValueError, KeyError, TypeError) as e:
        fail(f"manifest.json: {e}")
    if not isinstance(name, str) or not NAME_RE.match(name):
        fail("manifest name must be 1-24 chars of [a-z0-9_] starting with a letter")
    if not isinstance(version, str) or len(version) > 16:
        fail("manifest version must be a string of at most 16 chars")
    try:
        version_key(version)
    except ValueError as e:
        fail(str(e))
    return name, version


def pack_entries(entries):
    out = bytearray(b"ECAP" + bytes([1, len(entries), 0, 0]))
    for name, data in entries:
        out += bytes([len(name)]) + name.encode() + struct.pack("<I", len(data)) + data
    return bytes(out)


def unpack(blob):
    if blob[:4] != b"ECAP" or blob[4:8] != bytes([1, 3, 0, 0]):
        fail("not an .ecapp package (format 1)")
    off, entries = 8, {}
    for _ in range(3):
        if off >= len(blob):
            fail("truncated package")
        n = blob[off]
        name = blob[off + 1:off + 1 + n].decode(errors="replace")
        (size,) = struct.unpack_from("<I", blob, off + 1 + n)
        off += 5 + n
        if name not in MAX or name in entries:
            fail(f"unexpected or repeated entry '{name}'")
        if size == 0 or size > MAX[name] or off + size > len(blob):
            fail(f"{name} is empty, truncated or larger than {MAX[name]} bytes")
        entries[name] = blob[off:off + size]
        off += size
    if off != len(blob):
        fail("trailing data after the last entry")
    return entries


def cmd_pack(args):
    with open(os.path.join(args.dir, "manifest.json"), "rb") as f:
        manifest = f.read()
    with open(os.path.join(args.dir, "app.wasm"), "rb") as f:
        wasm = f.read()
    for name, data in (("manifest.json", manifest), ("app.wasm", wasm)):
        if not data or len(data) > MAX[name]:
            fail(f"{name} must be 1-{MAX[name]} bytes")
    name, version = check_manifest(manifest)
    pub = public_raw(args.key)
    signed = {"name": name, "version": version, "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
              "wasm_sha256": hashlib.sha256(wasm).hexdigest()}
    sig = sign(args.key, canonical(name, version, signed["manifest_sha256"], signed["wasm_sha256"]))
    signature = json.dumps({"alg": "ed25519", "key_id": key_id(pub), "sdk": SDK_VERSION, "signed": signed,
                            "sig": base64.b64encode(sig).decode()}, separators=(",", ":")).encode()
    out = args.output or os.path.join(args.dir, f"{name}-{version}.ecapp")
    with open(out, "wb") as f:
        f.write(pack_entries([("manifest.json", manifest), ("app.wasm", wasm), ("signature.json", signature)]))
    print(f"{out}: {name} {version}, key {key_id(pub)}, wasm {len(wasm)} bytes")


def cmd_verify(args):
    with open(args.file, "rb") as f:
        entries = unpack(f.read())
    name, version = check_manifest(entries["manifest.json"])
    try:
        sig = json.loads(entries["signature.json"])
        signed = sig["signed"]
        if set(sig) != {"alg", "key_id", "sdk", "signed", "sig"} or \
                set(signed) != {"name", "version", "manifest_sha256", "wasm_sha256"}:
            fail("signature.json has missing or unknown keys")
        if sig["alg"] != "ed25519" or sig["sdk"] != SDK_VERSION:
            fail(f"unsupported alg {sig['alg']!r} or sdk {sig['sdk']!r}")
        raw_sig = base64.b64decode(sig["sig"], validate=True)
    except (ValueError, KeyError, TypeError) as e:
        fail(f"signature.json: {e}")
    if signed["name"] != name or signed["version"] != version:
        fail("signed name/version do not match manifest.json")
    if signed["manifest_sha256"] != hashlib.sha256(entries["manifest.json"]).hexdigest():
        fail("manifest.json does not match its signed hash")
    if signed["wasm_sha256"] != hashlib.sha256(entries["app.wasm"]).hexdigest():
        fail("app.wasm does not match its signed hash")
    keys = {}
    for b64 in args.pub:
        raw = base64.b64decode(b64, validate=True)
        if len(raw) != 32:
            fail(f"--pub {b64} is not a 32-byte Ed25519 key")
        keys[key_id(raw)] = raw
    if sig["key_id"] not in keys:
        fail(f"signed by untrusted key {sig['key_id']}")
    message = canonical(name, version, signed["manifest_sha256"], signed["wasm_sha256"])
    if len(raw_sig) != 64 or not verify_sig(keys[sig["key_id"]], raw_sig, message):
        fail(f"invalid signature (key {sig['key_id']})")
    print(f"{args.file}: OK {name} {version}, key {sig['key_id']}, wasm {len(entries['app.wasm'])} bytes")


def cmd_pubkey(args):
    pub = public_raw(args.key)
    print(f"{base64.b64encode(pub).decode()}  key_id {key_id(pub)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pack", help="sign and pack <dir>/{manifest.json,app.wasm}")
    p.add_argument("dir")
    p.add_argument("--key", required=True, help="Ed25519 private key (PKCS#8 PEM)")
    p.add_argument("-o", "--output", help="default: <dir>/<name>-<version>.ecapp")
    p.set_defaults(fn=cmd_pack)
    p = sub.add_parser("verify", help="check a package against trusted public keys")
    p.add_argument("file")
    p.add_argument("--pub", action="append", required=True, help="base64 raw 32-byte public key (repeatable)")
    p.set_defaults(fn=cmd_verify)
    p = sub.add_parser("pubkey", help="print the base64 public key and key_id of a private key")
    p.add_argument("key")
    p.set_defaults(fn=cmd_pubkey)
    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
