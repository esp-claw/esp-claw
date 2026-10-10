#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 esp-claw contributors
# SPDX-License-Identifier: Apache-2.0
"""Sign and check esp-claw firmware images for over-the-air updates.

  fwsign.py sign <app.bin> --key <ed25519.pem> [-o <app.bin.sig.json>]
  fwsign.py verify <app.bin> <app.bin.sig.json> --pub <base64> [--pub ...]
  fwsign.py pubkey <ed25519.pem>          prints the base64 public key + key_id

The image is the plain ESP-IDF app .bin; the signature is a detached JSON file
{"alg":"ed25519","key_id":"<8 hex>","version":"<v>","project":"<p>","size":N,"sha256":"<hex>","sig":"<b64>"}
where version and project come from the image's esp_app_desc_t and "sig" covers the canonical bytes
{"project":"<p>","version":"<v>","size":N,"sha256":"<hex>"}: this key order, no whitespace,
lowercase hex (see cap_wasm_fw_sig_canonical() in components/claw_capabilities/cap_wasm_apps).
Keys, key_id and signing work like app-sdk tools/ecapp.py, so an app signing key works here too.
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

APP_DESC_OFFSET = 32           # esp_image_header_t (24) + first esp_image_segment_header_t (8)
APP_DESC_MAGIC = 0xABCD5432
SIG_KEYS = {"alg", "key_id", "version", "project", "size", "sha256", "sig"}
TEXT_RE = re.compile(r'^[\x20-\x7e]{1,31}$')    # printable, fits the 32-byte desc fields
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")  # DER SubjectPublicKeyInfo for a raw Ed25519 key

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    serialization = None


def fail(msg):
    sys.exit(f"fwsign: {msg}")


def canonical(project, version, size, sha256):
    return f'{{"project":"{project}","version":"{version}","size":{size},"sha256":"{sha256}"}}'.encode()


def key_id(pub_raw):
    return hashlib.sha256(pub_raw).hexdigest()[:8]


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


def app_desc(image):
    """(project, version) from the image's esp_app_desc_t."""
    if len(image) < APP_DESC_OFFSET + 80 or image[0] != 0xE9:
        fail("not an ESP-IDF app image")
    magic, = struct.unpack_from("<I", image, APP_DESC_OFFSET)
    if magic != APP_DESC_MAGIC:
        fail("no esp_app_desc_t in the image")
    version = image[APP_DESC_OFFSET + 16:APP_DESC_OFFSET + 48].split(b"\0")[0].decode("ascii", "replace")
    project = image[APP_DESC_OFFSET + 48:APP_DESC_OFFSET + 80].split(b"\0")[0].decode("ascii", "replace")
    for name, value in (("version", version), ("project", project)):
        if not TEXT_RE.match(value) or '"' in value or "\\" in value:
            fail(f"image {name} '{value}' must be 1-31 printable ASCII chars without quotes or backslashes")
    return project, version


def cmd_sign(args):
    with open(args.image, "rb") as f:
        image = f.read()
    project, version = app_desc(image)
    sha = hashlib.sha256(image).hexdigest()
    pub = public_raw(args.key)
    sig = sign(args.key, canonical(project, version, len(image), sha))
    doc = {"alg": "ed25519", "key_id": key_id(pub), "version": version, "project": project,
           "size": len(image), "sha256": sha, "sig": base64.b64encode(sig).decode()}
    out = args.output or args.image + ".sig.json"
    with open(out, "w") as f:
        f.write(json.dumps(doc, separators=(",", ":")) + "\n")
    print(f"{out}: {project} {version}, {len(image)} bytes, key {key_id(pub)}")


def cmd_verify(args):
    with open(args.image, "rb") as f:
        image = f.read()
    try:
        with open(args.sig) as f:
            sig = json.load(f)
        if set(sig) != SIG_KEYS or sig["alg"] != "ed25519" or not isinstance(sig["size"], int):
            fail("not a firmware signature file")
        raw_sig = base64.b64decode(sig["sig"], validate=True)
    except (OSError, ValueError, TypeError) as e:
        fail(f"cannot read {args.sig}: {e}")
    project, version = app_desc(image)
    sha = hashlib.sha256(image).hexdigest()
    if (sig["project"], sig["version"], sig["size"], sig["sha256"]) != (project, version, len(image), sha):
        fail("project, version, size or sha256 do not match the image")
    keys = {}
    for b64 in args.pub:
        raw = base64.b64decode(b64, validate=True)
        if len(raw) != 32:
            fail(f"--pub {b64} is not a 32-byte Ed25519 key")
        keys[key_id(raw)] = raw
    if sig["key_id"] not in keys:
        fail(f"signed by untrusted key {sig['key_id']}")
    if len(raw_sig) != 64 or not verify_sig(keys[sig["key_id"]], raw_sig, canonical(project, version, len(image), sha)):
        fail(f"invalid signature (key {sig['key_id']})")
    print(f"{args.image}: OK {project} {version}, {len(image)} bytes, key {sig['key_id']}")


def cmd_pubkey(args):
    pub = public_raw(args.key)
    print(f"{base64.b64encode(pub).decode()}  key_id {key_id(pub)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("sign", help="write <app.bin>.sig.json")
    p.add_argument("image")
    p.add_argument("--key", required=True, help="Ed25519 private key (PKCS#8 PEM)")
    p.add_argument("-o", "--output", help="default: <app.bin>.sig.json")
    p.set_defaults(fn=cmd_sign)
    p = sub.add_parser("verify", help="check an image against its signature and trusted public keys")
    p.add_argument("image")
    p.add_argument("sig")
    p.add_argument("--pub", action="append", required=True, help="base64 raw 32-byte public key (repeatable)")
    p.set_defaults(fn=cmd_verify)
    p = sub.add_parser("pubkey", help="print the base64 public key and key_id of a private key")
    p.add_argument("key")
    p.set_defaults(fn=cmd_pubkey)
    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
