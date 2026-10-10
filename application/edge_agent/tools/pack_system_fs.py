#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
"""Packs a directory tree into the read-only image main/app_romfs.c serves at /system.

Layout (little endian): "ROFS", u32 entry count, then per entry u32 path offset, u32 data offset,
u32 size, u32 flags (1 = directory), then NUL-terminated paths and 4-byte aligned file data.
Paths are relative ("skills/x/SKILL.md"), sorted, and every parent directory has an entry.
The output is only rewritten when its content changes, so unchanged builds do not relink.
"""
import argparse
import os
import struct
import sys


def collect(root, excludes):
    entries = {}
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, '/')
        rel_dir = '' if rel_dir == '.' else rel_dir
        dirnames[:] = sorted(d for d in dirnames if (f'{rel_dir}/{d}' if rel_dir else d) not in excludes)
        if rel_dir:
            entries[rel_dir] = None
        for name in filenames:
            rel = f'{rel_dir}/{name}' if rel_dir else name
            with open(os.path.join(dirpath, name), 'rb') as f:
                entries[rel] = f.read()
    return sorted(entries.items())


def pack(entries):
    header_len = 8 + 16 * len(entries)
    paths = b''.join(p.encode() + b'\0' for p, _ in entries)
    data_off = (header_len + len(paths) + 3) & ~3
    table = bytearray(b'ROFS' + struct.pack('<I', len(entries)))
    data = bytearray()
    path_off = header_len
    for path, content in entries:
        if content is None:
            table += struct.pack('<IIII', path_off, 0, 0, 1)
        else:
            table += struct.pack('<IIII', path_off, data_off + len(data), len(content), 0)
            data += content + b'\0' * (-len(content) % 4)
        path_off += len(path.encode()) + 1
    return bytes(table) + paths + b'\0' * (data_off - header_len - len(paths)) + bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_dir')
    parser.add_argument('output')
    parser.add_argument('--exclude', action='append', default=[], help='top-level path to leave out')
    args = parser.parse_args()

    image = pack(collect(args.source_dir, set(args.exclude)))
    try:
        with open(args.output, 'rb') as f:
            if f.read() == image:
                return 0
    except FileNotFoundError:
        pass
    with open(args.output, 'wb') as f:
        f.write(image)
    print(f'system fs image: {len(image)} bytes -> {args.output}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
