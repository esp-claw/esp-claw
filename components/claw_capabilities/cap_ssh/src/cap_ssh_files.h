/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#define CAP_SSH_FILES_PATH_MAX 256

/*
 * Writes `workdir`/`path` with empty and "." segments removed. `path` is relative to `workdir` or
 * absolute inside it. Fails on ".." segments, control characters, a `workdir` that is not absolute
 * or is "/", a path outside `workdir`, or when the result does not fit.
 */
bool cap_ssh_files_resolve(const char *workdir, const char *path, char *out, size_t out_size);
/* True when `path` is `root` or lies below it; both must be canonical and `root` must not be "/". */
bool cap_ssh_files_inside(const char *root, const char *path);
/*
 * Returns how many leading bytes of `buf` are UTF-8 text without NUL bytes; a multi-byte character
 * cut off at the end is left out. Returns -1 when the data is not such text.
 */
int cap_ssh_files_text_len(const char *buf, size_t len);
