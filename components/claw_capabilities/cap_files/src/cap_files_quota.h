/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

/* Limits for the user file area: everything under the data root outside the system directories. */
#define CAP_FILES_QUOTA_TOTAL (128 * 1024)
#define CAP_FILES_QUOTA_FILE  (32 * 1024)

/* True when `path` lies under the data root `base` but outside its system directories (apps, inbox,
 * memory, router_rules, scheduler, scripts, sessions, skills, static). */
bool cap_files_quota_applies(const char *base, const char *path);
/* Bytes used by regular files in the user file area of `base`, not counting the file `exclude`. */
size_t cap_files_quota_used(const char *base, const char *exclude);
