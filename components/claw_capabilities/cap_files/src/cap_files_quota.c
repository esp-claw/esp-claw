/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_files_quota.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* Top-level directories of the data root for configuration, skills, apps and memory. */
static const char *const s_system_dirs[] = {
    "apps", "inbox", "memory", "router_rules", "scheduler", "scripts", "sessions", "skills", "static",
};

static bool cap_files_quota_is_system(const char *name, size_t len)
{
    for (size_t i = 0; i < sizeof(s_system_dirs) / sizeof(s_system_dirs[0]); i++) {
        if (strlen(s_system_dirs[i]) == len && strncmp(name, s_system_dirs[i], len) == 0) {
            return true;
        }
    }
    return false;
}

bool cap_files_quota_applies(const char *base, const char *path)
{
    size_t len = strlen(base);
    const char *rel;
    size_t seg;

    if (strncmp(path, base, len) != 0 || path[len] != '/' || !path[len + 1]) {
        return false;
    }
    rel = path + len + 1;
    seg = strcspn(rel, "/");
    return rel[seg] == '\0' || !cap_files_quota_is_system(rel, seg);
}

static size_t cap_files_quota_sum(const char *dir_path, const char *exclude, bool top)
{
    DIR *dir = opendir(dir_path);
    struct dirent *entry = NULL;
    size_t used = 0;

    while (dir && (entry = readdir(dir)) != NULL) {
        char full_path[256];
        struct stat st = {0};

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
                snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name) >= (int)sizeof(full_path) ||
                stat(full_path, &st) != 0) {
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            if (!top || !cap_files_quota_is_system(entry->d_name, strlen(entry->d_name))) {
                used += cap_files_quota_sum(full_path, exclude, false);
            }
        } else if (S_ISREG(st.st_mode) && strcmp(full_path, exclude) != 0) {
            used += (size_t)st.st_size;
        }
    }
    if (dir) {
        closedir(dir);
    }
    return used;
}

size_t cap_files_quota_used(const char *base, const char *exclude)
{
    return cap_files_quota_sum(base, exclude, true);
}
