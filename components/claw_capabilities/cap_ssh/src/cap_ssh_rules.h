/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#define CAP_SSH_RULES_CMDS_MAX 8
#define CAP_SSH_RULES_TEXT_MAX 1024

/* One simple command: the program token as typed (unquoted) and its arguments joined by one space. */
typedef struct {
    const char *prog;
    const char *args;
} cap_ssh_rules_cmd_t;

typedef struct {
    size_t count;
    cap_ssh_rules_cmd_t cmds[CAP_SSH_RULES_CMDS_MAX];
    char buf[CAP_SSH_RULES_TEXT_MAX + 2 * CAP_SSH_RULES_CMDS_MAX];
} cap_ssh_rules_parsed_t;

/*
 * Tokenizes `command` shell-style and splits it on ; && || |. Returns false when the command is
 * not auto-approvable: substitutions, variables, subshells, background jobs, input redirection,
 * output redirection other than to /dev/null, &1 or &2, newlines, unbalanced quotes, variable
 * assignments or more than CAP_SSH_RULES_CMDS_MAX commands.
 */
bool cap_ssh_rules_parse(const char *command, cap_ssh_rules_parsed_t *out);
/* Programs that are never auto-approved and get no "always" rule (see the cap_ssh skill). */
bool cap_ssh_rules_hardline(const char *prog, const char *args);
/* fnmatch() on the joined arguments; a pattern ending in " *" also matches without the last part. */
bool cap_ssh_rules_match(const char *pattern, const char *args);
/* Writes `args` with glob characters escaped, so the pattern matches exactly that text. */
bool cap_ssh_rules_escape(const char *args, char *out, size_t out_size);
/* Writes the widest pattern allowed for `cmd`: "*", or "<subcommand> *" for programs that are
 * hardline except for some subcommands. */
void cap_ssh_rules_wildcard(const cap_ssh_rules_cmd_t *cmd, char *out, size_t out_size);
