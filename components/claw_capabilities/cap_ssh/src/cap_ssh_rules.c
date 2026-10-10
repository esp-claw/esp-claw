/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_ssh_rules.h"

#include <ctype.h>
#include <fnmatch.h>
#include <stdio.h>
#include <string.h>

/* Programs that delete, overwrite, escalate, reconfigure, fetch or run other code. */
static const char *const s_hardline[] = {
    "rm", "rmdir", "dd", "mkfs*", "shred", "wipefs", "fdisk", "parted", "chmod", "chown", "chattr",
    "sudo", "su", "doas", "pkexec", "runuser", "kill", "killall", "pkill", "reboot", "shutdown",
    "poweroff", "halt", "init", "telinit", "mv", "cp", "tee", "truncate", "ln", "tar", "crontab", "at",
    "useradd", "userdel", "usermod", "passwd", "iptables", "nft", "ufw", "firewall-cmd", "apt", "apt-get",
    "dnf", "yum", "rpm", "pip*", "npm", "snap", "flatpak", "curl", "wget", "nc", "ncat", "socat", "ssh",
    "scp", "rsync", "python*", "perl", "ruby", "node", "php", "lua*", "bash", "sh", "dash", "zsh", "ksh",
    "fish", "csh", "tcsh", "busybox", "eval", "exec", "source", ".", "command", "builtin", "env", "xargs",
    "find", "nohup", "timeout", "nice", "ionice", "stdbuf", "time", "watch", "strace", "chroot", "setsid",
    "unshare", "nsenter", "systemd-run", "sed", "awk", "gawk", "mawk", "git",
    /* Shell keywords and builtins that would make the rest of the line a command or change PATH. */
    "!", "if", "then", "else", "elif", "fi", "case", "esac", "for", "select", "while", "until", "do",
    "done", "function", "coproc", "alias", "export", "declare", "typeset", "readonly", "local",
    "set", "unset", "shopt", "hash", "enable", "trap",
};

/* Hardline unless the argument at `index` is one of `subs`. */
static const struct {
    const char *prog;
    int index;
    const char *subs;
} s_except[] = {
    {"docker", 0, " ps logs inspect images stats "},
    {"podman", 0, " ps logs inspect images stats "},
    {"systemctl", 0, " status is-active is-enabled list-units "},
    {"service", 1, " status "},
};

static int cap_ssh_rules_find_except(const char *prog)
{
    const char *base = strrchr(prog, '/') ? strrchr(prog, '/') + 1 : prog;

    for (int i = 0; i < (int)(sizeof(s_except) / sizeof(s_except[0])); i++) {
        if (strcmp(base, s_except[i].prog) == 0) {
            return i;
        }
    }
    return -1;
}

/* Copies argument `index` of `args` into `word`; false when it is missing or too long. */
static bool cap_ssh_rules_arg(const char *args, int index, char *word, size_t size)
{
    size_t len;

    for (; index > 0 && args; index--) {
        args = strchr(args, ' ');
        args = args ? args + 1 : NULL;
    }
    len = args ? strcspn(args, " ") : 0;
    if (!len || len >= size) {
        return false;
    }
    memcpy(word, args, len);
    word[len] = '\0';
    return true;
}

bool cap_ssh_rules_hardline(const char *prog, const char *args)
{
    const char *base = strrchr(prog, '/') ? strrchr(prog, '/') + 1 : prog;
    int except = cap_ssh_rules_find_except(prog);
    char key[24] = " ";

    if (except >= 0) {
        return !cap_ssh_rules_arg(args, s_except[except].index, key + 1, sizeof(key) - 2) ||
               !strstr(s_except[except].subs, strcat(key, " "));
    }
    for (size_t i = 0; i < sizeof(s_hardline) / sizeof(s_hardline[0]); i++) {
        if (fnmatch(s_hardline[i], base, 0) == 0) {
            return true;
        }
    }
    return false;
}

void cap_ssh_rules_wildcard(const cap_ssh_rules_cmd_t *cmd, char *out, size_t out_size)
{
    int except = cap_ssh_rules_find_except(cmd->prog);
    char sub[24];

    if (except < 0 || !cap_ssh_rules_arg(cmd->args, s_except[except].index, sub, sizeof(sub))) {
        snprintf(out, out_size, "*");
    } else {
        snprintf(out, out_size, s_except[except].index ? "* %s" : "%s *", sub);
    }
}

bool cap_ssh_rules_match(const char *pattern, const char *args)
{
    char shorter[CAP_SSH_RULES_TEXT_MAX + 1];
    size_t len = strlen(pattern);

    if (fnmatch(pattern, args, 0) == 0) {
        return true;
    }
    if (len < 2 || len > CAP_SSH_RULES_TEXT_MAX || strcmp(pattern + len - 2, " *") != 0) {
        return false;
    }
    memcpy(shorter, pattern, len - 2);
    shorter[len - 2] = '\0';
    return fnmatch(shorter, args, 0) == 0;
}

bool cap_ssh_rules_escape(const char *args, char *out, size_t out_size)
{
    size_t len = 0;

    for (; *args; args++) {
        if (len + 3 > out_size) {
            return false;
        }
        if (strchr("*?[\\", *args)) {
            out[len++] = '\\';
        }
        out[len++] = *args;
    }
    out[len] = '\0';
    return true;
}

/* True when `s` ends a redirection target or word. */
static bool cap_ssh_rules_word_end(const char *s)
{
    return *s == '\0' || strchr(" \t;|&", *s);
}

/* Skips a harmless redirection (to /dev/null, &1 or &2) at `*s`; false if it is any other one.
 * Leaves `*s` unchanged and sets `*found` false when there is no redirection. */
static bool cap_ssh_rules_redirect(const char **s, bool *found)
{
    const char *r = *s;

    if (*r == '&') {
        r++;
    } else {
        while (isdigit((unsigned char)*r)) {
            r++;
        }
    }
    *found = *r == '>';
    if (!*found) {
        return true;
    }
    r += r[1] == '>' ? 2 : 1;
    if (r[0] == '&' && (r[1] == '1' || r[1] == '2') && cap_ssh_rules_word_end(r + 2)) {
        *s = r + 2;
        return true;
    }
    r += strspn(r, " \t");
    if (strncmp(r, "/dev/null", 9) == 0 && cap_ssh_rules_word_end(r + 9)) {
        *s = r + 9;
        return true;
    }
    return false;
}

bool cap_ssh_rules_parse(const char *s, cap_ssh_rules_parsed_t *out)
{
    char *o = out->buf;
    char *const end = out->buf + sizeof(out->buf) - 2;
    cap_ssh_rules_cmd_t *cmd = NULL;
    size_t tokens = 0;
    bool redirect;

    out->count = 0;
    if (strlen(s) > CAP_SSH_RULES_TEXT_MAX || strpbrk(s, "\n\r")) {
        return false;
    }
    for (;;) {
        s += strspn(s, " \t");
        if (*s == '\0' || *s == ';' || *s == '|' || (s[0] == '&' && s[1] == '&')) {
            if (!tokens) {
                return false;
            }
            *o++ = '\0';
            if (tokens == 1) {
                cmd->args = o - 1;
            }
            /* Globs and braces expand into another program; "=" makes an assignment prefix. */
            if (strpbrk(cmd->prog, "*?[{}=")) {
                return false;
            }
            if (*s == '\0') {
                return true;
            }
            s += (s[0] == s[1] && s[0] != ';') ? 2 : 1;
            tokens = 0;
            continue;
        }
        if (!cap_ssh_rules_redirect(&s, &redirect)) {
            return false;
        }
        if (redirect) {
            continue;
        }
        if (*s == '&' || *s == '<') {
            return false;
        }

        if (!tokens) {
            if (out->count == CAP_SSH_RULES_CMDS_MAX) {
                return false;
            }
            cmd = &out->cmds[out->count++];
            cmd->prog = o;
        } else if (tokens == 1) {
            *o++ = '\0';
            cmd->args = o;
        } else {
            *o++ = ' ';
        }
        tokens++;

        for (char c; (c = *s) && !strchr(" \t;|&<>", c); s++) {
            if (o >= end || strchr("$`()", c)) {
                return false;
            }
            if (c == '\'') {
                const char *close = strchr(s + 1, '\'');

                if (!close || o + (close - s - 1) >= end) {
                    return false;
                }
                memcpy(o, s + 1, close - s - 1);
                o += close - s - 1;
                s = close;
            } else if (c == '"') {
                for (s++; *s != '"'; s++) {
                    if (!*s || strchr("$`", *s) || o >= end) {
                        return false;
                    }
                    if (*s == '\\' && s[1] && strchr("\"\\", s[1])) {
                        s++;
                    }
                    *o++ = *s;
                }
            } else if (c == '\\') {
                if (!s[1]) {
                    return false;
                }
                *o++ = *++s;
            } else {
                *o++ = c;
            }
        }
        if (o == cmd->prog) {
            return false;
        }
    }
}
