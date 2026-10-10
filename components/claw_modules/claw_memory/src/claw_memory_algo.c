/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "claw_memory_algo.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#define CLAW_MEMORY_RECENCY_HALF_LIFE_SEC (30.0f * 86400.0f)

static const char *const s_kind_names[] = {
    "other", "profile", "preference", "device", "project", "event",
};

static const char *const s_stop_words[] = {
    "the", "and", "for", "with", "what", "who", "where", "when", "how", "which", "does", "did",
    "is", "are", "was", "my", "me", "you", "your", "do", "of", "to", "in", "on", "at", "a", "an",
    "about", "user", "der", "die", "das", "und", "ich", "mein", "meine", "mir", "mich", "ist",
    "was", "wo", "wie", "wer", "mit", "ein", "eine", "von", "zu", "im", "am", "den", "dem", "du",
    "hast", "habe", "hat", "weisst", "weißt", "über",
};

/* Lower-case keywords that only appear around credentials. */
static const char *const s_secret_words[] = {
    "password", "passwort", "passwd", "kennwort", "api key", "api-key", "api_key", "apikey",
    "secret key", "client secret", "private key", "access token", "auth token", "api token",
    "bot token", "refresh token", "bearer ", "-----begin",
};

/* Case-sensitive prefixes of well-known key formats, followed by >= 16 key chars. */
static const char *const s_secret_prefixes[] = {
    "sk-", "ghp_", "gho_", "github_pat_", "xoxb-", "xoxp-", "AKIA", "AIza", "glpat-",
};

const char *claw_memory_kind_name(uint8_t kind)
{
    return kind < sizeof(s_kind_names) / sizeof(s_kind_names[0]) ? s_kind_names[kind] : "other";
}

uint8_t claw_memory_kind_from_name(const char *name)
{
    size_t i;

    for (i = 0; name && i < sizeof(s_kind_names) / sizeof(s_kind_names[0]); i++) {
        if (strcmp(name, s_kind_names[i]) == 0) {
            return (uint8_t)i;
        }
    }
    return CLAW_MEMORY_KIND_OTHER;
}

static bool ci_contains(const char *haystack, const char *needle)
{
    size_t n;

    if (!haystack || !needle || !needle[0]) {
        return false;
    }
    n = strlen(needle);
    for (; *haystack; haystack++) {
        size_t i = 0;

        while (i < n && haystack[i] &&
               tolower((unsigned char)haystack[i]) == tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == n) {
            return true;
        }
    }
    return false;
}

static bool is_key_char(char ch)
{
    return isalnum((unsigned char)ch) || ch == '-' || ch == '_' || ch == '+' || ch == '/' || ch == '=';
}

bool claw_memory_text_has_secret(const char *text)
{
    const char *p;
    size_t i;

    if (!text || !text[0]) {
        return false;
    }
    for (i = 0; i < sizeof(s_secret_words) / sizeof(s_secret_words[0]); i++) {
        if (ci_contains(text, s_secret_words[i])) {
            return true;
        }
    }
    /* "token: xyz" / "token=xyz" */
    for (p = text; (p = strstr(p, "oken")) != NULL; p += 4) {
        const char *q = p + 4;

        while (*q == ' ') {
            q++;
        }
        if (p > text && (p[-1] == 't' || p[-1] == 'T') && (*q == ':' || *q == '=')) {
            return true;
        }
    }
    for (i = 0; i < sizeof(s_secret_prefixes) / sizeof(s_secret_prefixes[0]); i++) {
        for (p = text; (p = strstr(p, s_secret_prefixes[i])) != NULL; p++) {
            const char *q = p + strlen(s_secret_prefixes[i]);
            size_t run = 0;

            while (is_key_char(q[run])) {
                run++;
            }
            if (run >= 16) {
                return true;
            }
        }
    }
    /* Long high-entropy blob: >= 32 key chars mixing letters and digits. */
    for (p = text; *p;) {
        size_t run = 0;
        bool digit = false;
        bool alpha = false;

        while (is_key_char(p[run])) {
            digit |= isdigit((unsigned char)p[run]) != 0;
            alpha |= isalpha((unsigned char)p[run]) != 0;
            run++;
        }
        if (run >= 32 && digit && alpha) {
            return true;
        }
        p += run ? run : 1;
    }
    return false;
}

size_t claw_memory_tail_offset(const char *text, size_t len, size_t max_bytes)
{
    size_t start;
    size_t i;

    if (!text || len <= max_bytes) {
        return 0;
    }
    start = len - max_bytes;
    while (start < len && ((unsigned char)text[start] & 0xC0) == 0x80) {
        start++;
    }
    for (i = start; i < len && i < start + 512; i++) {
        if (text[i] == '\n') {
            return i + 1;
        }
    }
    return start;
}

static bool is_stop_word(const char *token)
{
    size_t i;

    for (i = 0; i < sizeof(s_stop_words) / sizeof(s_stop_words[0]); i++) {
        if (strcmp(token, s_stop_words[i]) == 0) {
            return true;
        }
    }
    return false;
}

static bool is_token_char(unsigned char ch)
{
    return isalnum(ch) || ch == '-' || ch == '_' || ch >= 0x80;
}

size_t claw_memory_tokenize(const char *text,
                            char tokens[][CLAW_MEMORY_TOKEN_MAX],
                            size_t max_tokens)
{
    size_t count = 0;
    const unsigned char *p = (const unsigned char *)text;

    while (p && *p && count < max_tokens) {
        char token[CLAW_MEMORY_TOKEN_MAX];
        size_t len = 0;
        size_t i;
        bool dup = false;

        while (*p && !is_token_char(*p)) {
            p++;
        }
        while (*p && is_token_char(*p)) {
            if (len + 1 < sizeof(token)) {
                token[len++] = (char)tolower(*p);
            }
            p++;
        }
        /* Do not leave a truncated UTF-8 sequence at the end of the token. */
        if (len > 0 && ((unsigned char)token[len - 1] & 0x80)) {
            size_t lead = len - 1;
            unsigned char ch;
            size_t need;

            while (lead > 0 && ((unsigned char)token[lead] & 0xC0) == 0x80) {
                lead--;
            }
            ch = (unsigned char)token[lead];
            need = ch >= 0xF0 ? 4 : (ch >= 0xE0 ? 3 : (ch >= 0xC0 ? 2 : 1));
            if (len - lead < need) {
                len = lead;
            }
        }
        token[len] = '\0';
        while (len > 0 && (token[len - 1] == '-' || token[len - 1] == '_')) {
            token[--len] = '\0';
        }
        if (len < 2 || is_stop_word(token)) {
            continue;
        }
        for (i = 0; i < count; i++) {
            dup |= strcmp(tokens[i], token) == 0;
        }
        if (!dup) {
            memcpy(tokens[count++], token, len + 1);
        }
    }
    return count;
}

static bool csv_has_term_ci(const char *csv, const char *term)
{
    size_t n = strlen(term);
    const char *p = csv;

    while (p && *p) {
        const char *end = p + strcspn(p, ",;/|");
        const char *s = p;
        const char *e = end;

        while (s < e && *s == ' ') {
            s++;
        }
        while (e > s && e[-1] == ' ') {
            e--;
        }
        if ((size_t)(e - s) == n) {
            size_t i = 0;

            while (i < n && tolower((unsigned char)s[i]) == (unsigned char)term[i]) {
                i++;
            }
            if (i == n) {
                return true;
            }
        }
        p = *end ? end + 1 : end;
    }
    return false;
}

float claw_memory_keyword_match(const char tokens[][CLAW_MEMORY_TOKEN_MAX],
                                size_t token_count,
                                const char *content,
                                const char *tags,
                                const char *keywords)
{
    float sum = 0.0f;
    size_t i;

    if (!tokens || token_count == 0) {
        return 0.0f;
    }
    for (i = 0; i < token_count; i++) {
        if (csv_has_term_ci(keywords, tokens[i]) || csv_has_term_ci(tags, tokens[i])) {
            sum += 1.0f;
        } else if (strlen(tokens[i]) >= 3 &&
                   (ci_contains(content, tokens[i]) || ci_contains(keywords, tokens[i]) ||
                    ci_contains(tags, tokens[i]))) {
            sum += 0.6f;
        }
    }
    return sum / (float)token_count;
}

float claw_memory_hybrid_match(float cosine, float keyword, bool has_cosine)
{
    if (!has_cosine) {
        return keyword;
    }
    return 0.6f * (cosine > 0.0f ? cosine : 0.0f) + 0.4f * keyword;
}

float claw_memory_rank_score(float match,
                             uint32_t now,
                             uint32_t updated_at,
                             uint16_t access_count,
                             uint8_t importance)
{
    float age = 0.0f;
    float recency;
    float usage;
    float weight;

    if (now >= CLAW_MEMORY_MIN_VALID_EPOCH && updated_at && now > updated_at) {
        age = (float)(now - updated_at);
    }
    /* Floor of 0.3 keeps old profile facts reachable. */
    recency = 0.3f + 0.7f * exp2f(-age / CLAW_MEMORY_RECENCY_HALF_LIFE_SEC);
    usage = 1.0f + 0.2f * logf(1.0f + (float)access_count);
    if (importance < 1 || importance > 5) {
        importance = 3;
    }
    weight = 0.6f + 0.2f * (float)importance;
    return match * recency * usage * weight;
}

void claw_memory_vec_quantize(const float *vec, int8_t *out, float *out_scale)
{
    float max_abs = 0.0f;
    float scale;
    size_t i;

    for (i = 0; i < CLAW_MEMORY_EMBED_DIM; i++) {
        float a = fabsf(vec[i]);

        if (a > max_abs) {
            max_abs = a;
        }
    }
    scale = max_abs > 0.0f ? max_abs / 127.0f : 0.0f;
    for (i = 0; i < CLAW_MEMORY_EMBED_DIM; i++) {
        long q = scale > 0.0f ? lroundf(vec[i] / scale) : 0;

        out[i] = (int8_t)(q > 127 ? 127 : (q < -127 ? -127 : q));
    }
    *out_scale = scale;
}

void claw_memory_vec_dequantize(const int8_t *vec, float scale, float *out)
{
    size_t i;

    for (i = 0; i < CLAW_MEMORY_EMBED_DIM; i++) {
        out[i] = (float)vec[i] * scale;
    }
}

float claw_memory_vec_cosine(const int8_t *stored, const float *query)
{
    float dot = 0.0f;
    float ns = 0.0f;
    float nq = 0.0f;
    size_t i;

    /* The per-vector scale cancels out in the cosine. */
    for (i = 0; i < CLAW_MEMORY_EMBED_DIM; i++) {
        float s = (float)stored[i];

        dot += s * query[i];
        ns += s * s;
        nq += query[i] * query[i];
    }
    if (ns <= 0.0f || nq <= 0.0f) {
        return 0.0f;
    }
    return dot / (sqrtf(ns) * sqrtf(nq));
}

static void copy_utf8(char *dst, size_t dst_size, const char *src)
{
    size_t len;

    if (!dst || dst_size == 0) {
        return;
    }
    dst[0] = '\0';
    if (!src) {
        return;
    }
    while (*src == ' ' || *src == '\n' || *src == '\t') {
        src++;
    }
    len = strlen(src);
    if (len >= dst_size) {
        len = dst_size - 1;
        while (len > 0 && ((unsigned char)src[len] & 0xC0) == 0x80) {
            len--;
        }
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
    while (len > 0 && (dst[len - 1] == ' ' || dst[len - 1] == '\n' || dst[len - 1] == '\t')) {
        dst[--len] = '\0';
    }
}

static void copy_csv(const cJSON *json, const char *key, char *dst, size_t dst_size)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(json, key);
    const cJSON *entry;
    size_t off = 0;

    dst[0] = '\0';
    if (cJSON_IsString(value)) {
        copy_utf8(dst, dst_size, value->valuestring);
        return;
    }
    if (!cJSON_IsArray(value)) {
        return;
    }
    cJSON_ArrayForEach(entry, value) {
        int written;

        if (!cJSON_IsString(entry) || !entry->valuestring[0]) {
            continue;
        }
        written = snprintf(dst + off, dst_size - off, "%s%s", off ? "," : "", entry->valuestring);
        if (written < 0 || (size_t)written >= dst_size - off) {
            dst[off] = '\0';
            break;
        }
        off += (size_t)written;
    }
}

size_t claw_memory_parse_facts(const cJSON *root,
                               claw_memory_fact_t *out,
                               size_t max_facts,
                               size_t *out_dropped)
{
    const cJSON *facts = cJSON_GetObjectItemCaseSensitive(root, "facts");
    const cJSON *list = cJSON_IsArray(facts) ? facts : NULL;
    const cJSON *entry;
    size_t count = 0;
    size_t dropped = 0;

    cJSON_ArrayForEach(entry, list) {
        claw_memory_fact_t *fact;
        const cJSON *importance;

        if (count >= max_facts) {
            dropped++;
            continue;
        }
        fact = &out[count];
        memset(fact, 0, sizeof(*fact));
        copy_utf8(fact->content, sizeof(fact->content),
                  cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(entry, "content")));
        copy_csv(entry, "tags", fact->tags, sizeof(fact->tags));
        copy_csv(entry, "keywords", fact->keywords, sizeof(fact->keywords));
        importance = cJSON_GetObjectItemCaseSensitive(entry, "importance");
        fact->importance = cJSON_IsNumber(importance) ?
                           (uint8_t)(importance->valueint < 1 ? 1 : (importance->valueint > 5 ? 5 : importance->valueint)) : 3;
        fact->kind = claw_memory_kind_from_name(
            cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(entry, "kind")));
        if (!fact->content[0] || claw_memory_text_has_secret(fact->content) ||
            claw_memory_text_has_secret(fact->tags) || claw_memory_text_has_secret(fact->keywords)) {
            dropped++;
            continue;
        }
        count++;
    }
    if (out_dropped) {
        *out_dropped = dropped;
    }
    return count;
}

static bool neighbor_known(const char (*neighbors)[CLAW_MEMORY_RECONCILE_TOPK][CLAW_MEMORY_ID_MAX],
                           size_t index,
                           const char *id)
{
    size_t i;

    if (!neighbors || !id || !id[0]) {
        return false;
    }
    for (i = 0; i < CLAW_MEMORY_RECONCILE_TOPK; i++) {
        if (neighbors[index][i][0] && strcmp(neighbors[index][i], id) == 0) {
            return true;
        }
    }
    return false;
}

static bool str_eq_ci(const char *a, const char *b)
{
    while (a && b && *a && tolower((unsigned char)*a) == tolower((unsigned char)*b)) {
        a++;
        b++;
    }
    return a && b && *a == '\0' && *b == '\0';
}

void claw_memory_parse_decisions(const cJSON *root,
                                 size_t candidate_count,
                                 const char (*neighbors)[CLAW_MEMORY_RECONCILE_TOPK][CLAW_MEMORY_ID_MAX],
                                 const claw_memory_fact_t *candidates,
                                 claw_memory_decision_t *out)
{
    const cJSON *decisions = cJSON_GetObjectItemCaseSensitive(root, "decisions");
    const cJSON *list = cJSON_IsArray(decisions) ? decisions : NULL;
    const cJSON *entry;
    size_t i;

    for (i = 0; i < candidate_count; i++) {
        memset(&out[i], 0, sizeof(out[i]));
        out[i].op = CLAW_MEMORY_OP_ADD;
    }
    cJSON_ArrayForEach(entry, list) {
        const cJSON *index = cJSON_GetObjectItemCaseSensitive(entry, "index");
        const char *action = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(entry, "action"));
        const char *id = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(entry, "id"));
        const char *content = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(entry, "content"));
        claw_memory_decision_t *d;
        size_t idx;

        if (!cJSON_IsNumber(index) || index->valueint < 0 ||
            (size_t)index->valueint >= candidate_count || !action) {
            continue;
        }
        idx = (size_t)index->valueint;
        d = &out[idx];
        if (str_eq_ci(action, "NOOP")) {
            d->op = CLAW_MEMORY_OP_NOOP;
        } else if (str_eq_ci(action, "DELETE")) {
            d->op = neighbor_known(neighbors, idx, id) ? CLAW_MEMORY_OP_DELETE : CLAW_MEMORY_OP_NOOP;
        } else if (str_eq_ci(action, "UPDATE")) {
            d->op = neighbor_known(neighbors, idx, id) ? CLAW_MEMORY_OP_UPDATE : CLAW_MEMORY_OP_ADD;
        } else {
            d->op = CLAW_MEMORY_OP_ADD;
        }
        if (d->op == CLAW_MEMORY_OP_UPDATE || d->op == CLAW_MEMORY_OP_DELETE) {
            copy_utf8(d->id, sizeof(d->id), id);
        }
        if (d->op == CLAW_MEMORY_OP_UPDATE) {
            copy_utf8(d->content, sizeof(d->content),
                      content && content[0] && !claw_memory_text_has_secret(content) ?
                      content : (candidates ? candidates[idx].content : ""));
        }
    }
}

static uint32_t gc_projected_bytes(const claw_memory_gc_entry_t *entry, uint8_t action)
{
    if (action == CLAW_MEMORY_GC_DELETE) {
        return 0;
    }
    if (action == CLAW_MEMORY_GC_COMPACT && entry->log_bytes > CLAW_MEMORY_GC_KEEP_BYTES) {
        return entry->bytes - entry->log_bytes + CLAW_MEMORY_GC_KEEP_BYTES;
    }
    return entry->bytes;
}

uint32_t claw_memory_gc_plan(const claw_memory_gc_entry_t *entries,
                             size_t count,
                             uint32_t now,
                             uint32_t fixed_bytes,
                             uint8_t *out_actions)
{
    bool clock_valid = now >= CLAW_MEMORY_MIN_VALID_EPOCH;
    uint32_t total = fixed_bytes;
    size_t i;

    for (i = 0; i < count; i++) {
        const claw_memory_gc_entry_t *e = &entries[i];

        out_actions[i] = CLAW_MEMORY_GC_KEEP;
        if (clock_valid && !e->active && e->extracted &&
            e->mtime >= CLAW_MEMORY_MIN_VALID_EPOCH && now > e->mtime &&
            now - e->mtime > CLAW_MEMORY_GC_MAX_AGE_SEC) {
            out_actions[i] = CLAW_MEMORY_GC_DELETE;
        } else if (e->log_bytes > CLAW_MEMORY_GC_COMPACT_BYTES) {
            out_actions[i] = CLAW_MEMORY_GC_COMPACT;
        }
        total += gc_projected_bytes(e, out_actions[i]);
    }

    /* Over budget: oldest inactive, extracted sessions go first. */
    while (total > CLAW_MEMORY_GC_BUDGET_BYTES) {
        size_t oldest = count;

        for (i = 0; i < count; i++) {
            if (out_actions[i] != CLAW_MEMORY_GC_DELETE && !entries[i].active && entries[i].extracted &&
                (oldest == count || entries[i].mtime < entries[oldest].mtime)) {
                oldest = i;
            }
        }
        if (oldest == count) {
            break;
        }
        total -= gc_projected_bytes(&entries[oldest], out_actions[oldest]);
        out_actions[oldest] = CLAW_MEMORY_GC_DELETE;
    }

    /* Still over budget: compact the largest remaining logs. */
    while (total > CLAW_MEMORY_GC_BUDGET_BYTES) {
        size_t largest = count;

        for (i = 0; i < count; i++) {
            if (out_actions[i] == CLAW_MEMORY_GC_KEEP &&
                entries[i].log_bytes > CLAW_MEMORY_GC_KEEP_BYTES + 16U * 1024U &&
                (largest == count || entries[i].log_bytes > entries[largest].log_bytes)) {
                largest = i;
            }
        }
        if (largest == count) {
            break;
        }
        total -= entries[largest].bytes;
        out_actions[largest] = CLAW_MEMORY_GC_COMPACT;
        total += gc_projected_bytes(&entries[largest], out_actions[largest]);
    }
    return total;
}
