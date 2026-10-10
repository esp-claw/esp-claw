/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *platform;
    const char *attachment_kind;
    const char *saved_path;
    const char *saved_dir;
    const char *saved_name;
    const char *original_filename;
    const char *mime;
    const char *caption;
    const char *source_key;
    const char *source_value;
    size_t size_bytes;
    int64_t saved_at_ms;
} cap_im_attachment_payload_config_t;

const char *cap_im_attachment_ext_from_mime(const char *mime);
const char *cap_im_attachment_guess_extension(const char *path_or_url,
                                              const char *original_filename,
                                              const char *mime);
const char *cap_im_attachment_normalize_url(const char *url,
                                            char *buf,
                                            size_t buf_size);
esp_err_t cap_im_attachment_build_saved_paths(const char *root_dir,
                                              const char *platform_dir,
                                              const char *chat_id,
                                              const char *message_id,
                                              const char *kind,
                                              const char *extension,
                                              char *saved_dir,
                                              size_t saved_dir_size,
                                              char *saved_name,
                                              size_t saved_name_size,
                                              char *saved_path,
                                              size_t saved_path_size);
/* Streams url to dest_path in small chunks. expected_bytes (0 if unknown) sizes the free-space
 * check: known sizes need expected_bytes plus a fixed reserve, unknown sizes a larger fixed floor.
 * Returns ESP_ERR_NO_MEM when the storage volume, not RAM, is too full. */
esp_err_t cap_im_attachment_download_url_to_file(const char *log_tag,
                                                 const char *root_dir,
                                                 const char *url,
                                                 const char *dest_path,
                                                 size_t max_bytes,
                                                 size_t expected_bytes,
                                                 size_t *out_bytes);
esp_err_t cap_im_attachment_save_buffer_to_file(const char *log_tag,
                                                const char *dest_path,
                                                const unsigned char *buf,
                                                size_t buf_len);
/* Deletes the oldest files under root_dir/<platform>/<chat>/ until the shared inbox budget is met.
 * keep_path (may be NULL) is never deleted. */
void cap_im_attachment_prune_inbox(const char *log_tag, const char *root_dir, const char *keep_path);
/* Uploads the audio file at path to an OpenAI-compatible <base_url>/audio/transcriptions endpoint.
 * On success *out_text is a heap string the caller frees. On failure a short reason is written to
 * err_buf. */
esp_err_t cap_im_attachment_transcribe_file(const char *log_tag,
                                            const char *base_url,
                                            const char *api_key,
                                            const char *model,
                                            const char *path,
                                            const char *mime,
                                            char **out_text,
                                            char *err_buf,
                                            size_t err_buf_size);
char *cap_im_attachment_build_payload_json(
    const cap_im_attachment_payload_config_t *config);

#ifdef __cplusplus
}
#endif
