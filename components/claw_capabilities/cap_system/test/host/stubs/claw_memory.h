#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

esp_err_t claw_memory_storage_check(bool repair, char *out, size_t out_size);
