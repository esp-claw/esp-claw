#pragma once

#include <stddef.h>

#define CLAW_STORAGE_RESERVE_BYTES (128U * 1024U)

void claw_storage_set_allocation_unit(size_t bytes);
size_t claw_storage_get_allocation_unit(void);
