#pragma once
#include <stddef.h>
#include <stdint.h>

#include "k7titan_c/utils.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Count occurrences of a single byte value. */
K7TC_API size_t k7tc_count_byte(const uint8_t* data, size_t len, uint8_t value);

/* Shannon entropy scaled to 0-100 (8 bits -> 100). */
K7TC_API int k7tc_entropy_percent(const uint8_t* data, size_t len);

/* Case-insensitive substring search. Returns 1 if found, 0 otherwise. */
K7TC_API int k7tc_contains_ci(const uint8_t* data, size_t len, const char* needle);

#ifdef __cplusplus
}
#endif
