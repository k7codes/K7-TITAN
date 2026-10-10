#pragma once
#include <stddef.h>
#include <stdint.h>

#include "k7titan_c/utils.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Compute CRC-32 (IEEE 802.3) of a buffer. Pass 0 as seed for a fresh run. */
K7TC_API uint32_t k7tc_crc32(const uint8_t* data, size_t len, uint32_t seed);

#ifdef __cplusplus
}
#endif
