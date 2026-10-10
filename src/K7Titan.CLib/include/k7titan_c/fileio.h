#pragma once
#include <stddef.h>
#include <stdint.h>

#include "k7titan_c/utils.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint8_t* data;
  size_t size;
} k7tc_buffer;

/* Read an entire file into a heap buffer. Caller frees with k7tc_free_buffer. */
K7TC_API int k7tc_read_file(const char* path, k7tc_buffer* out);

/* Release a buffer produced by k7tc_read_file. */
K7TC_API void k7tc_free_buffer(k7tc_buffer* buf);

/* Query file size in bytes. Returns 0 on success, negative on error. */
K7TC_API int k7tc_file_size(const char* path, size_t* out);

#ifdef __cplusplus
}
#endif
