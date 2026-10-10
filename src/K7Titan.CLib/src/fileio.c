#include "k7titan_c/fileio.h"

#include <stdio.h>
#include <stdlib.h>

int k7tc_read_file(const char* path, k7tc_buffer* out) {
  if (!path || !out) return -1;
  out->data = NULL;
  out->size = 0;

  FILE* f = fopen(path, "rb");
  if (!f) return -2;

  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return -3;
  }
  long size = ftell(f);
  if (size < 0) {
    fclose(f);
    return -3;
  }
  rewind(f);

  out->data = (uint8_t*)malloc((size_t)size ? (size_t)size : 1);
  if (!out->data) {
    fclose(f);
    return -4;
  }

  size_t read = fread(out->data, 1, (size_t)size, f);
  fclose(f);
  out->size = read;
  return 0;
}

void k7tc_free_buffer(k7tc_buffer* buf) {
  if (!buf) return;
  free(buf->data);
  buf->data = NULL;
  buf->size = 0;
}

int k7tc_file_size(const char* path, size_t* out) {
  if (!path || !out) return -1;
  FILE* f = fopen(path, "rb");
  if (!f) return -2;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return -3;
  }
  long size = ftell(f);
  fclose(f);
  if (size < 0) return -3;
  *out = (size_t)size;
  return 0;
}
