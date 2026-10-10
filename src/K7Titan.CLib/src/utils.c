#include "k7titan_c/utils.h"
#include <stdio.h>

static const char* hex = "0123456789abcdef";

K7TC_API int k7tc_hex_encode(const uint8_t* in, size_t inlen, char* out, size_t outlen) {
  if (!in || !out || outlen < inlen * 2 + 1) return -1;
  for (size_t i = 0; i < inlen; ++i) {
    out[i * 2 + 0] = hex[(in[i] >> 4) & 0xF];
    out[i * 2 + 1] = hex[in[i] & 0xF];
  }
  out[inlen * 2] = '\0';
  return 0;
}
