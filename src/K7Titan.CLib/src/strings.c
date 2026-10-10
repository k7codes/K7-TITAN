#include "k7titan_c/strings.h"

#include <ctype.h>
#include <math.h>

size_t k7tc_count_byte(const uint8_t* data, size_t len, uint8_t value) {
  if (!data) return 0;
  size_t count = 0;
  for (size_t i = 0; i < len; ++i) {
    if (data[i] == value) ++count;
  }
  return count;
}

int k7tc_entropy_percent(const uint8_t* data, size_t len) {
  if (!data || len == 0) return 0;
  size_t counts[256] = {0};
  for (size_t i = 0; i < len; ++i) counts[data[i]]++;

  double entropy = 0.0;
  for (size_t i = 0; i < 256; ++i) {
    if (!counts[i]) continue;
    double p = (double)counts[i] / (double)len;
    entropy -= p * (log(p) / log(2.0));
  }
  int percent = (int)((entropy / 8.0) * 100.0 + 0.5);
  if (percent < 0) percent = 0;
  if (percent > 100) percent = 100;
  return percent;
}

int k7tc_contains_ci(const uint8_t* data, size_t len, const char* needle) {
  if (!data || !needle || needle[0] == '\0') return 0;
  size_t nlen = 0;
  while (needle[nlen]) ++nlen;
  if (nlen > len) return 0;

  for (size_t i = 0; i + nlen <= len; ++i) {
    size_t j = 0;
    while (j < nlen &&
           tolower((unsigned char)data[i + j]) == tolower((unsigned char)needle[j])) {
      ++j;
    }
    if (j == nlen) return 1;
  }
  return 0;
}
