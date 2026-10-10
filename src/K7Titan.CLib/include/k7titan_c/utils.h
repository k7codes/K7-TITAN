#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define K7TC_API __declspec(dllexport)
#else
#define K7TC_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

K7TC_API int k7tc_hex_encode(const uint8_t* in, size_t inlen, char* out, size_t outlen);

#ifdef __cplusplus
}
#endif
