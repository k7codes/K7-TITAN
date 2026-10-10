#include "k7titan/hasher.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <fstream>

#pragma comment(lib, "bcrypt.lib")

namespace k7titan {

static std::string to_hex(const uint8_t* data, size_t len) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.resize(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out[i * 2] = kHex[(data[i] >> 4) & 0xF];
    out[i * 2 + 1] = kHex[data[i] & 0xF];
  }
  return out;
}

static std::string hash_with_lsa_property(LPCWSTR alg, const std::vector<uint8_t>& data, size_t digest_len) {
  BCRYPT_ALG_HANDLE alg_handle = nullptr;
  BCRYPT_HASH_HANDLE hash_handle = nullptr;
  std::string result;
  std::vector<uint8_t> digest(digest_len);

  if (BCryptOpenAlgorithmProvider(&alg_handle, alg, nullptr, 0) < 0) return result;
  if (BCryptCreateHash(alg_handle, &hash_handle, nullptr, 0, nullptr, 0, 0) < 0) {
    BCryptCloseAlgorithmProvider(alg_handle, 0);
    return result;
  }
  BCryptHashData(hash_handle, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0);
  BCryptFinishHash(hash_handle, digest.data(), static_cast<ULONG>(digest.size()), 0);
  result = to_hex(digest.data(), digest.size());

  BCryptDestroyHash(hash_handle);
  BCryptCloseAlgorithmProvider(alg_handle, 0);
  return result;
}

std::string sha256_hex(const std::vector<uint8_t>& data) {
  return hash_with_lsa_property(BCRYPT_SHA256_ALGORITHM, data, 32);
}

std::string md5_hex(const std::vector<uint8_t>& data) {
  return hash_with_lsa_property(BCRYPT_MD5_ALGORITHM, data, 16);
}

std::string sha256_hex_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return {};
  std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return sha256_hex(data);
}

}
