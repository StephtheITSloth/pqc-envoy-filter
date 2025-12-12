#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

/**
 * Simple base64 encoding utility for PQC key material transmission.
 * Used to encode binary keys/ciphertext for HTTP headers.
 */
class Base64Utils {
public:
  /**
   * Encode binary data to base64 string.
   *
   * @param data Pointer to binary data
   * @param len Length of binary data
   * @return Base64-encoded string
   */
  static std::string encode(const uint8_t* data, size_t len);

  /**
   * Decode base64 string to binary data.
   *
   * @param encoded Base64-encoded string
   * @return Vector of decoded bytes (empty on failure)
   */
  static std::vector<uint8_t> decode(const std::string& encoded);

private:
  static constexpr const char* BASE64_CHARS =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
};

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
