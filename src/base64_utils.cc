#include "src/base64_utils.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

std::string Base64Utils::encode(const uint8_t* data, size_t len) {
  if (!data || len == 0) {
    return "";
  }

  std::string encoded;
  encoded.reserve(((len + 2) / 3) * 4);  // Pre-allocate for efficiency

  for (size_t i = 0; i < len; i += 3) {
    uint32_t triple = (data[i] << 16);

    if (i + 1 < len) {
      triple |= (data[i + 1] << 8);
    }
    if (i + 2 < len) {
      triple |= data[i + 2];
    }

    // Extract 4 base64 characters from 3 bytes
    encoded.push_back(BASE64_CHARS[(triple >> 18) & 0x3F]);
    encoded.push_back(BASE64_CHARS[(triple >> 12) & 0x3F]);

    if (i + 1 < len) {
      encoded.push_back(BASE64_CHARS[(triple >> 6) & 0x3F]);
    } else {
      encoded.push_back('=');  // Padding
    }

    if (i + 2 < len) {
      encoded.push_back(BASE64_CHARS[triple & 0x3F]);
    } else {
      encoded.push_back('=');  // Padding
    }
  }

  return encoded;
}

std::vector<uint8_t> Base64Utils::decode(const std::string& encoded) {
  if (encoded.empty()) {
    return {};
  }

  // Validation: Length must be a multiple of 4
  if (encoded.size() % 4 != 0) {
    return {};  // Invalid: not a multiple of 4
  }

  // Build reverse lookup table (thread-safe in C++11+)
  static int lookup[256];
  static bool initialized = false;

  if (!initialized) {
    for (int i = 0; i < 256; i++) {
      lookup[i] = -1;
    }
    for (int i = 0; i < 64; i++) {
      lookup[static_cast<unsigned char>(BASE64_CHARS[i])] = i;
    }
    // Note: Padding character '=' is NOT added to lookup table
    // It will have value -1 and must be checked separately
    initialized = true;
  }

  std::vector<uint8_t> decoded;
  decoded.reserve((encoded.size() / 4) * 3);

  for (size_t i = 0; i < encoded.size(); i += 4) {
    // Get the 4 characters of this group
    char c0 = encoded[i];
    char c1 = encoded[i + 1];
    char c2 = encoded[i + 2];
    char c3 = encoded[i + 3];

    // Check for padding in invalid positions
    if (c0 == '=' || c1 == '=') {
      return {};  // Invalid: padding in first or second position
    }

    // Check for internal padding (not at the end)
    bool is_last_group = (i + 4 >= encoded.size());
    if (!is_last_group && (c2 == '=' || c3 == '=')) {
      return {};  // Invalid: padding not at end
    }

    // Validate padding patterns in the last group
    if (is_last_group) {
      if (c2 == '=' && c3 != '=') {
        return {};  // Invalid: if position 2 is padding, position 3 must be too
      }
      if (c2 != '=' && c3 == '=' && c2 == '=') {
        return {};  // Invalid: position 2 can't be padding if position 3 is
      }
    }

    // Get lookup values (only for non-padding characters)
    int val0 = lookup[static_cast<unsigned char>(c0)];
    int val1 = lookup[static_cast<unsigned char>(c1)];
    int val2 = (c2 == '=') ? 0 : lookup[static_cast<unsigned char>(c2)];
    int val3 = (c3 == '=') ? 0 : lookup[static_cast<unsigned char>(c3)];

    // Validate characters
    if (val0 == -1 || val1 == -1) {
      return {};  // Invalid character in first two positions
    }
    if (c2 != '=' && val2 == -1) {
      return {};  // Invalid character in position 2
    }
    if (c3 != '=' && val3 == -1) {
      return {};  // Invalid character in position 3
    }

    // Decode the triple
    uint32_t triple = (val0 << 18) | (val1 << 12) | (val2 << 6) | val3;

    // Extract bytes based on padding
    decoded.push_back((triple >> 16) & 0xFF);

    if (c2 != '=') {
      decoded.push_back((triple >> 8) & 0xFF);
    }

    if (c3 != '=') {
      decoded.push_back(triple & 0xFF);
    }
  }

  return decoded;
}

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
