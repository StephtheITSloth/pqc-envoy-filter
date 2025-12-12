// Test file for Base64Utils encoding and decoding
// Comprehensive tests for base64 encode/decode operations

#include "gtest/gtest.h"
#include "src/base64_utils.h"

using namespace Envoy::Extensions::HttpFilters::PqcFilter;

// ============================================================================
// BASE64 ENCODING TESTS
// ============================================================================

TEST(Base64UtilsTest, EncodeEmptyData) {
  // ARRANGE
  const uint8_t* data = nullptr;
  size_t len = 0;

  // ACT
  std::string result = Base64Utils::encode(data, len);

  // ASSERT
  ASSERT_EQ(result, "");
}

TEST(Base64UtilsTest, EncodeThreeBytes) {
  // ARRANGE: "ABC" -> "QUJD"
  const uint8_t data[] = {0x41, 0x42, 0x43};

  // ACT
  std::string result = Base64Utils::encode(data, 3);

  // ASSERT
  ASSERT_EQ(result, "QUJD");
}

TEST(Base64UtilsTest, EncodeTwoBytesWithPadding) {
  // ARRANGE: 2 bytes should have 1 padding char
  const uint8_t data[] = {0xFF, 0xAB};

  // ACT
  std::string result = Base64Utils::encode(data, 2);

  // ASSERT
  ASSERT_EQ(result, "/6s=");
  ASSERT_EQ(result[3], '=');  // Verify padding
}

TEST(Base64UtilsTest, EncodeOneByteWithPadding) {
  // ARRANGE: 1 byte should have 2 padding chars
  const uint8_t data[] = {0xFF};

  // ACT
  std::string result = Base64Utils::encode(data, 1);

  // ASSERT
  ASSERT_EQ(result, "/w==");
  ASSERT_EQ(result[2], '=');  // Verify first padding
  ASSERT_EQ(result[3], '=');  // Verify second padding
}

// ============================================================================
// BASE64 DECODING TESTS
// ============================================================================

TEST(Base64UtilsTest, DecodeEmptyString) {
  // ARRANGE
  std::string encoded = "";

  // ACT
  std::vector<uint8_t> result = Base64Utils::decode(encoded);

  // ASSERT
  ASSERT_TRUE(result.empty());
}

TEST(Base64UtilsTest, DecodeValidThreeBytes) {
  // ARRANGE: "QUJD" -> "ABC" (0x41, 0x42, 0x43)
  std::string encoded = "QUJD";

  // ACT
  std::vector<uint8_t> result = Base64Utils::decode(encoded);

  // ASSERT
  ASSERT_EQ(result.size(), 3);
  ASSERT_EQ(result[0], 0x41);  // 'A'
  ASSERT_EQ(result[1], 0x42);  // 'B'
  ASSERT_EQ(result[2], 0x43);  // 'C'
}

TEST(Base64UtilsTest, DecodeTwoBytesWithPadding) {
  // ARRANGE: "/6s=" -> [0xFF, 0xAB]
  std::string encoded = "/6s=";

  // ACT
  std::vector<uint8_t> result = Base64Utils::decode(encoded);

  // ASSERT
  ASSERT_EQ(result.size(), 2);
  ASSERT_EQ(result[0], 0xFF);
  ASSERT_EQ(result[1], 0xAB);
}

TEST(Base64UtilsTest, DecodeOneByteWithPadding) {
  // ARRANGE: "/w==" -> [0xFF]
  std::string encoded = "/w==";

  // ACT
  std::vector<uint8_t> result = Base64Utils::decode(encoded);

  // ASSERT
  ASSERT_EQ(result.size(), 1);
  ASSERT_EQ(result[0], 0xFF);
}

TEST(Base64UtilsTest, DecodeInvalidCharacter) {
  // ARRANGE: Invalid character '@' in base64
  std::string encoded = "QUJ@";

  // ACT
  std::vector<uint8_t> result = Base64Utils::decode(encoded);

  // ASSERT: Should return empty vector on invalid input
  ASSERT_TRUE(result.empty());
}

// ============================================================================
// ROUND-TRIP TESTS (Encode then Decode)
// ============================================================================

TEST(Base64UtilsTest, RoundTripThreeBytes) {
  // ARRANGE
  const uint8_t original[] = {0x41, 0x42, 0x43};

  // ACT
  std::string encoded = Base64Utils::encode(original, 3);
  std::vector<uint8_t> decoded = Base64Utils::decode(encoded);

  // ASSERT
  ASSERT_EQ(decoded.size(), 3);
  ASSERT_EQ(decoded[0], original[0]);
  ASSERT_EQ(decoded[1], original[1]);
  ASSERT_EQ(decoded[2], original[2]);
}

TEST(Base64UtilsTest, RoundTripTwoBytes) {
  // ARRANGE
  const uint8_t original[] = {0xFF, 0xAB};

  // ACT
  std::string encoded = Base64Utils::encode(original, 2);
  std::vector<uint8_t> decoded = Base64Utils::decode(encoded);

  // ASSERT
  ASSERT_EQ(decoded.size(), 2);
  ASSERT_EQ(decoded[0], original[0]);
  ASSERT_EQ(decoded[1], original[1]);
}

TEST(Base64UtilsTest, RoundTripOneByte) {
  // ARRANGE
  const uint8_t original[] = {0xFF};

  // ACT
  std::string encoded = Base64Utils::encode(original, 1);
  std::vector<uint8_t> decoded = Base64Utils::decode(encoded);

  // ASSERT
  ASSERT_EQ(decoded.size(), 1);
  ASSERT_EQ(decoded[0], original[0]);
}

TEST(Base64UtilsTest, RoundTripKyberPublicKey) {
  // ARRANGE: Simulate a Kyber768 public key (1184 bytes)
  std::vector<uint8_t> original(1184);
  for (size_t i = 0; i < 1184; i++) {
    original[i] = static_cast<uint8_t>(i % 256);
  }

  // ACT
  std::string encoded = Base64Utils::encode(original.data(), original.size());
  std::vector<uint8_t> decoded = Base64Utils::decode(encoded);

  // ASSERT
  ASSERT_EQ(decoded.size(), original.size());
  for (size_t i = 0; i < original.size(); i++) {
    ASSERT_EQ(decoded[i], original[i]) << "Mismatch at byte " << i;
  }
}

// ============================================================================
// EDGE CASES AND VALIDATION TESTS
// ============================================================================

TEST(Base64UtilsTest, DecodeIncompleteGroup) {
  // ARRANGE: Only 3 characters when we need 4
  std::string encoded = "QUJ";  // Incomplete

  // ACT
  std::vector<uint8_t> result = Base64Utils::decode(encoded);

  // ASSERT: Should return empty vector (invalid input)
  ASSERT_TRUE(result.empty());
}

TEST(Base64UtilsTest, DecodeInvalidLengthNotMultipleOfFour) {
  // ARRANGE: Length 5 is not a multiple of 4
  std::string encoded = "QUJDE";  // Invalid length

  // ACT
  std::vector<uint8_t> result = Base64Utils::decode(encoded);

  // ASSERT: Should return empty vector
  ASSERT_TRUE(result.empty());
}

TEST(Base64UtilsTest, DecodeInvalidLengthOne) {
  // ARRANGE: Length 1 is not valid
  std::string encoded = "Q";

  // ACT
  std::vector<uint8_t> result = Base64Utils::decode(encoded);

  // ASSERT: Should return empty vector
  ASSERT_TRUE(result.empty());
}

TEST(Base64UtilsTest, DecodeInvalidLengthTwo) {
  // ARRANGE: Length 2 is not valid
  std::string encoded = "QU";

  // ACT
  std::vector<uint8_t> result = Base64Utils::decode(encoded);

  // ASSERT: Should return empty vector
  ASSERT_TRUE(result.empty());
}

TEST(Base64UtilsTest, DecodeInternalPaddingInvalid) {
  // ARRANGE: Padding in the middle is invalid (A==B is wrong)
  std::string encoded = "A==B";

  // ACT
  std::vector<uint8_t> result = Base64Utils::decode(encoded);

  // ASSERT: Should return empty vector (padding must be at end)
  ASSERT_TRUE(result.empty());
}

TEST(Base64UtilsTest, DecodePaddingInFirstPosition) {
  // ARRANGE: Padding in first position is invalid
  std::string encoded = "=ABC";

  // ACT
  std::vector<uint8_t> result = Base64Utils::decode(encoded);

  // ASSERT: Should return empty vector
  ASSERT_TRUE(result.empty());
}

TEST(Base64UtilsTest, DecodePaddingInSecondPosition) {
  // ARRANGE: Padding in second position is invalid
  std::string encoded = "A=BC";

  // ACT
  std::vector<uint8_t> result = Base64Utils::decode(encoded);

  // ASSERT: Should return empty vector
  ASSERT_TRUE(result.empty());
}

TEST(Base64UtilsTest, DecodeThreePaddingCharacters) {
  // ARRANGE: Three padding characters is invalid (max is 2)
  std::string encoded = "A===";

  // ACT
  std::vector<uint8_t> result = Base64Utils::decode(encoded);

  // ASSERT: Should return empty vector
  ASSERT_TRUE(result.empty());
}

TEST(Base64UtilsTest, EncodeLargeData) {
  // ARRANGE: 10KB of data
  std::vector<uint8_t> original(10240);
  for (size_t i = 0; i < original.size(); i++) {
    original[i] = static_cast<uint8_t>(i % 256);
  }

  // ACT
  std::string encoded = Base64Utils::encode(original.data(), original.size());
  std::vector<uint8_t> decoded = Base64Utils::decode(encoded);

  // ASSERT
  ASSERT_EQ(decoded.size(), original.size());
  ASSERT_EQ(decoded, original);
}
