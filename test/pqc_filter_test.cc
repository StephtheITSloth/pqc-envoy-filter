// Test file for PqcFilter HTTP Stream Decoder Filter
// Tests the core filter logic including hex logging functionality

#include "gtest/gtest.h"
#include "test/pqc_filter_testable.h"  // Uses mock Envoy interfaces
#include "src/pqc_filter_config.h"

using namespace Envoy::Extensions::HttpFilters::PqcFilter;
using namespace Envoy::Buffer;
using namespace Envoy::Http;

// Test Fixture: Sets up common test infrastructure
class PqcFilterTest : public testing::Test {
protected:
  // This runs before each test
  void SetUp() override {
    // Create a config with a test algorithm name
    config_ = std::make_shared<PqcFilterConfig>("TestAlgorithm");

    // Create the filter instance
    filter_ = std::make_unique<PqcFilter>(config_);
  }

  // Test data members
  std::shared_ptr<PqcFilterConfig> config_;
  std::unique_ptr<PqcFilter> filter_;
};

// ============================================================================
// TEST CASES
// ============================================================================

TEST_F(PqcFilterTest, FilterCanBeInstantiated) {
  // ARRANGE: (done in SetUp)

  // ACT: Filter is already created

  // ASSERT: Verify filter exists
  ASSERT_NE(filter_, nullptr);
}

// Test 1: Basic functionality - filter returns Continue status
TEST_F(PqcFilterTest, DecodeDataReturnsCorrectStatus) {
  // ARRANGE: Create a buffer with some test data
  std::vector<uint8_t> test_data = {0x01, 0x02, 0x03, 0x04, 0x05};
  Instance buffer(test_data);

  // ACT: Call decodeData
  FilterDataStatus status = filter_->decodeData(buffer, false);

  // ASSERT: Should return Continue to pass data through
  ASSERT_EQ(status, FilterDataStatus::Continue);
}

// Test 2: Buffer with >= 10 bytes - should log first 10 bytes as hex
TEST_F(PqcFilterTest, DecodeDataWith10OrMoreBytes) {
  // ARRANGE: Create buffer with exactly 15 bytes
  std::vector<uint8_t> test_data = {
    0x0A, 0x1B, 0x2C, 0x3D, 0x4E,  // First 5
    0x5F, 0x60, 0x71, 0x82, 0x93,  // Next 5 (completes first 10)
    0xA4, 0xB5, 0xC6, 0xD7, 0xE8   // Extra 5 (should not be logged)
  };
  Instance buffer(test_data);

  // ACT: Call decodeData
  FilterDataStatus status = filter_->decodeData(buffer, false);

  // ASSERT: Status should be Continue
  ASSERT_EQ(status, FilterDataStatus::Continue);

  // TODO: When we implement hex logging, we'll verify the log contains:
  // "0A 1B 2C 3D 4E 5F 60 71 82 93"
  // For now, we just verify it doesn't crash
}

// Test 3: Buffer with < 10 bytes - should log all available bytes
TEST_F(PqcFilterTest, DecodeDataWithFewerThan10Bytes) {
  // ARRANGE: Create buffer with only 5 bytes
  std::vector<uint8_t> test_data = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB};
  Instance buffer(test_data);

  // ACT: Call decodeData
  FilterDataStatus status = filter_->decodeData(buffer, false);

  // ASSERT: Status should be Continue
  ASSERT_EQ(status, FilterDataStatus::Continue);

  // TODO: When we implement hex logging, we'll verify the log contains:
  // "FF EE DD CC BB"
}

// Test 4: Empty buffer - should handle gracefully
TEST_F(PqcFilterTest, DecodeDataWithEmptyBuffer) {
  // ARRANGE: Create empty buffer
  Instance buffer;  // Default constructor creates empty buffer

  // ACT: Call decodeData
  FilterDataStatus status = filter_->decodeData(buffer, false);

  // ASSERT: Should not crash and return Continue
  ASSERT_EQ(status, FilterDataStatus::Continue);
  ASSERT_EQ(buffer.length(), 0);
}

// ============================================================================
// TLS RECORD TYPE 22 DETECTION TESTS
// ============================================================================

// Test 5: TLS Handshake detection - buffer starts with 0x16 (TLS Record Type 22)
TEST_F(PqcFilterTest, DetectTlsHandshakeRecordType22) {
  // ARRANGE: Create buffer starting with 0x16 (TLS Handshake)
  // This simulates the start of a TLS handshake (ClientHello, ServerHello, etc.)
  std::vector<uint8_t> test_data = {
    0x16,  // TLS Record Type 22 (Handshake)
    0x03, 0x03,  // TLS version (TLS 1.2)
    0x00, 0x05,  // Record length
    0x01, 0x02, 0x03, 0x04, 0x05  // Payload
  };
  Instance buffer(test_data);

  // ACT: Call decodeData
  FilterDataStatus status = filter_->decodeData(buffer, false);

  // ASSERT: Should detect TLS handshake and return Continue
  ASSERT_EQ(status, FilterDataStatus::Continue);

  // TODO: When logging is implemented, verify log contains:
  // "Detected TLS Handshake (Record Type 22)"
}

// Test 6: Non-TLS data - buffer does NOT start with 0x16
TEST_F(PqcFilterTest, DoesNotDetectTlsWhenNotPresent) {
  // ARRANGE: Create buffer with regular HTTP data (not TLS)
  std::vector<uint8_t> test_data = {
    0x47, 0x45, 0x54, 0x20,  // "GET " in ASCII
    0x2F, 0x69, 0x6E, 0x64   // "/ind"
  };
  Instance buffer(test_data);

  // ACT: Call decodeData
  FilterDataStatus status = filter_->decodeData(buffer, false);

  // ASSERT: Should NOT detect TLS and return Continue
  ASSERT_EQ(status, FilterDataStatus::Continue);

  // TODO: When logging is implemented, verify log does NOT contain:
  // "Detected TLS Handshake"
}

// Test 7: Buffer safety - empty buffer should not crash when checking for TLS
TEST_F(PqcFilterTest, TlsDetectionSafeWithEmptyBuffer) {
  // ARRANGE: Create empty buffer
  Instance buffer;

  // ACT: Call decodeData (should check buffer size BEFORE accessing bytes)
  FilterDataStatus status = filter_->decodeData(buffer, false);

  // ASSERT: Should not crash and return Continue
  // This test validates CRITICAL security check:
  // Must check buffer_length > 0 BEFORE accessing slice_data[0]
  ASSERT_EQ(status, FilterDataStatus::Continue);
  ASSERT_EQ(buffer.length(), 0);
}

// Test 8: Single byte TLS handshake - edge case with minimal buffer
TEST_F(PqcFilterTest, TlsDetectionWithSingleByte) {
  // ARRANGE: Create buffer with just the TLS record type byte
  std::vector<uint8_t> test_data = {0x16};  // Just the handshake byte
  Instance buffer(test_data);

  // ACT: Call decodeData
  FilterDataStatus status = filter_->decodeData(buffer, false);

  // ASSERT: Should detect TLS even with minimal data
  ASSERT_EQ(status, FilterDataStatus::Continue);

  // TODO: When logging is implemented, verify log contains:
  // "Detected TLS Handshake (Record Type 22)"
}

// ============================================================================
// POST-QUANTUM CRYPTOGRAPHY INITIALIZATION TESTS (TDD)
// ============================================================================

// Test 9: Kyber-768 initialization - verify filter initializes PQC correctly
TEST_F(PqcFilterTest, KyberInitializationSucceeds) {
  // ARRANGE: Filter is already created in SetUp()
  // The constructor should have called initializeKyber()

  // ACT: Filter should be fully initialized
  // We can't directly access private members (kyber_kem_, kyber_public_key_, etc.)
  // But we can verify the filter was constructed without errors

  // ASSERT: Filter exists and was created successfully
  ASSERT_NE(filter_, nullptr);

  // Additional verification: Filter can process data after Kyber init
  std::vector<uint8_t> test_data = {0x01, 0x02, 0x03};
  Instance buffer(test_data);
  FilterDataStatus status = filter_->decodeData(buffer, false);
  ASSERT_EQ(status, FilterDataStatus::Continue);

  // Verify Kyber initialization using public methods
  ASSERT_TRUE(filter_->hasKyberInitialized());
  ASSERT_NE(filter_->getKyberPublicKeySize(), 0);
  ASSERT_NE(filter_->getKyberPublicKey(), nullptr);

  // Kyber768 should have 1184 byte public key
  ASSERT_EQ(filter_->getKyberPublicKeySize(), 1184);
}

// Test 10: Dilithium3 (ML-DSA-65) initialization - verify digital signature capability
TEST_F(PqcFilterTest, DilithiumInitializationSucceeds) {
  // ARRANGE: Filter is already created in SetUp()
  // The constructor should have called initializeDilithium()

  // ACT: Filter should be fully initialized with Dilithium
  // We can't directly access private members (dilithium_sig_, dilithium_public_key_, etc.)
  // But we can verify the filter was constructed without errors

  // ASSERT: Filter exists and was created successfully
  ASSERT_NE(filter_, nullptr);

  // Additional verification: Filter can process data after Dilithium init
  std::vector<uint8_t> test_data = {0x01, 0x02, 0x03};
  Instance buffer(test_data);
  FilterDataStatus status = filter_->decodeData(buffer, false);
  ASSERT_EQ(status, FilterDataStatus::Continue);

  // Verify Dilithium initialization using public methods
  ASSERT_TRUE(filter_->hasDilithiumInitialized());
  ASSERT_NE(filter_->getDilithiumPublicKeySize(), 0);
  ASSERT_NE(filter_->getDilithiumPublicKey(), nullptr);

  // ML-DSA-65 (Dilithium3) should have 1952 byte public key
  ASSERT_EQ(filter_->getDilithiumPublicKeySize(), 1952);
}

// ============================================================================
// KEM ENCAPSULATION TESTS (Client-side key exchange)
// ============================================================================

// Test 11: Client encapsulation - simulate client generating shared secret
TEST_F(PqcFilterTest, ClientEncapsulationSucceeds) {
  // ARRANGE: Get the server's public key
  const uint8_t* server_public_key = filter_->getKyberPublicKey();
  size_t public_key_size = filter_->getKyberPublicKeySize();

  ASSERT_NE(server_public_key, nullptr);
  ASSERT_EQ(public_key_size, 1184);  // Kyber768 public key size

  // Allocate buffers for outputs
  // Kyber768: ciphertext = 1088 bytes, shared_secret = 32 bytes
  std::vector<uint8_t> ciphertext(1088);
  std::vector<uint8_t> shared_secret(32);

  // ACT: Perform client-side encapsulation
  bool success = filter_->clientEncapsulate(
      server_public_key,
      public_key_size,
      ciphertext.data(),
      shared_secret.data()
  );

  // ASSERT: Encapsulation should succeed
  ASSERT_TRUE(success);

  // Verify outputs are non-zero (contain data)
  bool ciphertext_has_data = false;
  for (uint8_t byte : ciphertext) {
    if (byte != 0) {
      ciphertext_has_data = true;
      break;
    }
  }
  ASSERT_TRUE(ciphertext_has_data);

  bool shared_secret_has_data = false;
  for (uint8_t byte : shared_secret) {
    if (byte != 0) {
      shared_secret_has_data = true;
      break;
    }
  }
  ASSERT_TRUE(shared_secret_has_data);
}

// Test 12: Client encapsulation with null public key - should fail gracefully
TEST_F(PqcFilterTest, ClientEncapsulationFailsWithNullPublicKey) {
  // ARRANGE: Create output buffers
  std::vector<uint8_t> ciphertext(1088);
  std::vector<uint8_t> shared_secret(32);

  // ACT: Try to encapsulate with null public key
  bool success = filter_->clientEncapsulate(
      nullptr,  // Invalid: null public key
      1184,
      ciphertext.data(),
      shared_secret.data()
  );

  // ASSERT: Should fail
  ASSERT_FALSE(success);
}

// Test 13: Client encapsulation with invalid key length - should fail
TEST_F(PqcFilterTest, ClientEncapsulationFailsWithInvalidKeyLength) {
  // ARRANGE: Get server's public key but use wrong length
  const uint8_t* server_public_key = filter_->getKyberPublicKey();
  std::vector<uint8_t> ciphertext(1088);
  std::vector<uint8_t> shared_secret(32);

  // ACT: Try to encapsulate with wrong key length
  bool success = filter_->clientEncapsulate(
      server_public_key,
      999,  // Invalid: wrong length (should be 1184)
      ciphertext.data(),
      shared_secret.data()
  );

  // ASSERT: Should fail
  ASSERT_FALSE(success);
}

// Test 14: Client encapsulation with null output buffers - should fail
TEST_F(PqcFilterTest, ClientEncapsulationFailsWithNullOutputs) {
  // ARRANGE: Get server's public key
  const uint8_t* server_public_key = filter_->getKyberPublicKey();
  size_t public_key_size = filter_->getKyberPublicKeySize();

  // ACT & ASSERT: Try with null ciphertext buffer
  bool success1 = filter_->clientEncapsulate(
      server_public_key,
      public_key_size,
      nullptr,  // Invalid: null ciphertext
      new uint8_t[32]
  );
  ASSERT_FALSE(success1);

  // ACT & ASSERT: Try with null shared secret buffer
  bool success2 = filter_->clientEncapsulate(
      server_public_key,
      public_key_size,
      new uint8_t[1088],
      nullptr  // Invalid: null shared secret
  );
  ASSERT_FALSE(success2);
}
