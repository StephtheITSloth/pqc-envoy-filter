// Test file for PqcFilter HTTP Stream Decoder Filter
// Tests the core filter logic including hex logging functionality

#include "gtest/gtest.h"
#include "test/pqc_filter_testable.h"  // Uses mock Envoy interfaces
#include "src/pqc_filter_config.h"
#include "src/base64_utils.h"  // Base64 encoding/decoding for HTTP headers

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

// ============================================================================
// KEM DECAPSULATION TESTS (Server-side key exchange)
// ============================================================================

// Test 15: Server decapsulation - recover shared secret from ciphertext
TEST_F(PqcFilterTest, ServerDecapsulationSucceeds) {
  // ARRANGE: Simulate client encapsulation first
  const uint8_t* server_public_key = filter_->getKyberPublicKey();
  std::vector<uint8_t> ciphertext(1088);
  std::vector<uint8_t> client_secret(32);

  bool encaps_success = filter_->clientEncapsulate(
      server_public_key,
      1184,
      ciphertext.data(),
      client_secret.data()
  );
  ASSERT_TRUE(encaps_success);

  // ACT: Server decapsulates to recover shared secret
  std::vector<uint8_t> server_secret(32);
  bool decaps_success = filter_->serverDecapsulate(
      ciphertext.data(),
      1088,
      server_secret.data()
  );

  // ASSERT: Decapsulation should succeed
  ASSERT_TRUE(decaps_success);

  // Verify server's secret has data
  bool server_secret_has_data = false;
  for (uint8_t byte : server_secret) {
    if (byte != 0) {
      server_secret_has_data = true;
      break;
    }
  }
  ASSERT_TRUE(server_secret_has_data);
}

// Test 16: Server decapsulation with null ciphertext - should fail
TEST_F(PqcFilterTest, ServerDecapsulationFailsWithNullCiphertext) {
  // ARRANGE: Create output buffer
  std::vector<uint8_t> server_secret(32);

  // ACT: Try to decapsulate with null ciphertext
  bool success = filter_->serverDecapsulate(
      nullptr,  // Invalid: null ciphertext
      1088,
      server_secret.data()
  );

  // ASSERT: Should fail
  ASSERT_FALSE(success);
}

// Test 17: Server decapsulation with invalid ciphertext length - should fail
TEST_F(PqcFilterTest, ServerDecapsulationFailsWithInvalidCiphertextLength) {
  // ARRANGE: Create valid ciphertext
  const uint8_t* server_public_key = filter_->getKyberPublicKey();
  std::vector<uint8_t> ciphertext(1088);
  std::vector<uint8_t> client_secret(32);

  filter_->clientEncapsulate(
      server_public_key,
      1184,
      ciphertext.data(),
      client_secret.data()
  );

  std::vector<uint8_t> server_secret(32);

  // ACT: Try to decapsulate with wrong ciphertext length
  bool success = filter_->serverDecapsulate(
      ciphertext.data(),
      999,  // Invalid: wrong length (should be 1088)
      server_secret.data()
  );

  // ASSERT: Should fail
  ASSERT_FALSE(success);
}

// Test 18: Server decapsulation with null output buffer - should fail
TEST_F(PqcFilterTest, ServerDecapsulationFailsWithNullOutput) {
  // ARRANGE: Create valid ciphertext
  const uint8_t* server_public_key = filter_->getKyberPublicKey();
  std::vector<uint8_t> ciphertext(1088);
  std::vector<uint8_t> client_secret(32);

  filter_->clientEncapsulate(
      server_public_key,
      1184,
      ciphertext.data(),
      client_secret.data()
  );

  // ACT: Try to decapsulate with null output buffer
  bool success = filter_->serverDecapsulate(
      ciphertext.data(),
      1088,
      nullptr  // Invalid: null output
  );

  // ASSERT: Should fail
  ASSERT_FALSE(success);
}

// ============================================================================
// FULL KEY EXCHANGE INTEGRATION TEST
// ============================================================================

// Test 19: Complete key exchange - verify client and server get identical secrets
TEST_F(PqcFilterTest, FullKeyExchangeProducesIdenticalSharedSecrets) {
  // ARRANGE: Get server's public key
  const uint8_t* server_public_key = filter_->getKyberPublicKey();
  size_t public_key_size = filter_->getKyberPublicKeySize();

  // Client buffers
  std::vector<uint8_t> ciphertext(1088);
  std::vector<uint8_t> client_shared_secret(32);

  // Server buffer
  std::vector<uint8_t> server_shared_secret(32);

  // ACT: Perform complete key exchange

  // Step 1: Client encapsulates (generates shared secret + ciphertext)
  bool encaps_success = filter_->clientEncapsulate(
      server_public_key,
      public_key_size,
      ciphertext.data(),
      client_shared_secret.data()
  );
  ASSERT_TRUE(encaps_success);

  // Step 2: Server decapsulates (recovers shared secret from ciphertext)
  bool decaps_success = filter_->serverDecapsulate(
      ciphertext.data(),
      1088,
      server_shared_secret.data()
  );
  ASSERT_TRUE(decaps_success);

  // ASSERT: Both shared secrets must be identical!
  // This is the CRITICAL property of KEM - both parties derive the same secret
  for (size_t i = 0; i < 32; i++) {
    ASSERT_EQ(client_shared_secret[i], server_shared_secret[i])
        << "Shared secret mismatch at byte " << i;
  }

  // Additional verification: secrets are not all zeros
  bool has_nonzero = false;
  for (uint8_t byte : client_shared_secret) {
    if (byte != 0) {
      has_nonzero = true;
      break;
    }
  }
  ASSERT_TRUE(has_nonzero) << "Shared secret should not be all zeros";
}

// ============================================================================
// HTTP HEADER KEY EXCHANGE TESTS (Application-Layer PQC)
// ============================================================================

// Test 20: Server advertises public key when client requests PQC
TEST_F(PqcFilterTest, ServerAdvertisesPublicKeyInResponseHeader) {
  // ARRANGE: Create request with PQC initialization header
  RequestHeaderMap request_headers;
  request_headers.addCopy(LowerCaseString("x-pqc-init"), "true");

  // ACT: Filter processes the request headers
  FilterHeadersStatus status = filter_->decodeHeaders(request_headers, false);

  // ASSERT: Filter should continue processing
  ASSERT_EQ(status, FilterHeadersStatus::Continue);

  // ACT (Part 2): Filter processes response headers
  ResponseHeaderMap response_headers;
  FilterHeadersStatus response_status = filter_->encodeHeaders(response_headers, false);

  // ASSERT: Filter should continue processing responses
  ASSERT_EQ(response_status, FilterHeadersStatus::Continue);

  // ASSERT: Response should contain X-PQC-Public-Key header
  auto public_key_header = response_headers.get(LowerCaseString("x-pqc-public-key"));
  ASSERT_FALSE(public_key_header.empty());

  // ASSERT: Public key should be base64-encoded (1184 bytes → ~1580 chars)
  const auto& encoded_key = public_key_header[0]->value().getStringView();
  ASSERT_GT(encoded_key.size(), 1500);  // Should be around 1580 characters
  ASSERT_LT(encoded_key.size(), 1650);

  // ASSERT: Response should contain X-PQC-Status header
  auto status_header = response_headers.get(LowerCaseString("x-pqc-status"));
  ASSERT_FALSE(status_header.empty());
  ASSERT_EQ(status_header[0]->value().getStringView(), "pending");
}

// Test 21: Client sends ciphertext and server decapsulates to derive shared secret
TEST_F(PqcFilterTest, ClientSendsCiphertextAndServerDecapsulates) {
  // ARRANGE: Simulate full key exchange flow

  // Step 1: Client gets server's public key (from Test 20 flow)
  const uint8_t* server_public_key = filter_->getKyberPublicKey();
  size_t pk_len = filter_->getKyberPublicKeySize();

  // Step 2: Client performs encapsulation
  std::vector<uint8_t> ciphertext(1088);  // Kyber768 ciphertext size
  std::vector<uint8_t> client_shared_secret(32);

  bool encap_success = filter_->clientEncapsulate(
      server_public_key,
      pk_len,
      ciphertext.data(),
      client_shared_secret.data()
  );
  ASSERT_TRUE(encap_success);

  // Step 3: Client base64-encodes ciphertext for HTTP header transmission
  std::string encoded_ciphertext = Base64Utils::encode(ciphertext.data(), ciphertext.size());

  // Step 4: Client sends ciphertext in X-PQC-Ciphertext header
  RequestHeaderMap request_headers;
  request_headers.addCopy(LowerCaseString("x-pqc-ciphertext"), encoded_ciphertext);

  // ACT: Filter processes request with ciphertext
  FilterHeadersStatus status = filter_->decodeHeaders(request_headers, false);

  // ASSERT: Filter should continue processing
  ASSERT_EQ(status, FilterHeadersStatus::Continue);

  // ASSERT: Server should have decapsulated and stored the shared secret
  // We verify this by calling getSharedSecret() method
  const uint8_t* server_shared_secret = filter_->getSharedSecret();
  ASSERT_NE(server_shared_secret, nullptr) << "Server should have stored shared secret after decapsulation";

  // ASSERT: Server's shared secret should match client's shared secret
  size_t secret_len = filter_->getSharedSecretSize();
  ASSERT_EQ(secret_len, 32) << "Shared secret should be 32 bytes for Kyber768";

  // Verify byte-by-byte match
  for (size_t i = 0; i < 32; i++) {
    ASSERT_EQ(server_shared_secret[i], client_shared_secret[i])
        << "Shared secret mismatch at byte " << i;
  }
}

// ============================================================================
// AES-256-GCM ENCRYPTION TESTS (Quantum-Resistant Data Protection)
// ============================================================================

// Test 22: Encrypt plaintext with AES-256-GCM, decrypt on server, verify match
TEST_F(PqcFilterTest, EncryptAndDecryptWithAES256GCM) {
  // ARRANGE: Establish shared secret first (from Test 21)
  const uint8_t* server_public_key = filter_->getKyberPublicKey();
  size_t pk_len = filter_->getKyberPublicKeySize();

  std::vector<uint8_t> ciphertext(1088);
  std::vector<uint8_t> client_shared_secret(32);

  bool encap_success = filter_->clientEncapsulate(
      server_public_key,
      pk_len,
      ciphertext.data(),
      client_shared_secret.data()
  );
  ASSERT_TRUE(encap_success);

  // Server receives and decapsulates
  std::string encoded_ciphertext = Base64Utils::encode(ciphertext.data(), ciphertext.size());
  RequestHeaderMap request_headers;
  request_headers.addCopy(LowerCaseString("x-pqc-ciphertext"), encoded_ciphertext);
  filter_->decodeHeaders(request_headers, false);

  // Verify shared secret established
  const uint8_t* server_shared_secret = filter_->getSharedSecret();
  ASSERT_NE(server_shared_secret, nullptr);

  // ARRANGE: Plaintext message to encrypt
  std::string plaintext = "This is a secret message protected by post-quantum cryptography!";
  std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());

  // ACT: Client encrypts the message using AES-256-GCM
  std::vector<uint8_t> encrypted_data;
  std::vector<uint8_t> iv(12);  // 12-byte IV for GCM mode
  std::vector<uint8_t> auth_tag(16);  // 16-byte authentication tag

  bool encrypt_success = filter_->encryptAES256GCM(
      plaintext_bytes.data(),
      plaintext_bytes.size(),
      client_shared_secret.data(),
      iv.data(),
      encrypted_data,
      auth_tag.data()
  );
  ASSERT_TRUE(encrypt_success) << "Encryption should succeed";
  ASSERT_EQ(encrypted_data.size(), plaintext_bytes.size()) << "Ciphertext size should match plaintext size";

  // ACT: Server decrypts using the same shared secret
  std::vector<uint8_t> decrypted_data;
  bool decrypt_success = filter_->decryptAES256GCM(
      encrypted_data.data(),
      encrypted_data.size(),
      server_shared_secret,
      iv.data(),
      auth_tag.data(),
      decrypted_data
  );
  ASSERT_TRUE(decrypt_success) << "Decryption should succeed";

  // ASSERT: Decrypted data matches original plaintext
  ASSERT_EQ(decrypted_data.size(), plaintext_bytes.size())
      << "Decrypted size should match original plaintext size";

  for (size_t i = 0; i < plaintext_bytes.size(); i++) {
    ASSERT_EQ(decrypted_data[i], plaintext_bytes[i])
        << "Decrypted data mismatch at byte " << i;
  }

  // ASSERT: Verify authentication tag prevents tampering
  std::vector<uint8_t> tampered_data = encrypted_data;
  tampered_data[0] ^= 0x01;  // Flip one bit

  std::vector<uint8_t> tampered_decrypt;
  bool tampered_decrypt_success = filter_->decryptAES256GCM(
      tampered_data.data(),
      tampered_data.size(),
      server_shared_secret,
      iv.data(),
      auth_tag.data(),
      tampered_decrypt
  );
  ASSERT_FALSE(tampered_decrypt_success)
      << "Decryption should fail for tampered data (authentication tag mismatch)";
}

// Test 23: Verify secure random IV generation for AES-256-GCM
TEST_F(PqcFilterTest, SecureRandomIVGeneration) {
  // ARRANGE: Establish shared secret first (from Test 21)
  const uint8_t* server_public_key = filter_->getKyberPublicKey();
  size_t pk_len = filter_->getKyberPublicKeySize();

  std::vector<uint8_t> ciphertext(1088);
  std::vector<uint8_t> client_shared_secret(32);

  bool encap_success = filter_->clientEncapsulate(
      server_public_key, pk_len, ciphertext.data(), client_shared_secret.data());
  ASSERT_TRUE(encap_success);

  // Server receives and decapsulates
  std::string encoded_ciphertext = Base64Utils::encode(ciphertext.data(), ciphertext.size());
  RequestHeaderMap request_headers;
  request_headers.addCopy(LowerCaseString("x-pqc-ciphertext"), encoded_ciphertext);
  filter_->decodeHeaders(request_headers, false);

  const uint8_t* server_shared_secret = filter_->getSharedSecret();
  ASSERT_NE(server_shared_secret, nullptr);

  // ARRANGE: Use the same plaintext for multiple encryptions
  std::string plaintext = "Test message for IV uniqueness verification";
  std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());

  // ACT: Perform multiple encryptions with the same plaintext and key
  const int num_encryptions = 10;
  std::vector<std::vector<uint8_t>> ivs(num_encryptions, std::vector<uint8_t>(12));
  std::vector<std::vector<uint8_t>> ciphertexts(num_encryptions);
  std::vector<std::vector<uint8_t>> auth_tags(num_encryptions, std::vector<uint8_t>(16));

  for (int i = 0; i < num_encryptions; i++) {
    bool encrypt_success = filter_->encryptAES256GCM(
        plaintext_bytes.data(), plaintext_bytes.size(),
        client_shared_secret.data(), ivs[i].data(), ciphertexts[i], auth_tags[i].data());
    ASSERT_TRUE(encrypt_success) << "Encryption " << i << " should succeed";
  }

  // ASSERT: Verify all IVs are unique (probability of collision with secure random is negligible)
  for (int i = 0; i < num_encryptions; i++) {
    for (int j = i + 1; j < num_encryptions; j++) {
      bool ivs_are_different = false;
      for (int k = 0; k < 12; k++) {
        if (ivs[i][k] != ivs[j][k]) {
          ivs_are_different = true;
          break;
        }
      }
      ASSERT_TRUE(ivs_are_different)
          << "IV " << i << " and IV " << j << " should be different (secure random generation)";
    }
  }

  // ASSERT: Verify different IVs produce different ciphertexts (even with same plaintext/key)
  for (int i = 0; i < num_encryptions; i++) {
    for (int j = i + 1; j < num_encryptions; j++) {
      bool ciphertexts_are_different = false;
      for (size_t k = 0; k < ciphertexts[i].size() && k < ciphertexts[j].size(); k++) {
        if (ciphertexts[i][k] != ciphertexts[j][k]) {
          ciphertexts_are_different = true;
          break;
        }
      }
      ASSERT_TRUE(ciphertexts_are_different)
          << "Ciphertext " << i << " and ciphertext " << j
          << " should be different due to different IVs";
    }
  }

  // ASSERT: Verify each ciphertext can still be decrypted correctly with its corresponding IV
  for (int i = 0; i < num_encryptions; i++) {
    std::vector<uint8_t> decrypted_data;
    bool decrypt_success = filter_->decryptAES256GCM(
        ciphertexts[i].data(), ciphertexts[i].size(),
        server_shared_secret, ivs[i].data(), auth_tags[i].data(), decrypted_data);
    ASSERT_TRUE(decrypt_success) << "Decryption " << i << " should succeed";

    // Verify decrypted data matches original plaintext
    ASSERT_EQ(decrypted_data.size(), plaintext_bytes.size());
    for (size_t k = 0; k < plaintext_bytes.size(); k++) {
      ASSERT_EQ(decrypted_data[k], plaintext_bytes[k])
          << "Decryption " << i << " should match original plaintext at byte " << k;
    }
  }
}
