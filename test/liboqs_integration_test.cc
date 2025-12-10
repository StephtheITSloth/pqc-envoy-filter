#include <gtest/gtest.h>
#include <oqs/oqs.h>
#include <memory>
#include <cstring>

// Secure deleter for cryptographic key material
// Zeros memory before deletion to prevent key material from lingering
template <typename T>
struct SecureDeleter {
  size_t size;
  explicit SecureDeleter(size_t s = 0) : size(s) {}

  void operator()(T* ptr) const {
    if (ptr && size > 0) {
      // Securely zero the memory before freeing
      // volatile prevents compiler from optimizing away the memset
      volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);
      for (size_t i = 0; i < size; ++i) {
        p[i] = 0;
      }
    }
    delete[] ptr;
  }
};

// Helper type aliases for secure smart pointers
using SecureBuffer = std::unique_ptr<uint8_t[], SecureDeleter<uint8_t>>;

// Helper to create a secure buffer
SecureBuffer make_secure_buffer(size_t size) {
  return SecureBuffer(new uint8_t[size], SecureDeleter<uint8_t>(size));
}

// Basic integration test to verify liboqs linkage and Kyber functionality
// This test confirms:
// 1. liboqs library links correctly with our build system
// 2. Kyber-768 (NIST Level 3 KEM) is available and functional
// 3. Basic key generation, encapsulation, and decapsulation work

TEST(LiboqsIntegrationTest, KyberIsAvailable) {
  // Check if Kyber-768 is enabled in the build
  ASSERT_TRUE(OQS_KEM_alg_is_enabled("Kyber768"))
      << "Kyber-768 should be enabled in liboqs build";
}

TEST(LiboqsIntegrationTest, KyberBasicKeyExchange) {
  // Create a new Kyber-768 KEM instance
  // Using unique_ptr with custom deleter for RAII
  std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kem(
      OQS_KEM_new("Kyber768"), OQS_KEM_free);
  ASSERT_NE(kem, nullptr) << "Failed to create Kyber-768 KEM instance";

  // Allocate secure buffers for keys and ciphertext
  // These will automatically zero memory on destruction
  auto public_key = make_secure_buffer(kem->length_public_key);
  auto secret_key = make_secure_buffer(kem->length_secret_key);
  auto ciphertext = make_secure_buffer(kem->length_ciphertext);
  auto shared_secret_encaps = make_secure_buffer(kem->length_shared_secret);
  auto shared_secret_decaps = make_secure_buffer(kem->length_shared_secret);

  // Step 1: Generate a keypair
  OQS_STATUS status = OQS_KEM_keypair(kem.get(), public_key.get(), secret_key.get());
  ASSERT_EQ(status, OQS_SUCCESS) << "Keypair generation failed";

  // Step 2: Encapsulate (create shared secret + ciphertext)
  status = OQS_KEM_encaps(kem.get(), ciphertext.get(), shared_secret_encaps.get(),
                          public_key.get());
  ASSERT_EQ(status, OQS_SUCCESS) << "Encapsulation failed";

  // Step 3: Decapsulate (recover shared secret from ciphertext)
  status = OQS_KEM_decaps(kem.get(), shared_secret_decaps.get(), ciphertext.get(),
                          secret_key.get());
  ASSERT_EQ(status, OQS_SUCCESS) << "Decapsulation failed";

  // Step 4: Verify that both shared secrets match
  ASSERT_EQ(memcmp(shared_secret_encaps.get(), shared_secret_decaps.get(),
                   kem->length_shared_secret), 0)
      << "Shared secrets from encapsulation and decapsulation do not match";

  // No manual cleanup needed! Smart pointers handle it automatically
  // Secret key material is securely zeroed by SecureDeleter
}

TEST(LiboqsIntegrationTest, DilithiumIsAvailable) {
  // Check if ML-DSA-65 (Dilithium3, NIST Level 3 signature) is enabled
  // Note: liboqs 0.15.0 renamed Dilithium3 to ML-DSA-65 per NIST standardization
  ASSERT_TRUE(OQS_SIG_alg_is_enabled("ML-DSA-65"))
      << "ML-DSA-65 (Dilithium3) should be enabled in liboqs build";
}

TEST(LiboqsIntegrationTest, DilithiumBasicSignature) {
  // Create a new ML-DSA-65 (Dilithium3) signature instance with RAII
  std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)> sig(
      OQS_SIG_new("ML-DSA-65"), OQS_SIG_free);
  ASSERT_NE(sig, nullptr) << "Failed to create ML-DSA-65 signature instance";

  // Allocate secure buffers for keys and signature
  auto public_key = make_secure_buffer(sig->length_public_key);
  auto secret_key = make_secure_buffer(sig->length_secret_key);
  auto signature = make_secure_buffer(sig->length_signature);
  size_t signature_len;

  // Test message
  const char *message = "Hello, Post-Quantum World!";
  size_t message_len = strlen(message);

  // Step 1: Generate a keypair
  OQS_STATUS status = OQS_SIG_keypair(sig.get(), public_key.get(), secret_key.get());
  ASSERT_EQ(status, OQS_SUCCESS) << "Signature keypair generation failed";

  // Step 2: Sign the message
  status = OQS_SIG_sign(sig.get(), signature.get(), &signature_len,
                        (const uint8_t *)message, message_len, secret_key.get());
  ASSERT_EQ(status, OQS_SUCCESS) << "Signature generation failed";

  // Step 3: Verify the signature
  status = OQS_SIG_verify(sig.get(), (const uint8_t *)message, message_len,
                          signature.get(), signature_len, public_key.get());
  ASSERT_EQ(status, OQS_SUCCESS) << "Signature verification failed";

  // Step 4: Test that verification fails with wrong message
  const char *wrong_message = "Wrong message";
  status = OQS_SIG_verify(sig.get(), (const uint8_t *)wrong_message,
                          strlen(wrong_message), signature.get(), signature_len,
                          public_key.get());
  ASSERT_NE(status, OQS_SUCCESS)
      << "Signature verification should fail with wrong message";

  // Automatic cleanup with secure memory zeroing
}
