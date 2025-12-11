#pragma once

// Testable version of PqcFilter that uses mock Envoy interfaces
// This file includes the mock headers BEFORE including the real filter

#include "test/mocks/mock_buffer.h"
#include "test/mocks/mock_http.h"
#include "test/mocks/mock_logger.h"

// Now include the actual filter implementation
// It will use our mocked types above
#include "src/pqc_filter_config.h"

// Post-Quantum Cryptography includes
#include <oqs/oqs.h>
#include "src/pqc_crypto_utils.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

/**
 * Testable version of PqcFilter
 * Uses mock Envoy interfaces for unit testing
 */
class PqcFilter : public Http::StreamDecoderFilter,
                  public Logger::Loggable<Logger::Id::filter> {
public:
  explicit PqcFilter(std::shared_ptr<PqcFilterConfig> config) : config_(config) {
    initializeKyber();
    initializeDilithium();
  }

  // Http::StreamDecoderFilter interface
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) {
    ENVOY_LOG(info, "PQC Filter using algorithm: {}",
              config_->getAlgorithmName());
    return Http::FilterHeadersStatus::Continue;
  }

  Http::FilterDataStatus decodeData(Buffer::Instance& data,
                                    bool end_stream) {
    // Production-ready implementation using getRawSlices()
    uint64_t buffer_length = data.length();

    if (buffer_length == 0) {
      ENVOY_LOG(debug, "Received empty buffer");
      return Http::FilterDataStatus::Continue;
    }

    // Get raw slices for inspection
    std::vector<Buffer::RawSlice> slices = data.getRawSlices();

    // SECURITY: Check for TLS Record Type 22 (Handshake = 0x16)
    // This is critical for PQC key exchange detection
    // IMPORTANT: Always check buffer size BEFORE accessing bytes
    if (!slices.empty() && slices[0].len_ > 0) {
      const uint8_t* first_byte_ptr = static_cast<const uint8_t*>(slices[0].mem_);
      if (first_byte_ptr[0] == 0x16) {
        ENVOY_LOG(info, "Detected TLS Handshake (Record Type 22)");
      }
    }

    uint64_t bytes_to_log = std::min(buffer_length, static_cast<uint64_t>(10));

    // Build hex string from slices (already retrieved above)
    std::string hex_string;
    hex_string.reserve(bytes_to_log * 3);

    uint64_t bytes_logged = 0;

    for (const auto& slice : slices) {
      if (bytes_logged >= bytes_to_log) {
        break;
      }

      const uint8_t* slice_data = static_cast<const uint8_t*>(slice.mem_);
      size_t slice_len = slice.len_;

      uint64_t bytes_from_slice = std::min(
          static_cast<uint64_t>(slice_len),
          bytes_to_log - bytes_logged
      );

      for (uint64_t i = 0; i < bytes_from_slice; i++) {
        char hex_buf[4];
        snprintf(hex_buf, sizeof(hex_buf), "%02X ", slice_data[i]);
        hex_string += hex_buf;
      }

      bytes_logged += bytes_from_slice;
    }

    // Remove trailing space
    if (!hex_string.empty()) {
      hex_string.pop_back();
    }

    ENVOY_LOG(info, "First {} bytes (hex): {}", bytes_logged, hex_string);

    return Http::FilterDataStatus::Continue;
  }

  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap& trailers) {
    return Http::FilterTrailersStatus::Continue;
  }

  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
    decoder_callbacks_ = &callbacks;
  }

  // Public key access methods (for key exchange operations)
  // NOTE: Private keys are intentionally NOT exposed for security reasons

  // Kyber KEM public key access
  const uint8_t* getKyberPublicKey() const { return kyber_public_key_.get(); }
  size_t getKyberPublicKeySize() const {
    return kyber_kem_ ? kyber_kem_->length_public_key : 0;
  }

  // Dilithium signature public key access
  const uint8_t* getDilithiumPublicKey() const { return dilithium_public_key_.get(); }
  size_t getDilithiumPublicKeySize() const {
    return dilithium_sig_ ? dilithium_sig_->length_public_key : 0;
  }

  // Status check methods
  bool hasKyberInitialized() const { return kyber_kem_ != nullptr; }
  bool hasDilithiumInitialized() const { return dilithium_sig_ != nullptr; }

  // KEM operations for key exchange

  /**
   * Simulate client-side KEM encapsulation.
   *
   * This method performs the client's role in the key exchange:
   * 1. Takes the server's public key
   * 2. Generates a random shared secret
   * 3. Encapsulates the secret using the public key, producing ciphertext
   *
   * @param server_public_key The server's public key (from getKyberPublicKey())
   * @param server_public_key_len Length of the public key
   * @param out_ciphertext Output buffer for ciphertext (must be pre-allocated)
   * @param out_shared_secret Output buffer for shared secret (must be pre-allocated)
   * @return true if encapsulation succeeded, false otherwise
   */
  bool clientEncapsulate(const uint8_t* server_public_key,
                         size_t server_public_key_len,
                         uint8_t* out_ciphertext,
                         uint8_t* out_shared_secret) const {
    // Validate inputs
    if (!kyber_kem_) {
      ENVOY_LOG(error, "KEM not initialized - cannot perform encapsulation");
      return false;
    }

    if (!server_public_key || !out_ciphertext || !out_shared_secret) {
      ENVOY_LOG(error, "Invalid parameters for encapsulation - null pointer");
      return false;
    }

    if (server_public_key_len != kyber_kem_->length_public_key) {
      ENVOY_LOG(error, "Invalid public key length: expected {}, got {}",
                kyber_kem_->length_public_key, server_public_key_len);
      return false;
    }

    // Perform KEM encapsulation (client-side operation)
    OQS_STATUS status = OQS_KEM_encaps(
        kyber_kem_.get(),
        out_ciphertext,      // Output: ciphertext to send to server
        out_shared_secret,   // Output: shared secret (client's copy)
        server_public_key    // Input: server's public key
    );

    if (status != OQS_SUCCESS) {
      ENVOY_LOG(error, "KEM encapsulation failed - status: {}", status);
      return false;
    }

    ENVOY_LOG(debug, "Client encapsulation successful - ciphertext_size: {} bytes, shared_secret_size: {} bytes",
              kyber_kem_->length_ciphertext, kyber_kem_->length_shared_secret);

    return true;
  }

private:
  std::shared_ptr<PqcFilterConfig> config_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_{nullptr};

  // Post-Quantum Cryptography - Kyber-768
  std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kyber_kem_{nullptr, OQS_KEM_free};
  SecureBuffer kyber_public_key_;
  SecureBuffer kyber_secret_key_;

  // Dilithium3 (ML-DSA-65) signature
  std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)> dilithium_sig_{nullptr, OQS_SIG_free};
  SecureBuffer dilithium_public_key_;
  SecureBuffer dilithium_secret_key_;

  // Initialization functions
  void initializeKyber() {
    // Simple stub for now - full implementation will be in pqc_filter.cc
    kyber_kem_ = std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)>(
        OQS_KEM_new("Kyber768"), OQS_KEM_free);

    if (!kyber_kem_) {
      ENVOY_LOG(error, "Failed to create Kyber-768 KEM instance");
      return;
    }

    kyber_public_key_ = make_secure_buffer(kyber_kem_->length_public_key);
    kyber_secret_key_ = make_secure_buffer(kyber_kem_->length_secret_key);

    OQS_STATUS status = OQS_KEM_keypair(
        kyber_kem_.get(),
        kyber_public_key_.get(),
        kyber_secret_key_.get()
    );

    if (status != OQS_SUCCESS) {
      ENVOY_LOG(error, "Failed to generate Kyber-768 keypair");
      return;
    }

    ENVOY_LOG(info, "Kyber-768 initialized successfully");
  }

  void initializeDilithium() {
    // Create Dilithium3 (ML-DSA-65) signature instance
    dilithium_sig_ = std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)>(
        OQS_SIG_new("ML-DSA-65"), OQS_SIG_free);

    if (!dilithium_sig_) {
      ENVOY_LOG(error, "Failed to create ML-DSA-65 (Dilithium3) signature instance");
      return;
    }

    dilithium_public_key_ = make_secure_buffer(dilithium_sig_->length_public_key);
    dilithium_secret_key_ = make_secure_buffer(dilithium_sig_->length_secret_key);

    OQS_STATUS status = OQS_SIG_keypair(
        dilithium_sig_.get(),
        dilithium_public_key_.get(),
        dilithium_secret_key_.get()
    );

    if (status != OQS_SUCCESS) {
      ENVOY_LOG(error, "Failed to generate ML-DSA-65 (Dilithium3) keypair");
      return;
    }

    ENVOY_LOG(info, "ML-DSA-65 (Dilithium3) initialized successfully");
  }
};

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
