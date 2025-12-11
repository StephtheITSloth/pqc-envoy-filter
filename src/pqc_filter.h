#pragma once

#include <oqs/oqs.h>

#include "envoy/http/filter.h"
#include "source/common/common/logger.h"
#include "src/pqc_crypto_utils.h"
#include "src/pqc_filter_config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

/**
 * The actual HTTP filter that processes requests.
 * This is where your PQC logic will live.
 */
class PqcFilter : public Http::StreamDecoderFilter,
                  public Logger::Loggable<Logger::Id::filter> {
public:
  explicit PqcFilter(std::shared_ptr<PqcFilterConfig> config);

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance& data,
                                    bool end_stream) override;
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap& trailers) override;
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override;

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

private:
  std::shared_ptr<PqcFilterConfig> config_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_{nullptr};

  // Kyber-768 KEM instance (manages the algorithm)
  std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kyber_kem_;

  // Kyber-768 keys (securely managed)
  SecureBuffer kyber_public_key_;
  SecureBuffer kyber_secret_key_;

  // Dilithium3 (ML-DSA-65) signature instance
  std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)> dilithium_sig_;

  // Dilithium3 keys (securely managed)
  SecureBuffer dilithium_public_key_;
  SecureBuffer dilithium_secret_key_;

  // Initialization functions
  void initializeKyber();
  void initializeDilithium();
};

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy