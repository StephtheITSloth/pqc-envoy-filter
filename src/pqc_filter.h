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

private:
  std::shared_ptr<PqcFilterConfig> config_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_{nullptr};
  // Kyber-768 KEM instance (manages the algorithm)
  std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kyber_kem_;

  // Kyber-768 keys (securely managed)
  SecureBuffer kyber_public_key_;
  SecureBuffer kyber_secret_key_;

  // Initialization function
  void initializeKyber();
};

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy