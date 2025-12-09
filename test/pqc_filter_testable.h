#pragma once

// Testable version of PqcFilter that uses mock Envoy interfaces
// This file includes the mock headers BEFORE including the real filter

#include "test/mocks/mock_buffer.h"
#include "test/mocks/mock_http.h"
#include "test/mocks/mock_logger.h"

// Now include the actual filter implementation
// It will use our mocked types above
#include "src/pqc_filter_config.h"

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
  explicit PqcFilter(std::shared_ptr<PqcFilterConfig> config) : config_(config) {}

  // Http::StreamDecoderFilter interface
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) {
    ENVOY_LOG(info, "PQC Filter using algorithm: {}",
              config_->getAlgorithmName());
    return Http::FilterHeadersStatus::Continue;
  }

  Http::FilterDataStatus decodeData(Buffer::Instance& data,
                                    bool end_stream) {
    // TODO: Implement hex logging here
    uint64_t buffer_length =  data.length();

    if (buffer_length == 0){
      ENVOY_LOG(debug, "Received empty buffer");
      return Http::FilterDataStatus::Continue;
    }

    uint64_t bytes_to_log = std::min(buffer_length, static_cast<uint64_t>(10));

    std::string hex_string;
    hex_string.reserve(bytes_to_log * 3);

    std::vector<uint8_t> bytes(bytes_to_log);
    data.copyOut(0, bytes_to_log, bytes.data());

    for (uint64_t i = 0; i < bytes_to_log; i++) {
      char hex_buf[4];
      snprintf(hex_buf, sizeof(hex_buf), "%02X ", bytes[i]);
      hex_string += hex_buf;
    }

    ENVOY_LOG(info, "First {} bytes (hex): {}", bytes_to_log, hex_string);

    return Http::FilterDataStatus::Continue;
  }

  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap& trailers) {
    return Http::FilterTrailersStatus::Continue;
  }

  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
    decoder_callbacks_ = &callbacks;
  }

private:
  std::shared_ptr<PqcFilterConfig> config_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_{nullptr};
};

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
