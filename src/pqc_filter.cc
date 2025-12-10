#include "src/pqc_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

PqcFilter::PqcFilter(std::shared_ptr<PqcFilterConfig> config) 
    : config_(config) {}

Http::FilterHeadersStatus PqcFilter::decodeHeaders(
    Http::RequestHeaderMap& headers, bool end_stream) {
  
  // Log which algorithm we're using (for now, just logging)
  ENVOY_LOG(info, "PQC Filter using algorithm: {}", 
            config_->getAlgorithmName());
  
  // For now, just pass through
  // Later: Add PQC key exchange logic here
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus PqcFilter::decodeData(
    Buffer::Instance& data, bool end_stream) {

  // Get buffer length
  uint64_t buffer_length = data.length();

  // Handle empty buffer
  if (buffer_length == 0) {
    ENVOY_LOG(debug, "Received empty buffer");
    return Http::FilterDataStatus::Continue;
  }

  // Calculate how many bytes to log (min of 10 or buffer length)
  uint64_t bytes_to_log = std::min(buffer_length, static_cast<uint64_t>(10));

  // Get raw slices (zero-copy access to buffer memory)
  // Production-ready: handles fragmented buffers efficiently
  Buffer::RawSliceVector slices = data.getRawSlices();

  if (!slices.empty()) {
    if(slices[0].len_ > 0) {
      const uint8_t* first_byte_ptr = static_cast<const uint8_t*>(slices[0].mem_);

      if (first_byte_ptr[0] == 0x16) {
        ENVOY_LOG(info, "Detected TLS Handshake (Record Type 22)");
      }
    }
  }

  // Build hex string by iterating through slices
  std::string hex_string;
  hex_string.reserve(bytes_to_log * 3);  // Pre-allocate: "XX " per byte

  uint64_t bytes_logged = 0;

  for (const auto& slice : slices) {
    if (bytes_logged >= bytes_to_log) {
      break;  // We've logged enough
    }

    // Access slice data
    const uint8_t* slice_data = static_cast<const uint8_t*>(slice.mem_);
    size_t slice_len = slice.len_;

    // Calculate how many bytes to read from this slice
    uint64_t bytes_from_slice = std::min(
        static_cast<uint64_t>(slice_len),
        bytes_to_log - bytes_logged
    );

    // Convert bytes to hex
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

  // Log the hex string
  ENVOY_LOG(info, "First {} bytes (hex): {}", bytes_logged, hex_string);

  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus PqcFilter::decodeTrailers(
    Http::RequestTrailerMap& trailers) {
  return Http::FilterTrailersStatus::Continue;
}

void PqcFilter::setDecoderFilterCallbacks(
    Http::StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy