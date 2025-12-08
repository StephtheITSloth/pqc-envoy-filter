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
  
  // For now, just pass through
  // Later: Decrypt/process data with PQC
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