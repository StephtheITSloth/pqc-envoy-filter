#pragma once

#include <map>
#include <string>

// Mock implementation of Envoy's HTTP interfaces for unit testing

namespace Envoy {

// Forward declarations
namespace Buffer {
  class Instance;
}

namespace Http {

// Filter return statuses (these need to match Envoy's enum values)
// IMPORTANT: These must be declared BEFORE StreamDecoderFilter uses them
enum class FilterHeadersStatus {
  Continue = 0,
  StopIteration = 1,
};

enum class FilterDataStatus {
  Continue = 0,
  StopIterationAndBuffer = 1,
  StopIterationNoBuffer = 2,
};

enum class FilterTrailersStatus {
  Continue = 0,
  StopIteration = 1,
};

// Mock HTTP header map
class RequestHeaderMap {
public:
  void addCopy(const std::string& key, const std::string& value) {
    headers_[key] = value;
  }

  const std::string& get(const std::string& key) const {
    static const std::string empty;
    auto it = headers_.find(key);
    return (it != headers_.end()) ? it->second : empty;
  }

private:
  std::map<std::string, std::string> headers_;
};

// Mock HTTP trailer map
class RequestTrailerMap {
  // Minimal implementation - we don't use trailers yet
};

// Mock filter callbacks
class StreamDecoderFilterCallbacks {
  // Minimal implementation - we don't use callbacks in current tests
};

// Mock StreamDecoderFilter interface (base class for our filter)
class StreamDecoderFilter {
public:
  virtual ~StreamDecoderFilter() = default;

  virtual FilterHeadersStatus decodeHeaders(RequestHeaderMap& headers,
                                           bool end_stream) = 0;
  virtual FilterDataStatus decodeData(Buffer::Instance& data,
                                     bool end_stream) = 0;
  virtual FilterTrailersStatus decodeTrailers(RequestTrailerMap& trailers) = 0;
  virtual void setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) = 0;
};

} // namespace Http
} // namespace Envoy
