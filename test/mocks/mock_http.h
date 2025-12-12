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

// Mock LowerCaseString (for header keys)
class LowerCaseString {
public:
  explicit LowerCaseString(const std::string& str) : value_(str) {}
  const std::string& get() const { return value_; }
  operator const std::string&() const { return value_; }
private:
  std::string value_;
};

// Mock header value wrapper
class HeaderString {
public:
  HeaderString(const std::string& str) : value_(str) {}
  const std::string& getStringView() const { return value_; }
private:
  std::string value_;
};

// Mock header entry
class HeaderEntry {
public:
  HeaderEntry(const std::string& key, const std::string& val)
      : key_(key), value_(val) {}
  const HeaderString& value() const { return value_; }
  const std::string& key() const { return key_; }
private:
  std::string key_;
  HeaderString value_;
};

// Mock HTTP header map (base class for request and response headers)
class HeaderMap {
public:
  void addCopy(const LowerCaseString& key, const std::string& value) {
    headers_[key.get()] = value;
  }

  std::vector<const HeaderEntry*> get(const LowerCaseString& key) const {
    auto it = headers_.find(key.get());
    if (it != headers_.end()) {
      // Create a temporary HeaderEntry and return its pointer
      // Note: This is a simplified mock - in real Envoy this is more complex
      entries_.push_back(std::make_unique<HeaderEntry>(it->first, it->second));
      return {entries_.back().get()};
    }
    return {};
  }

  bool empty() const { return headers_.empty(); }

protected:
  std::map<std::string, std::string> headers_;
  mutable std::vector<std::unique_ptr<HeaderEntry>> entries_;
};

// Mock HTTP request header map
class RequestHeaderMap : public HeaderMap {
};

// Mock HTTP response header map
class ResponseHeaderMap : public HeaderMap {
};

// Mock HTTP trailer maps
class RequestTrailerMap {
  // Minimal implementation - we don't use trailers yet
};

class ResponseTrailerMap {
  // Minimal implementation - we don't use trailers yet
};

// Mock filter callbacks
class StreamDecoderFilterCallbacks {
  // Minimal implementation - we don't use callbacks in current tests
};

class StreamEncoderFilterCallbacks {
  // Minimal implementation - we don't use callbacks in current tests
};

// Mock StreamDecoderFilter interface (for request processing)
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

// Mock StreamEncoderFilter interface (for response processing)
class StreamEncoderFilter {
public:
  virtual ~StreamEncoderFilter() = default;

  virtual FilterHeadersStatus encodeHeaders(ResponseHeaderMap& headers,
                                           bool end_stream) = 0;
  virtual FilterDataStatus encodeData(Buffer::Instance& data,
                                     bool end_stream) = 0;
  virtual FilterTrailersStatus encodeTrailers(ResponseTrailerMap& trailers) = 0;
  virtual void setEncoderFilterCallbacks(StreamEncoderFilterCallbacks& callbacks) = 0;
};

// Mock StreamFilter interface (bidirectional - processes both requests and responses)
class StreamFilter : public StreamDecoderFilter, public StreamEncoderFilter {
public:
  virtual ~StreamFilter() = default;
};

} // namespace Http
} // namespace Envoy
