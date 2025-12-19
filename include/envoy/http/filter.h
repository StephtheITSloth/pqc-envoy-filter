// STUB: Minimal Envoy HTTP filter interface for compilation
// This allows existing C++ code to compile without full Envoy headers
// The actual filter uses C ABI wrapper at runtime

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <cstring>

namespace Envoy {

namespace Buffer {
class Instance {
public:
  virtual ~Instance() = default;
  virtual uint64_t length() const = 0;
  virtual void drain(uint64_t size) = 0;
  virtual const uint8_t* linearize(uint32_t size) = 0;
};
} // namespace Buffer

namespace Http {

// Forward declarations
class RequestHeaderMap;
class ResponseHeaderMap;
class RequestTrailerMap;
class ResponseTrailerMap;

// Filter status enums
enum class FilterHeadersStatus {
  Continue,
  StopIteration,
  StopAllIterationAndBuffer,
  StopAllIterationAndWatermark
};

enum class FilterDataStatus {
  Continue,
  StopIterationAndBuffer,
  StopIterationAndWatermark,
  StopIterationNoBuffer
};

enum class FilterTrailersStatus {
  Continue,
  StopIteration
};

// Stub filter callbacks
class StreamDecoderFilterCallbacks {
public:
  virtual ~StreamDecoderFilterCallbacks() = default;
};

class StreamEncoderFilterCallbacks {
public:
  virtual ~StreamEncoderFilterCallbacks() = default;
};

// Stub filter interfaces
class StreamDecoderFilter {
public:
  virtual ~StreamDecoderFilter() = default;
  virtual FilterHeadersStatus decodeHeaders(RequestHeaderMap& headers, bool end_stream) = 0;
  virtual FilterDataStatus decodeData(Buffer::Instance& data, bool end_stream) = 0;
  virtual FilterTrailersStatus decodeTrailers(RequestTrailerMap& trailers) = 0;
  virtual void setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) = 0;
};

class StreamEncoderFilter {
public:
  virtual ~StreamEncoderFilter() = default;
  virtual FilterHeadersStatus encodeHeaders(ResponseHeaderMap& headers, bool end_stream) = 0;
  virtual FilterDataStatus encodeData(Buffer::Instance& data, bool end_stream) = 0;
  virtual FilterTrailersStatus encodeTrailers(ResponseTrailerMap& trailers) = 0;
  virtual void setEncoderFilterCallbacks(StreamEncoderFilterCallbacks& callbacks) = 0;
};

class StreamFilter : public StreamDecoderFilter, public StreamEncoderFilter {
public:
  virtual ~StreamFilter() = default;
};

// Stub header map interfaces
class LowerCaseString {
public:
  explicit LowerCaseString(const std::string& str) : str_(str) {}
  const std::string& get() const { return str_; }
private:
  std::string str_;
};

// StringView for header values
class StringView {
public:
  StringView() : data_(nullptr), size_(0) {}
  StringView(const char* data, size_t size) : data_(data), size_(size) {}
  StringView(const std::string& str) : data_(str.data()), size_(str.size()) {}
  const char* data() const { return data_; }
  size_t size() const { return size_; }
  std::string toString() const { return std::string(data_, size_); }
  operator std::string() const { return toString(); }
  bool operator==(const char* rhs) const {
    return size_ == strlen(rhs) && memcmp(data_, rhs, size_) == 0;
  }
  bool operator==(const std::string& rhs) const {
    return size_ == rhs.size() && memcmp(data_, rhs.data(), size_) == 0;
  }
private:
  const char* data_;
  size_t size_;
};

class HeaderEntry {
public:
  virtual ~HeaderEntry() = default;

  // HeaderString wraps a StringView and provides getStringView()
  class HeaderString {
  public:
    HeaderString() = default;
    HeaderString(const std::string& str) : str_(str) {}
    StringView getStringView() const { return StringView(str_); }
  private:
    std::string str_;
  };

  virtual const HeaderString& value() const = 0;
  virtual const HeaderString& key() const = 0;
};

class HeaderMap {
public:
  virtual ~HeaderMap() = default;
  virtual std::vector<const HeaderEntry*> get(const LowerCaseString& key) const = 0;
  virtual void addCopy(const LowerCaseString& key, const std::string& value) = 0;
  virtual void remove(const LowerCaseString& key) = 0;
};

class RequestHeaderMap : public HeaderMap {};
class ResponseHeaderMap : public HeaderMap {};
class RequestTrailerMap : public HeaderMap {};
class ResponseTrailerMap : public HeaderMap {};

} // namespace Http

// Stub logger
namespace Logger {
enum class Id {
  filter
};

template<Id id>
class Loggable {
protected:
  // Stub logging - does nothing in compilation
  // At runtime, C ABI wrapper will use Envoy's logging
};

} // namespace Logger

} // namespace Envoy

// Stub logging macros
#define ENVOY_LOG(level, ...) do {} while(0)
