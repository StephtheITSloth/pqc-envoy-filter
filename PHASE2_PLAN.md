# Phase 2: Header Bridging Strategy

## The Challenge

Our C++ filter code expects:
```cpp
Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers, bool end_stream);
```

But Envoy C ABI provides:
```c
envoy_dynamic_module_type_on_http_filter_request_headers_status
envoy_dynamic_module_on_http_filter_request_headers(
    envoy_dynamic_module_type_http_filter_module_ptr filter_ptr,
    envoy_dynamic_module_type_http_request_headers_envoy_ptr request_headers,
    bool end_stream);
```

## Solution: Wrapper HeaderMap Class

Create a C++ class that:
1. Implements the `Http::RequestHeaderMap` interface
2. Stores the C ABI `filter_envoy_ptr` and `request_headers` pointers
3. Uses C ABI callbacks to read/write headers

```cpp
class AbiRequestHeaderMapWrapper : public Http::RequestHeaderMap {
private:
  envoy_dynamic_module_type_http_filter_envoy_ptr filter_ptr_;
  envoy_dynamic_module_type_http_request_headers_envoy_ptr headers_ptr_;

public:
  // Implement get() using envoy_dynamic_module_callback_http_get_request_header
  std::vector<const HeaderEntry*> get(const LowerCaseString& key) const override {
    const char* result_ptr;
    size_t result_len;
    bool found = envoy_dynamic_module_callback_http_get_request_header(
        filter_ptr_, key.get().data(), key.get().size(),
        &result_ptr, &result_len, 0, nullptr);

    if (found) {
      // Create HeaderEntry wrapper
      return {new AbiHeaderEntry(key.get(), std::string(result_ptr, result_len))};
    }
    return {};
  }

  // Implement addCopy() using envoy_dynamic_module_callback_http_set_request_header
  void addCopy(const LowerCaseString& key, const std::string& value) override {
    envoy_dynamic_module_callback_http_set_request_header(
        filter_ptr_, key.get().data(), key.get().size(),
        value.data(), value.size());
  }
};
```

## Implementation Steps

1. **Create AbiHeaderEntry** - Wraps a key-value pair
2. **Create AbiRequestHeaderMapWrapper** - Implements RequestHeaderMap via C ABI
3. **Create AbiResponseHeaderMapWrapper** - Implements ResponseHeaderMap via C ABI
4. **Update wrapper functions** - Create these wrappers and pass to C++ filter

## Timeline

- **Simple approach** (Current): ~1 hour
  - Create minimal wrappers
  - Support get() and addCopy() only
  - Enough to test basic PQC key exchange

- **Complete approach**: ~4 hours
  - Full HeaderMap interface implementation
  - All header manipulation methods
  - Production-ready

## Alternative: Pure C Rewrite

Instead of wrapping, rewrite filter logic in pure C:
- Pros: No wrapper overhead, cleaner architecture
- Cons: More code changes, harder to test incrementally
- Estimate: ~2-3 days

## Recommendation

Start with **Simple Wrapper Approach**:
1. Get basic PQC key exchange working
2. Validate the architecture end-to-end
3. Then decide: keep wrappers or migrate to pure C

This lets us test with Envoy v1.36 **today** instead of waiting days for a full rewrite.
