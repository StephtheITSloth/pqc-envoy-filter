load("@rules_cc//cc:defs.bzl", "cc_library")

# Mock Envoy interfaces for unit testing
# Allows testing filter logic without full Envoy dependency

cc_library(
    name = "mock_envoy_interfaces",
    hdrs = [
        "mock_buffer.h",
        "mock_http.h",
        "mock_logger.h",
    ],
    visibility = ["//test:__pkg__"],
)
