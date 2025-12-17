
load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
    name = "pqc_filter_config_test",
    srcs = ["pqc_filter_config_test.cc"],
    deps = [
        "//src:pqc_filter_config_lib",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "pqc_filter_factory_test",
    srcs = ["pqc_filter_factory_test.cc"],
    deps = [
        "//src:pqc_filter_factory_lib",  # Updated to use factory
        "//src:pqc_filter_config_lib",
        "@googletest//:gtest",
        "@googletest//:gtest_main",

        # Add Envoy test utilities
        "@envoy//test/mocks/server:factory_context_mocks",
    ],
)

cc_test(
    name = "pqc_filter_test",
    srcs = [
        "pqc_filter_test.cc",
        "pqc_filter_testable.h",  # Testable version with mocks
        "//src:pqc_crypto_utils.h",  # Secure memory utilities header
    ],
    linkopts = [
        "-lcrypto",  # OpenSSL libcrypto for AES-256-GCM
        "-lssl",     # OpenSSL libssl
    ],
    deps = [
        "//src:pqc_filter_lib",  # Main filter implementation with error handling
        "//src:pqc_filter_config_lib",
        "//src:base64_utils_lib",  # Base64 encoding for HTTP headers
        "//test/mocks:mock_envoy_interfaces",
        "@liboqs//:oqs",  # Post-Quantum Cryptography library
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "base64_utils_test",
    srcs = ["base64_utils_test.cc"],
    deps = [
        "//src:base64_utils_lib",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "liboqs_integration_test",
    srcs = ["liboqs_integration_test.cc"],
    deps = [
        "@liboqs//:oqs",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_binary(
    name = "check_algorithms",
    srcs = ["check_algorithms.cc"],
    linkopts = ["-lpthread"],
    deps = [
        "@liboqs//:oqs",
    ],
)