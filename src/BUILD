load("@rules_cc//cc:defs.bzl", "cc_library")

# ============================================================================
# Note: Proto targets are generated in //src/proto:BUILD
# ============================================================================

# Export headers for test visibility
exports_files(["pqc_crypto_utils.h"])

# ============================================================================
# Filter Configuration Library
# ============================================================================

cc_library(
    name = "pqc_filter_config_lib",
    srcs = ["pqc_filter_config.cc"],
    hdrs = ["pqc_filter_config.h"],
    visibility = ["//visibility:public"],
    deps = [
        "//src/proto:pkg_cc_proto",
        "@com_google_protobuf//:protobuf",
    ],
    # Note: Runtime linking against Envoy happens in Docker
    # No compile-time Envoy dependencies needed
)

# ============================================================================
# Filter Factory Library (We'll create this next)
# ============================================================================

cc_library(
    name = "pqc_filter_factory_lib",
    srcs = ["pqc_filter_factory.cc"],
    hdrs = ["pqc_filter_factory.h"],
    visibility = ["//visibility:public"],
    deps = [
        ":pqc_filter_config_lib",
        ":pqc_filter_cc_proto",
        
        # Envoy factory dependencies
        "@envoy//source/extensions/filters/http/common:factory_base_lib",
        "@envoy//include/envoy/server:filter_config_interface",
        "@envoy//include/envoy/http:filter_interface",
    ],
)

# ============================================================================
# The Actual HTTP Filter (We'll create this too)
# ============================================================================

cc_library(
    name = "base64_utils_lib",
    srcs = ["base64_utils.cc"],
    hdrs = ["base64_utils.h"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "pqc_filter_lib",
    srcs = ["pqc_filter.cc"],
    hdrs = [
        "pqc_filter.h",
        "pqc_crypto_utils.h",  # Secure memory utilities
    ],
    linkopts = [
        "-lcrypto",  # OpenSSL libcrypto for AES-256-GCM
        "-lssl",     # OpenSSL libssl
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":pqc_filter_config_lib",
        ":base64_utils_lib",  # Base64 encoding for HTTP headers

        # Post-Quantum Cryptography library
        # TODO(optimization): Current build is ~15MB (includes SLH-DSA/SPHINCS+)
        #                     Target is ~1.5MB (Kyber + Dilithium only)
        #                     Need to use OQS_ENABLE_SIG_SLH_DSA=OFF in liboqs.BUILD
        "@liboqs//:oqs",

        # Envoy filter interfaces
        "@envoy//include/envoy/http:filter_interface",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/common:logger_lib",
    ],
)

# ============================================================================
# Shared Library (.so) for Envoy Dynamic Loading
# ============================================================================
# This builds a .so file that can be loaded by Envoy at runtime
# Usage: bazel build //src:pqc_filter.so

cc_binary(
    name = "pqc_filter.so",
    linkshared = True,
    linkstatic = False,
    visibility = ["//visibility:public"],
    deps = [
        ":pqc_filter_lib",
        ":pqc_filter_factory_lib",
    ],
)