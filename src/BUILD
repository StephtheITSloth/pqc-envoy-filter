load("@rules_cc//cc:defs.bzl", "cc_library")

# ============================================================================
# Note: Proto targets are generated in //src/proto:BUILD
# ============================================================================

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
    name = "pqc_filter_lib",
    srcs = ["pqc_filter.cc"],
    hdrs = ["pqc_filter.h"],
    visibility = ["//visibility:public"],
    deps = [
        ":pqc_filter_config_lib",

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