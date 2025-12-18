# BUILD file for Envoy headers-only compilation
# This provides the minimal Envoy interfaces needed for filter development
# without requiring the full Envoy build system

cc_library(
    name = "envoy_headers",
    hdrs = glob([
        "envoy/**/*.h",
        "source/**/*.h",
    ]),
    includes = ["."],
    visibility = ["//visibility:public"],
)
