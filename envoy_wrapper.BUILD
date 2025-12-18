# Minimal wrapper for Envoy to expose only what we need for header-only builds

cc_library(
    name = "headers",
    hdrs = glob([
        "envoy/**/*.h",
        "source/**/*.h",
    ]),
    includes = ["."],
    visibility = ["//visibility:public"],
)
