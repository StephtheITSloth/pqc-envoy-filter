# src/BUILD

load("@rules_cc//cc:defs.bzl", "cc_library")
load("@com_google_protobuf//:protobuf.bzl", "cc_proto_library", "proto_library")

# Define base protobuf library
proto_library(
    name = "pqc_filter_proto",
    srcs = ["proto/pqc_filter.proto"],
    # Visibility allows the cc_proto_library rule to depend on this.
    visibility = ["//visibility:public"],
)

# This step compiles the .proto file and generates C++ headers/source files.
cc_proto_library(
    name = "pqc_filter_cc_proto",
    # The generated C++ code depends on the base proto library.
    deps = [":pqc_filter_proto"],
)

cc_library(
    name = "pqc_filter_config_lib",
    srcs = ["pqc_filter_config.cc"],
    hdrs = ["pqc_filter_config.h"],

    # ADD THIS LINE: Makes the library visible to all other packages
    visibility = ["//visibility:public"],

    deps = [
        # CRITICAL: We depend on the generated C++ ProtoBuf configuration class.
        ":pqc_filter_cc_proto",
        # We need this standard library to access the generated class.
        "@com_google_protobuf//:protobuf",
    ],
)