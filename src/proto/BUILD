load("@com_google_protobuf//:protobuf.bzl", "cc_proto_library")

# Production-grade proto compilation with validation
# Note: validate/validate.proto is imported in the .proto file
# The protoc compiler will find it via --proto_path
cc_proto_library(
    name = "pkg_cc_proto",
    srcs = ["pqc_filter.proto"],
    visibility = ["//visibility:public"],
    protoc = "@com_google_protobuf//:protoc",
    default_runtime = "@com_google_protobuf//:protobuf",
    include = ".",
)
