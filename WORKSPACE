# WORKSPACE file
workspace(name = "pqc_envoy_filter")

# Fetch Google Test dependencies
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
http_archive(
    name = "googletest",
    strip_prefix = "googletest-release-1.11.0",
    urls = ["https://github.com/google/googletest/archive/release-1.11.0.zip"],
    sha256 = "c04481308a983b632906b38c292150a00d433f5241400e2380d38eb570be9687",
)