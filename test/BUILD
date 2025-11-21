load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
    name = "pqc_filter_config_test",
    srcs = ["pqc_filter_config_test.cc"],
    deps = [
        "//src:pqc_filter_config_lib",  # 1. Your PQC library
        "@googletest//:gtest_main",     # 2. Google Test framework (includes gtest)
    ],
)

cc_test(
    name = "pqc_filter_factory_test",
    srcs = ["pqc_filter_factory_test.cc"],
    deps = [
        "//src:pqc_filter_config_lib",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
    ],
)