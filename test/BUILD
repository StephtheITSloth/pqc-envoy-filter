
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