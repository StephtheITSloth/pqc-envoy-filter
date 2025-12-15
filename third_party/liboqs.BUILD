# BUILD file for liboqs - Post-Quantum Cryptography Library
# Uses rules_foreign_cc to build liboqs via CMake
#
# ALGORITHMS ENABLED:
# - KEMs: Kyber (all variants), ML-KEM, Classic-McEliece
# - Signatures: ML-DSA (Dilithium), SLH-DSA (SPHINCS+), plus MAYO, CROSS, OV, SNOVA
#
# Current library size: ~15MB (includes SLH-DSA variants)
# TODO(optimization): Reduce to ~1.5MB by disabling SLH-DSA and other extras
#                     Set OQS_ENABLE_SIG_SLH_DSA=OFF and disable extra signature schemes

load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")

filegroup(
    name = "all_srcs",
    srcs = glob(
        include = ["**"],
        exclude = ["*.bazel"],
    ),
)

cmake(
    name = "oqs",
    cache_entries = {
        # Enable only NIST-standardized algorithms (Kyber + Dilithium)
        # This keeps binary size reasonable (~1.5MB instead of ~5MB)

        # Key Encapsulation Mechanisms (KEM)
        "OQS_ENABLE_KEM_KYBER": "ON",           # ML-KEM (NIST standard)

        # Digital Signatures
        "OQS_ENABLE_SIG_DILITHIUM": "ON",       # ML-DSA (NIST standard)

        # Disable everything else for now (can enable later)
        "OQS_ENABLE_KEM_BIKE": "OFF",
        "OQS_ENABLE_KEM_FRODOKEM": "OFF",
        "OQS_ENABLE_KEM_HQC": "OFF",
        "OQS_ENABLE_KEM_NTRU": "OFF",
        "OQS_ENABLE_KEM_NTRUPRIME": "OFF",
        "OQS_ENABLE_KEM_SABER": "OFF",
        "OQS_ENABLE_SIG_FALCON": "OFF",
        "OQS_ENABLE_SIG_SPHINCS": "OFF",        # Can enable later if needed

        # Build configuration
        "BUILD_SHARED_LIBS": "OFF",             # Static linking
        "OQS_BUILD_ONLY_LIB": "ON",            # Don't build tests/examples
        "OQS_USE_OPENSSL": "OFF",              # Standalone crypto

        # Optimization flags
        "CMAKE_BUILD_TYPE": "Release",
        "OQS_OPT_TARGET": "generic",           # Portable build
    },
    lib_source = ":all_srcs",
    out_static_libs = ["liboqs.a"],
    out_include_dir = "include",  # CMake installs headers to include/oqs/
    visibility = ["//visibility:public"],
)
