// File: pqc_filter_config_test.cc

#include "gtest/gtest.h"
#include "src/pqc_filter_config.h" // This header file exists, but the function doesn't!

// ADD THIS LINE: Brings the class name into the test's scope
using namespace Envoy::Extensions::HttpFilters::PqcFilter;

TEST(PqcFilterConfigTest, CanRetrieveAlgorithmName) {
  // ARRANGE
  PqcFilterConfig config; 
  // We can imagine the constructor or a setter initializing this value.
  const std::string expected_name = "Kyber768"; 

  // ACT & ASSERT
  // This line currently fails because getAlgorithmName() doesn't exist.
  ASSERT_EQ(config.getAlgorithmName(), expected_name); 
}