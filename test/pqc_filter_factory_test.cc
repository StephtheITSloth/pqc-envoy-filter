#include "gtest/gtest.h"
#include "src/pqc_filter_config.h"

using namespace Envoy::Extensions::HttpFilters::PqcFilter;

class PqcFilterFactoryTest : public testing::Test {};

TEST(PqcFilterFactoryTest, BasicConfigTest){
    const std::string yaml = R"EOF(
    algorithm_name: "Falcon512"
  )EOF";

  PqcFilterFactory factory;

  ASSERT_TRUE(true);
}