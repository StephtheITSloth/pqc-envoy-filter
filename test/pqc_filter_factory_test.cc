#include "gtest/gtest.h"
#include "src/pqc_filter_factory.h"
#include "src/proto/pqc_filter.pb.h"

// For parsing YAML config
#include "test/mocks/server/factory_context.h"

using namespace Envoy::Extensions::HttpFilters::PqcFilter;

class PqcFilterFactoryTest : public testing::Test {
protected:
  PqcFilterFactory factory_;
  Envoy::Server::Configuration::MockFactoryContext context_;
};

TEST_F(PqcFilterFactoryTest, CanCreateFactory) {
  // Just verify factory can be instantiated
  ASSERT_TRUE(true);
}

TEST_F(PqcFilterFactoryTest, FactoryHasCorrectName) {
  ASSERT_EQ(factory_.name(), "envoy.filters.http.pqc_filter");
}

TEST_F(PqcFilterFactoryTest, CanCreateFilterFromProto) {
  // Create a proto config
  envoy::extensions::filters::http::pqc_filter::v3::PqcFilter proto_config;
  proto_config.set_algorithm_name("Falcon512");

  // This should not throw
  auto filter_callback = factory_.createFilterFactoryFromProtoTyped(
      proto_config, "stats", context_);

  ASSERT_TRUE(filter_callback != nullptr);
}