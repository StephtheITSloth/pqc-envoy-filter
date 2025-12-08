#pragma once

#include "envoy/server/filter_config.h"
#include "source/extensions/filters/http/common/factory_base.h"

#include "src/proto/pqc_filter.pb.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

/**
 * Factory for creating PQC filter instances.
 * This is what Envoy calls to create your filter.
 */
class PqcFilterFactory
    : public Common::FactoryBase<
          envoy::extensions::filters::http::pqc_filter::v3::PqcFilter> {
public:
  PqcFilterFactory() : FactoryBase("envoy.filters.http.pqc_filter") {}

private:
  // This method creates the actual filter
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::pqc_filter::v3::PqcFilter& proto_config,
      const std::string& stats_prefix,
      Server::Configuration::FactoryContext& context) override;
};

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy