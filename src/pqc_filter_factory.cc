#include "src/pqc_filter_factory.h"
#include "src/pqc_filter.h"
#include "src/pqc_filter_config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

Http::FilterFactoryCb PqcFilterFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::pqc_filter::v3::PqcFilter& proto_config,
    const std::string&,
    Server::Configuration::FactoryContext&) {
  
  // Create config from protobuf
  auto config = std::make_shared<PqcFilterConfig>(proto_config.algorithm_name());
  
  // Return a lambda that creates filter instances
  return [config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamDecoderFilter(
        std::make_shared<PqcFilter>(config));
  };
}

// Register the factory with Envoy
REGISTER_FACTORY(PqcFilterFactory, 
                 Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy

//This is MAGIC - static registration:
//Happens at program startup (before main())
//Registers your factory in Envoy's global registry
//Makes your filter discoverable by name