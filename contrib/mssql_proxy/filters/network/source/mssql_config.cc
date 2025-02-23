#include <string>

#include "mssql_filter.h"

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"
#include "source/common/config/utility.h"
#include "envoy/server/transport_socket_config.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MssqlProxy {
/**
 *
 * Config registration for the MssqlProxy filter. @see NamedNetworkFilterConfigFactory.
 */
class MssqlProxyConfigFactory
    : public Envoy::Server::Configuration::NamedNetworkFilterConfigFactory {
public:
  absl::StatusOr<Network::FilterFactoryCb>
  createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                               Server::Configuration::FactoryContext& context) override {
    auto typed_proto_config =
        dynamic_cast<const envoy::extensions::filters::network::mssql_proxy::v3::MSSQLProxy&>(
            proto_config);
    FilterConfigSharedPtr filter_config =
        std::make_shared<FilterConfig>(typed_proto_config, context);

    return [filter_config](Network::FilterManager& filter_manager) -> void {
      filter_manager.addFilter(std::make_shared<Filter>(filter_config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return ProtobufTypes::MessagePtr{
        new envoy::extensions::filters::network::mssql_proxy::v3::MSSQLProxy()};
  }
  std::string name() const override { return "mssql_proxy"; }
};

/**
 * Static registration for the mssql_proxy filter. @see RegisterFactory.
 */
REGISTER_FACTORY(MssqlProxyConfigFactory, Server::Configuration::NamedNetworkFilterConfigFactory);

} // namespace MssqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
