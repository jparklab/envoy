#pragma once

#include <string>

#include "envoy/network/filter.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"
#include "source/common/config/utility.h"
#include "envoy/server/transport_socket_config.h"

#include "contrib/envoy/extensions/filters/network/mssql_proxy/v3/mssql_proxy.pb.h"
#include "contrib/envoy/extensions/filters/network/mssql_proxy/v3/mssql_proxy.pb.validate.h"

#include "mssql_codec.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MssqlProxy {

/**
 * Configuration for the MssqlProxy filter.
 */
class FilterConfig {
public:
  FilterConfig(const envoy::extensions::filters::network::mssql_proxy::v3::MSSQLProxy& proto_config,
               Server::Configuration::FactoryContext& context) {
    // TODO: implement
    (void)proto_config;
    (void)context;
  }
};

using FilterConfigSharedPtr = std::shared_ptr<FilterConfig>;

/**
 * Implementation of the MssqlProxy filter
 */
class Filter : public Network::Filter, DecoderCallbacks, Logger::Loggable<Logger::Id::filter> {
public:
  Filter(FilterConfigSharedPtr config) : config_(config) {}
  ~Filter() override = default;

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  Network::FilterStatus onNewConnection() override { return Network::FilterStatus::Continue; }
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override {
    read_callbacks_ = &callbacks;
  }

  // Network::WriteFilter
  Network::FilterStatus onWrite(Buffer::Instance& data, bool end_stream) override;

  void initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) override {
    write_callbacks_ = &callbacks;
  }

private:
  FilterConfigSharedPtr config_;

  Network::ReadFilterCallbacks* read_callbacks_{};
  Network::WriteFilterCallbacks* write_callbacks_{};
};

} // namespace MssqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
