#pragma once

#include <string>

#include "envoy/network/filter.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"
#include "source/common/config/utility.h"
#include "envoy/server/transport_socket_config.h"

#include "source/common/config/utility.h"

#include "contrib/envoy/extensions/filters/network/mssql_proxy/v3/mssql_proxy.pb.h"
#include "contrib/envoy/extensions/filters/network/mssql_proxy/v3/mssql_proxy.pb.validate.h"

#include "mssql_codec.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MssqlProxy {

/**
 * All MssqlProxy stats. @see stats_macros.h
 */
#define ALL_MSSQL_PROXY_STATS(COUNTER)                                                             \
  COUNTER(errors)                                                                                  \
  COUNTER(sessions)                                                                                \
  COUNTER(statements)                                                                              \
  COUNTER(statements_insert)                                                                       \
  COUNTER(statements_delete)                                                                       \
  COUNTER(statements_update)                                                                       \
  COUNTER(statements_select)                                                                       \
  COUNTER(statements_other)                                                                        \
  COUNTER(transactions)                                                                            \
  COUNTER(transactions_commit)                                                                     \
  COUNTER(transactions_rollback)

struct MssqlProxyStats {
  ALL_MSSQL_PROXY_STATS(GENERATE_COUNTER_STRUCT)
};

/**
 * Configuration for the MssqlProxy filter.
 */
class FilterConfig : Logger::Loggable<Logger::Id::filter> {
public:
  FilterConfig(const envoy::extensions::filters::network::mssql_proxy::v3::MSSQLProxy& proto_config,
               Server::Configuration::FactoryContext& context)
      : stats_(
            generateStats(fmt::format("mssql.{}", proto_config.stat_prefix()), context.scope())) {

    if (proto_config.has_downstream_tls_context()) {
      if (!proto_config.has_upstream_tls_context()) {
        ENVOY_LOG(warn, "mssql_proxy: downstream TLS context is set but upstream is not, will not "
                        "terminate SSL");
      } else {
        auto& downstream_tls = proto_config.downstream_tls_context();
        auto& tls_socket_config_factory = Config::Utility::getAndCheckFactoryByName<
            Server::Configuration::DownstreamTransportSocketConfigFactory>(
            "envoy.transport_sockets.tls");

        auto tls_socket_factory = tls_socket_config_factory.createTransportSocketFactory(
            downstream_tls, context.getTransportSocketFactoryContext(), {});

        if (tls_socket_factory.ok()) {
          downstream_transport_socket_factory_ = std::move(tls_socket_factory.value());
          ENVOY_LOG(trace, "mssql_proxy: created downstream transport socket factory");
        }
      }
    }

    if (proto_config.has_upstream_tls_context()) {
      if (!proto_config.has_downstream_tls_context()) {
        ENVOY_LOG(warn, "mssql_proxy: upstream TLS context is set but downstream is not, will "
                        "not terminate SSL");
      } else {
        auto& upstream_tls = proto_config.upstream_tls_context();
        auto& tls_socket_config_factory = Config::Utility::getAndCheckFactoryByName<
            Server::Configuration::UpstreamTransportSocketConfigFactory>(
            "envoy.transport_sockets.tls");

        auto tls_socket_factory = tls_socket_config_factory.createTransportSocketFactory(
            upstream_tls, context.getTransportSocketFactoryContext());

        if (tls_socket_factory.ok()) {
          upstream_transport_socket_factory_ = std::move(tls_socket_factory.value());
          ENVOY_LOG(trace, "mssql_proxy: created upstream transport socket factory");
        }
      }
    }
  }

  MssqlProxyStats& stats() { return stats_; }

  Network::TransportSocketPtr createDownstreamTransportSocket() {
    if (downstream_transport_socket_factory_.get() == nullptr) {
      return nullptr;
    }
    return downstream_transport_socket_factory_->createDownstreamTransportSocket();
  }
  Network::TransportSocketPtr createUpstreamTransportSocket() {
    if (upstream_transport_socket_factory_.get() == nullptr) {
      return nullptr;
    }
    return upstream_transport_socket_factory_->createTransportSocket(nullptr, nullptr);
  }

private:
  MssqlProxyStats stats_;

  Network::DownstreamTransportSocketFactoryPtr downstream_transport_socket_factory_;
  Network::UpstreamTransportSocketFactoryPtr upstream_transport_socket_factory_;

  MssqlProxyStats generateStats(const std::string& prefix, Stats::Scope& scope) {
    return MssqlProxyStats{ALL_MSSQL_PROXY_STATS(POOL_COUNTER_PREFIX(scope, prefix))};
  }
};

using FilterConfigSharedPtr = std::shared_ptr<FilterConfig>;

/**
 * Implementation of the MssqlProxy filter
 */
class Filter : public Network::Filter, DecoderCallbacks, Logger::Loggable<Logger::Id::filter> {
public:
  Filter(FilterConfigSharedPtr config) : config_(config) {
    decoder_ = std::make_unique<Decoder>(static_cast<DecoderCallbacks*>(this),
                                         config->createDownstreamTransportSocket(),
                                         config->createUpstreamTransportSocket());
  }
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

  // DecoderCallbacks
  Network::Connection& session() override { return read_callbacks_->connection(); }

  void onPreloginServerSSLPayload(Buffer::Instance& payload) override;
  void onPreloginClientSSLPayload(Buffer::Instance& payload) override;
  void onClientSSLPayload(Buffer::Instance& payload) override;
  void onServerSSLPayload(Buffer::Instance& payload) override;

private:
  FilterConfigSharedPtr config_;
  std::unique_ptr<Decoder> decoder_;

  Network::ReadFilterCallbacks* read_callbacks_{};
  Network::WriteFilterCallbacks* write_callbacks_{};
};

} // namespace MssqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
