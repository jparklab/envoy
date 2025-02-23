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

Network::FilterStatus Filter::onData(Buffer::Instance&, bool) {
  // TODO: implement
  return Network::FilterStatus::Continue;
}

Network::FilterStatus Filter::onWrite(Buffer::Instance&, bool) {
  // TODO: implement
  return Network::FilterStatus::Continue;
}

} // namespace MssqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
