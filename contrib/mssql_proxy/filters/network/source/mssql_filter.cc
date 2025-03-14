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

Network::FilterStatus Filter::onData(Buffer::Instance& data, bool) {
  ENVOY_CONN_LOG(trace, "mssql_proxy: received {} bytes from client", read_callbacks_->connection(),
                 data.length());

  Decoder::Result result = decoder_->onData(data);

  switch (result) {
  case Decoder::Result::NeedMoreData:
    // do not forward data until we have enough to process
    data.drain(data.length());
    return Network::FilterStatus::StopIteration;
  case Decoder::Result::PassThrough:
    return Network::FilterStatus::Continue;
  case Decoder::Result::Consumed:
    data.drain(data.length());
    return Network::FilterStatus::StopIteration;
  default:
    break;
  }

  return Network::FilterStatus::Continue;
}

Network::FilterStatus Filter::onWrite(Buffer::Instance& data, bool) {
  ENVOY_CONN_LOG(trace, "mssql_proxy: received {} bytes from server", read_callbacks_->connection(),
                 data.length());

  Decoder::Result result = decoder_->onWrite(data);

  switch (result) {
  case Decoder::Result::NeedMoreData:
    // FIXME: Filter::onUpstreamData() requires the buffer to be drained
    // [2025-03-12 12:16:02.447][2052380][critical][backtrace] [./source/server/backtrace.h:127]
    // Caught Aborted, suspect faulting address 0x3e8001f5025 [2025-03-12
    // 12:16:02.447][2052380][critical][backtrace] [./source/server/backtrace.h:111] Backtrace (use
    // tools/stack_decode.py to get line numbers): [2025-03-12
    // 12:16:02.447][2052380][critical][backtrace] [./source/server/backtrace.h:112] Envoy version:
    // 3cc95445c9cf4966283c2a8704f9cdb185f0cd88/1.33.0-dev/Modified/DEBUG/BoringSSL [2025-03-12
    // 12:16:02.447][2052380][critical][backtrace] [./source/server/backtrace.h:114] Address
    // mapping: 5fb73bd64000-5fb744b75000
    // /home/jpark/.cache/bazel/_bazel_jpark/ace7b8de40762dd92ed362808811797d/execroot/envoy/bazel-out/k8-fastbuild/bin/contrib/exe/envoy-static
    // do not forward data until we have enough to process
    data.drain(data.length());
    return Network::FilterStatus::StopIteration;
  case Decoder::Result::PassThrough:
    return Network::FilterStatus::Continue;
  case Decoder::Result::Consumed:
    data.drain(data.length());
    return Network::FilterStatus::StopIteration;
  default:
    break;
  }

  /*
  if (result == Network::FilterStatus::StopIteration) {
    data.drain(data.length());
  }
  */

  return Network::FilterStatus::Continue;
}

void Filter::onPrelogin(const PreloginMessage& message) { (void)message; }
void Filter::onPreloginResponse(const PreloginMessage& message) { (void)message; }
void Filter::onLogin(const LoginMessage& message) { (void)message; }

void Filter::onPreloginServerSSLPayload(Buffer::Instance& payload) {
  char header[MessageHeader::HeaderLength];
  uint16_t packet_length = static_cast<uint16_t>(payload.length() + MessageHeader::HeaderLength);
  header[0] = static_cast<char>(MessageHeader::PacketType::Prelogin);
  header[1] = 0x01; // status: end of message
  // length
  // FIXME: we should store the actualy copied record lengths
  header[2] = static_cast<char>(packet_length / 256);
  header[3] = static_cast<char>(packet_length & 0xff);
  header[6] = 0x01; // packet id

  Buffer::OwnedImpl buffer;
  buffer.add(header, MessageHeader::HeaderLength);
  buffer.move(payload, payload.length(), false);

  write_callbacks_->injectWriteDataToFilterChain(buffer, false);
}

void Filter::onClientSSLPayload(Buffer::Instance& payload) {
  ENVOY_CONN_LOG(trace, "mssql_proxy: inject read data {} bytes", read_callbacks_->connection(),
                 payload.length());
  read_callbacks_->injectReadDataToFilterChain(payload, false);
}

void Filter::onServerSSLPayload(Buffer::Instance& payload) {
  ENVOY_CONN_LOG(trace, "mssql_proxy: inject write data {} bytes", read_callbacks_->connection(),
                 payload.length());
  write_callbacks_->injectWriteDataToFilterChain(payload, false);
}

void Filter::onPreloginClientSSLPayload(Buffer::Instance& payload) {
#if 1
  char header[MessageHeader::HeaderLength];
  uint16_t packet_length = static_cast<uint16_t>(payload.length() + MessageHeader::HeaderLength);
  header[0] = static_cast<char>(MessageHeader::PacketType::Prelogin);
  header[1] = 0x01; // status: end of message
  // length
  // FIXME: we should store the actualy copied record lengths
  header[2] = static_cast<char>(packet_length / 256);
  header[3] = static_cast<char>(packet_length & 0xff);
  // bytes 4 and 5 are SPID
  // SPID is the process ID on the server, corresponding to the current connection.
  // This information is sent by the server to the client and is useful for identifying
  // which thread on the server sent the TDS packet. It is provided for debugging purposes.
  header[4] = 0x00;
  header[5] = 0x00;
  header[6] = 0x01; // packet id

  Buffer::OwnedImpl buffer;
  buffer.add(header, MessageHeader::HeaderLength);
  buffer.move(payload, payload.length(), false);

  ENVOY_CONN_LOG(trace, "mssql_proxy: inject read data {} bytes", read_callbacks_->connection(),
                 buffer.length());
  read_callbacks_->injectReadDataToFilterChain(buffer, false);
#else
  read_callbacks_->injectReadDataToFilterChain(payload, false);
#endif
}

} // namespace MssqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
