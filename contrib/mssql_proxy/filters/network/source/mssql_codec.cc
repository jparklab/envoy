#include <string>

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"
#include "source/common/config/utility.h"
#include "source/common/tls/ssl_socket.h"
#include "envoy/server/transport_socket_config.h"

#include "mssql_codec.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MssqlProxy {

Decoder::Decoder(DecoderCallbacks* callbacks, Network::TransportSocketPtr downstream_tls_socket,
                 Network::TransportSocketPtr upstream_tls_socket)
    : callbacks_(callbacks), downstream_tls_socket_(std::move(downstream_tls_socket)),
      upstream_tls_socket_(std::move(upstream_tls_socket)) {
  if (downstream_tls_socket_.get() != nullptr) {
    TransportSockets::Tls::SslSocket* ssl_socket =
        dynamic_cast<TransportSockets::Tls::SslSocket*>(downstream_tls_socket_.get());
    if (ssl_socket == nullptr) {
      ENVOY_LOG(error, "mssql_proxy: downstream transport socket is not SSL socket");
      return;
    }

    ENVOY_LOG(trace, "create downstream tls pipe");
    downstream_tls_socket_pipe_ = std::make_unique<TLSSocketPipe>(callbacks);
    downstream_tls_socket_->setTransportSocketCallbacks(*downstream_tls_socket_pipe_);

    if (upstream_tls_socket_.get() == nullptr) {
      PANIC("not supported");
    } else {
      TransportSockets::Tls::SslSocket* ssl_socket =
          dynamic_cast<TransportSockets::Tls::SslSocket*>(upstream_tls_socket_.get());
      if (ssl_socket == nullptr) {
        ENVOY_LOG(error, "mssql_proxy: upstream transport socket is not SSL socket");
        return;
      }

      ENVOY_LOG(trace, "create upstream tls pipe");
      upstream_tls_socket_pipe_ = std::make_unique<TLSSocketPipe>(callbacks);
      upstream_tls_socket_->setTransportSocketCallbacks(*upstream_tls_socket_pipe_);
    }
  }
}

// Decoder implementation
Decoder::Result Decoder::onData(Buffer::Instance& data) {
  read_buffer_.add(data);
  return decode(read_buffer_, true);
}

Decoder::Result Decoder::onWrite(Buffer::Instance& data) {
  write_buffer_.add(data);
  auto result = decode(write_buffer_, false);
  while (result == Result::HasMoreData) {
    result = decode(write_buffer_, false);
  }
  continue_ssl_payload_ = false;
  return result;
}

Decoder::Result Decoder::decode(Buffer::Instance& data, bool from_client) {
  if (data.length() < MessageHeader::HeaderLength) {
    ENVOY_LOG(trace, "mssql_proxy: insufficient data: {}", data.length());
    return Result::NeedMoreData;
  }

  uint8_t packet_type = data.peekInt<uint8_t>();
  if (packet_type > MessageHeader::MaxPacketType) {
    ENVOY_LOG(trace, "mssql_proxy: received SSL packet: type({}) from {}", packet_type,
              from_client ? "client" : "server");

    if (from_client) {
      if (downstream_tls_socket_.get() == nullptr) {
        ENVOY_LOG(trace, "mssql_proxy: downstream transport socket is not SSL socket");
        data.drain(data.length());
        return Result::PassThrough;
      }

      auto write_result = downstream_tls_socket_pipe_->fromRawSocket(data);
      if (!write_result.ok()) {
        ENVOY_LOG(trace, "mssql_proxy: failed to write to downstream transport socket");
      } else {
        Buffer::OwnedImpl decrypted_data;
        downstream_tls_socket_->doRead(decrypted_data);
        if (decrypted_data.length() > 0) {
          uint8_t decrypted_packet_type = decrypted_data.peekInt<uint8_t>();
          ENVOY_LOG(trace, "mssql_proxy: read {} bytes from downstream transport socket, type={}",
                    decrypted_data.length(), decrypted_packet_type);
          if (decrypted_packet_type == static_cast<uint8_t>(MessageHeader::PacketType::Login)) {
            auto message = LoginMessage(decrypted_data);
            ENVOY_LOG(trace, "mssql_proxy: decrypted login message received from {}: {}",
                      from_client ? "client" : "server", message.toString());
          }

          if (upstream_tls_socket_.get() == nullptr) {
            // TODO: pass decrypted data properly
            ENVOY_LOG(trace, "mssql_proxy: upstream transport socket is not SSL socket");
            data.drain(data.length());
            return Result::PassThrough;
          }

          auto result = upstream_tls_socket_->doWrite(decrypted_data, false);
          ENVOY_LOG(trace, "mssql_proxy: wrote {} bytes towards upstream SSL transport socket",
                    result.bytes_processed_);
          if (!upstream_tls_socket_pipe_->connected()) {
            ENVOY_LOG(
                trace,
                "mssql_proxy: upstream transport socket is not yet connected, pending bytes: {}",
                decrypted_data.length());
            pending_read_payload_.add(decrypted_data);
          }

          Buffer::OwnedImpl write_buffer;
          auto read_result = upstream_tls_socket_pipe_->toRawSocket(write_buffer, absl::nullopt);
          if (read_result.ok()) {
            ENVOY_LOG(trace, "mssql_proxy: read {} bytes towards upstream transport socket",
                      write_buffer.length());

            if (!upstream_tls_socket_pipe_->connected()) {
              ENVOY_LOG(trace, "mssql_proxy: upstream transport socket is not yet connected");
              callbacks_->onPreloginClientSSLPayload(write_buffer);
            } else {
              ENVOY_LOG(trace, "mssql_proxy: WRITE TO UPSTREAM");
              callbacks_->onClientSSLPayload(write_buffer);
            }

            data.drain(data.length());
            return Result::Consumed;
          }
        }
      }
    } else {
      if (upstream_tls_socket_.get() == nullptr) {
        ENVOY_LOG(trace, "mssql_proxy: downstream transport socket is not SSL socket");
        data.drain(data.length());
        return Result::PassThrough;
      }

      ENVOY_LOG(trace, "mssql_proxy: writing {} bytes from upstream transport socket",
                data.length());
      auto write_result = upstream_tls_socket_pipe_->fromRawSocket(data);
      if (!write_result.ok()) {
        ENVOY_LOG(trace, "mssql_proxy: failed to write to upstream transport socket");
      } else {
        Buffer::OwnedImpl decrypted_data;
        upstream_tls_socket_->doRead(decrypted_data);
        if (decrypted_data.length() > 0) {
          uint8_t decrypted_packet_type = decrypted_data.peekInt<uint8_t>();
          ENVOY_LOG(trace, "mssql_proxy: read {} bytes from upstream transport socket, type={}",
                    decrypted_data.length(), decrypted_packet_type);

          downstream_tls_socket_->doWrite(decrypted_data, false);

          Buffer::OwnedImpl write_buffer;
          auto read_result = downstream_tls_socket_pipe_->toRawSocket(write_buffer, absl::nullopt);
          if (read_result.ok()) {
            ENVOY_LOG(trace, "mssql_proxy: read {} bytes towards downstream transport socket",
                      write_buffer.length());

            callbacks_->onServerSSLPayload(write_buffer);
            data.drain(data.length());
            return Result::Consumed;
          }
        } else {
          ENVOY_LOG(trace, "mssql_proxy: no decrypted data read from upstream transport socket");
        }
      }
    }

    data.drain(data.length());
    return Result::Consumed;
  }

  auto header = MessageHeader(data);
  if (data.length() < header.packetLength()) {
    ENVOY_LOG(trace, "mssql_proxy: insufficient data: {}", data.length());
    return Result::NeedMoreData;
  }
  ENVOY_LOG(trace, "mssql_proxy: packet type: {}, status: {}, length: {}, total length: {}",
            static_cast<uint8_t>(header.packetType()), header.packetStatus(), header.packetLength(),
            data.length());

  switch (header.packetType()) {
  case MessageHeader::PacketType::Query: {
    ENVOY_LOG(trace, "mssql_proxy: query message received from {}",
              from_client ? "client" : "server");
    break;
  }
  case MessageHeader::PacketType::PreTds7Login: {
    ENVOY_LOG(trace, "mssql_proxy: pre tds7login message received from {}",
              from_client ? "client" : "server");
    break;
  }
  case MessageHeader::PacketType::Rpc: {
    ENVOY_LOG(trace, "mssql_proxy: rpc message received from {}",
              from_client ? "client" : "server");
    break;
  }
  case MessageHeader::PacketType::Reply: {
    ENVOY_LOG(trace, "mssql_proxy: reply message received from {}",
              from_client ? "client" : "server");
    break;
  }
  case MessageHeader::PacketType::AttnSignal: {
    ENVOY_LOG(trace, "mssql_proxy: attn signal message received from {}",
              from_client ? "client" : "server");
    break;
  }
  case MessageHeader::PacketType::BulkLoad: {
    ENVOY_LOG(trace, "mssql_proxy: bulk load message received from {}",
              from_client ? "client" : "server");
    ENVOY_LOG(trace, "mssql_proxy: bulkload message received");
    break;
  }
  case MessageHeader::PacketType::FedAuthToken: {
    ENVOY_LOG(trace, "mssql_proxy: federated auth token message received from {}",
              from_client ? "client" : "server");
    break;
  }
  case MessageHeader::PacketType::TransManagerReq: {
    ENVOY_LOG(trace, "mssql_proxy: transaction manager request message received from {}",
              from_client ? "client" : "server");
    break;
  }
  case MessageHeader::PacketType::Normal: {
    ENVOY_LOG(trace, "mssql_proxy: normal message received from {}",
              from_client ? "client" : "server");
    break;
  }
  case MessageHeader::PacketType::Login: {
    ENVOY_LOG(trace, "mssql_proxy: login message received from {}",
              from_client ? "client" : "server");
    break;
  }
  case MessageHeader::PacketType::Sspi: {
    ENVOY_LOG(trace, "mssql_proxy: sspi message received from {}",
              from_client ? "client" : "server");
    break;
  }
  case MessageHeader::PacketType::Prelogin: {
    uint8_t first_byte = data.peekInt<uint8_t>(MessageHeader::HeaderLength);
    ENVOY_LOG(
        trace,
        "mssql_proxy: prelogin message received from {}: first_byte={}, continue_ssl_payload={}",
        from_client ? "client" : "server", first_byte, continue_ssl_payload_);

    // FIXME: refactor continue_ssl_payload_
    if (continue_ssl_payload_ ||
        (first_byte >= MinSSLRecordType && first_byte <= MaxSSLRecordType)) {
      ENVOY_LOG(trace, "mssql_proxy: prelogin ssl message received from {}",
                from_client ? "client" : "server");

      Buffer::OwnedImpl plaintext_data;
      plaintext_data.move(data, MessageHeader::HeaderLength);

      if (from_client) {
        if (downstream_tls_socket_.get() == nullptr) {
          ENVOY_LOG(trace, "mssql_proxy: downstream transport socket is not SSL socket");
          return Result::PassThrough;
        }

        Buffer::OwnedImpl handshake_data;
        handshake_data.add(data);
        // pass through to TLS socket
        // remove header
        ENVOY_LOG(trace, "mssql_proxy: write {} bytes read from downstream transport socket",
                  handshake_data.length());
        auto write_result = downstream_tls_socket_pipe_->fromRawSocket(handshake_data);
        if (!write_result.ok()) {
          ENVOY_LOG(trace, "mssql_proxy: failed to write bytes from downstream transport socket");
        } else {
          Buffer::OwnedImpl decrypted_data;
          downstream_tls_socket_->doRead(decrypted_data);
          if (decrypted_data.length() > 0) {
            ENVOY_LOG(trace, "mssql_proxy: read {} bytes from downstream transport socket",
                      decrypted_data.length());
            plaintext_data.add(decrypted_data);
            auto message = PreloginMessage(plaintext_data);
            ENVOY_LOG(trace, "mssql_proxy: decrypted prelogin message received from {}: {}",
                      from_client ? "client" : "server", message.toString());
          }

          Buffer::OwnedImpl write_buffer;
          auto read_result = downstream_tls_socket_pipe_->toRawSocket(write_buffer, absl::nullopt);
          if (read_result.ok()) {
            ENVOY_LOG(trace, "mssql_proxy: read {} bytes towards downstream transport socket",
                      write_buffer.length());
            callbacks_->onPreloginServerSSLPayload(write_buffer);
          }

          if (downstream_tls_socket_pipe_->connected()) {
            ENVOY_LOG(trace, "mssql_proxy: downstream transport socket connected");
          }

          data.drain(data.length());
          return Result::Consumed;
        }
      } else {
        write_payload_.move(data, header.packetLength() - MessageHeader::HeaderLength);
        ENVOY_LOG(trace,
                  "mssql_proxy: moved data to payload buffer, length: {}, payload length: {}, "
                  "remaining: {}",
                  header.packetLength() - MessageHeader::HeaderLength, write_payload_.length(),
                  data.length());
        if (header.packetStatus() == 0x00) {
          ENVOY_LOG(trace,
                    "mssql_proxy: prelogin ssl message received from server: not end of message");
          continue_ssl_payload_ = true;
          return data.length() > 0 ? Result::HasMoreData : Result::Consumed;
        }

        Buffer::OwnedImpl handshake_data;
        handshake_data.move(write_payload_, write_payload_.length());
        // pass through to TLS socket
        // remove header
        ENVOY_LOG(trace, "mssql_proxy: write {} bytes read from upstream transport socket",
                  handshake_data.length());
        auto write_result = upstream_tls_socket_pipe_->fromRawSocket(handshake_data);
        if (!write_result.ok()) {
          ENVOY_LOG(trace, "mssql_proxy: failed to write bytes from upstream transport socket");
        } else {
          Buffer::OwnedImpl decrypted_data;
          upstream_tls_socket_->doRead(decrypted_data);
          if (decrypted_data.length() > 0) {
            ENVOY_LOG(trace, "mssql_proxy: read {} bytes from upstream transport socket",
                      decrypted_data.length());
            plaintext_data.add(decrypted_data);
            auto message = PreloginMessage(plaintext_data);
            ENVOY_LOG(trace, "mssql_proxy: decrypted prelogin message received from {}: {}",
                      from_client ? "client" : "server", message.toString());
          }

          Buffer::OwnedImpl write_buffer;
          auto read_result = upstream_tls_socket_pipe_->toRawSocket(write_buffer, absl::nullopt);
          while (read_result.ok()) {
            ENVOY_LOG(trace, "mssql_proxy: read {} bytes towards upstream transport socket",
                      write_buffer.length());
            callbacks_->onPreloginClientSSLPayload(write_buffer);
            write_buffer.drain(write_buffer.length());
            read_result = upstream_tls_socket_pipe_->toRawSocket(write_buffer, absl::nullopt);
          }

          if (upstream_tls_socket_pipe_->connected()) {
            ENVOY_LOG(trace, "mssql_proxy: upstream transport socket connected");
            auto result = upstream_tls_socket_->doWrite(pending_read_payload_, false);
            ENVOY_LOG(trace, "mssql_proxy: wrote {} bytes towards upstream SSL transport socket",
                      result.bytes_processed_);

            Buffer::OwnedImpl write_buffer;
            auto read_result = upstream_tls_socket_pipe_->toRawSocket(write_buffer, absl::nullopt);
            if (read_result.ok()) {
              ENVOY_LOG(trace,
                        "mssql_proxy: read {} encrypted bytes towards upstream transport socket",
                        write_buffer.length());

              callbacks_->onClientSSLPayload(write_buffer);
            }

            Buffer::OwnedImpl decrypted_data;
            upstream_tls_socket_->doRead(decrypted_data);
            if (decrypted_data.length() > 0) {
              ENVOY_LOG(trace, "mssql_proxy: read {} bytes from upstream transport socket",
                        decrypted_data.length());
              plaintext_data.add(decrypted_data);
              auto message = PreloginMessage(plaintext_data);
              ENVOY_LOG(trace, "mssql_proxy: decrypted prelogin message received from {}: {}",
                        from_client ? "client" : "server", message.toString());
            }

            pending_read_payload_.drain(pending_read_payload_.length());
          }

          // data.drain(header.packetLength() - MessageHeader::HeaderLength);
          ENVOY_LOG(trace, "mssql_proxy: remaining bytes: {}", data.length());
          return data.length() > 0 ? Result::HasMoreData : Result::Consumed;
        }
      }
      break;
    } else {
      ENVOY_LOG(trace, "mssql_proxy: parse prelogin message received from {}",
                from_client ? "client" : "server");
      auto message = PreloginMessage(data);
      ENVOY_LOG(trace, "mssql_proxy: prelogin message received from {}: {}",
                from_client ? "client" : "server", message.toString());
    }
    break;
  }
  }

  // FIXME: should drain packet length
  data.drain(data.length());

  return Result::PassThrough;
}

} // namespace MssqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy