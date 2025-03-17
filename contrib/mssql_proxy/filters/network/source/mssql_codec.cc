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
    if (upstream_tls_socket_.get() == nullptr) {
      // FilterConfig is expected to create both downstream_tls_socket and upstream_tls_socket
      PANIC("upstream_tls_socket cannot be null");
    }

    // check if downstream/upstream transport socket is SSL socket
    TransportSockets::Tls::SslSocket* downstream_ssl_socket =
        dynamic_cast<TransportSockets::Tls::SslSocket*>(downstream_tls_socket_.get());
    if (downstream_ssl_socket == nullptr) {
      ENVOY_LOG(error, "mssql_proxy: downstream transport socket is not SSL socket");
      return;
    }

    TransportSockets::Tls::SslSocket* upstream_ssl_socket =
        dynamic_cast<TransportSockets::Tls::SslSocket*>(upstream_tls_socket_.get());
    if (upstream_ssl_socket == nullptr) {
      ENVOY_LOG(error, "mssql_proxy: upstream transport socket is not SSL socket");
      return;
    }

    // create TLS socket pipes for downstream and upstream

    downstream_tls_socket_pipe_ = std::make_unique<TLSSocketPipe>(callbacks);
    downstream_tls_socket_->setTransportSocketCallbacks(*downstream_tls_socket_pipe_);

    upstream_tls_socket_pipe_ = std::make_unique<TLSSocketPipe>(callbacks);
    upstream_tls_socket_->setTransportSocketCallbacks(*upstream_tls_socket_pipe_);
  }
}

// Decoder implementation
Network::FilterStatus Decoder::onData(Buffer::Instance& data) {
  if (client_session_state_ == SessionState::EncryptionOff) {
    // TODO:
    return Network::FilterStatus::Continue;
  }

  if (client_session_state_ == SessionState::EncryptionOn) {
    if (downstream_tls_socket_.get() == nullptr) {
      // do not handle ssl payload if downstream transport socket is not SSL socket
      return Network::FilterStatus::Continue;
    }

    auto write_result = downstream_tls_socket_pipe_->fromRawSocket(data);
    if (!write_result.ok()) {
      ENVOY_LOG(trace, "mssql_proxy: failed to write to downstream transport socket");
      return Network::FilterStatus::StopIteration;
    }
    ENVOY_LOG(trace, "mssql_proxy: wrote to downstream transport socket, data length={}",
              data.length());

    ENVOY_LOG(trace, "mssql_proxy: read decrypted data from downstream transport socket");
    downstream_tls_socket_->doRead(read_buffer_);
  } else {
    read_buffer_.add(data);
  }

  auto result = decodeClientMessage(read_buffer_);
  switch (result) {
  case Decoder::Result::NeedMoreData:
  case Decoder::Result::Consumed:
    return Network::FilterStatus::StopIteration;
  case Decoder::Result::HasMoreData:
    // TODO: what should I return?
    // idea: forward packet using callbacks if necessary
    return Network::FilterStatus::StopIteration;
  case Decoder::Result::PassThrough:
    return Network::FilterStatus::Continue;
  default:
    PANIC("Unexpected result");
    break;
  }
}

Network::FilterStatus Decoder::onWrite(Buffer::Instance& data) {
  (void)server_session_state_;
  if (upstream_encrypted_) {
    if (upstream_tls_socket_.get() == nullptr) {
      // do not handle ssl payload if upstream transport socket is not SSL socket
      return Network::FilterStatus::Continue;
    }

    auto write_result = upstream_tls_socket_pipe_->fromRawSocket(data);
    if (!write_result.ok()) {
      ENVOY_LOG(trace, "mssql_proxy: failed to write to upstream transport socket");
      return Network::FilterStatus::StopIteration;
    }

    ENVOY_LOG(trace, "mssql_proxy: read decrypted data from upstream transport socket");
    upstream_tls_socket_->doRead(write_buffer_);
  } else {
    write_buffer_.add(data);
  }

  auto result = decodeServerMessage(write_buffer_);

  while (result == Result::HasMoreData) {
    result = decodeServerMessage(write_buffer_);
  }

  switch (result) {
  case Decoder::Result::NeedMoreData:
  case Decoder::Result::Consumed:
    return Network::FilterStatus::StopIteration;
  case Decoder::Result::HasMoreData:
    // TODO: what should I return?
    // idea: forward packet using callbacks if necessary
    return Network::FilterStatus::StopIteration;
  case Decoder::Result::PassThrough: {
    if (client_session_state_ == SessionState::EncryptionOn) {
      ENVOY_LOG(trace, "mssql_proxy: write {} bytes towards downstream transport socket",
                write_buffer_.length());

      downstream_tls_socket_->doWrite(write_buffer_, false);

      Buffer::OwnedImpl write_buffer;
      auto read_result = downstream_tls_socket_pipe_->toRawSocket(write_buffer, absl::nullopt);
      if (read_result.ok()) {
        ENVOY_LOG(trace, "mssql_proxy: read {} bytes towards downstream transport socket",
                  write_buffer.length());

        callbacks_->onServerSSLPayload(write_buffer);
      }
      write_buffer_.drain(write_buffer_.length());
      return Network::FilterStatus::StopIteration;
    } else {
      write_buffer_.drain(write_buffer_.length());
      return Network::FilterStatus::Continue;
    }
  }
  default:
    PANIC("Unexpected result");
    break;
  }
}

Decoder::Result Decoder::decodeClientMessage(Buffer::Instance& data) {
  if (data.length() < MessageHeader::HeaderLength) {
    ENVOY_LOG(trace, "mssql_proxy: insufficient data: {}", data.length());
    return Result::NeedMoreData;
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
    ENVOY_LOG(trace, "mssql_proxy: query message received from client");
    if (upstream_tls_socket_.get() == nullptr) {
      // TODO: pass decrypted data properly
      ENVOY_LOG(trace, "mssql_proxy: upstream transport socket is not SSL socket");
      data.drain(data.length());
      return Result::PassThrough;
    }

    auto result = upstream_tls_socket_->doWrite(data, false);
    ENVOY_LOG(trace, "mssql_proxy: wrote {} bytes towards upstream SSL transport socket",
              result.bytes_processed_);

    Buffer::OwnedImpl write_buffer;
    auto read_result = upstream_tls_socket_pipe_->toRawSocket(write_buffer, absl::nullopt);
    if (read_result.ok()) {
      ENVOY_LOG(trace, "mssql_proxy: read {} bytes towards upstream transport socket",
                write_buffer.length());

      callbacks_->onClientSSLPayload(write_buffer);
      data.drain(data.length());
      return Result::Consumed;
    }
    break;
  }
  case MessageHeader::PacketType::PreTds7Login: {
    ENVOY_LOG(trace, "mssql_proxy: pre tds7login message received from client");
    break;
  }
  case MessageHeader::PacketType::Rpc: {
    ENVOY_LOG(trace, "mssql_proxy: rpc message received from client");
    break;
  }
  case MessageHeader::PacketType::Reply: {
    ENVOY_LOG(trace, "mssql_proxy: reply message received from client");
    break;
  }
  case MessageHeader::PacketType::AttnSignal: {
    ENVOY_LOG(trace, "mssql_proxy: attn signal message received from client");
    break;
  }
  case MessageHeader::PacketType::BulkLoad: {
    ENVOY_LOG(trace, "mssql_proxy: bulk load message received from client");
    ENVOY_LOG(trace, "mssql_proxy: bulkload message received");
    break;
  }
  case MessageHeader::PacketType::FedAuthToken: {
    ENVOY_LOG(trace, "mssql_proxy: federated auth token message received from client");
    break;
  }
  case MessageHeader::PacketType::TransManagerReq: {
    ENVOY_LOG(trace, "mssql_proxy: transaction manager request message received from client");
    break;
  }
  case MessageHeader::PacketType::Normal: {
    ENVOY_LOG(trace, "mssql_proxy: normal message received from client");
    break;
  }
  case MessageHeader::PacketType::Login: {
    auto message = LoginMessage(data);
    ENVOY_LOG(trace, "mssql_proxy: login message received from client: {}", message.toString());

    if (upstream_tls_socket_.get() == nullptr) {
      // TODO: pass decrypted data properly
      ENVOY_LOG(trace, "mssql_proxy: upstream transport socket is not SSL socket");
      data.drain(data.length());
      return Result::PassThrough;
    }

    auto result = upstream_tls_socket_->doWrite(data, false);
    ENVOY_LOG(trace, "mssql_proxy: wrote {} bytes towards upstream SSL transport socket",
              result.bytes_processed_);
    if (!upstream_tls_socket_pipe_->connected()) {
      ENVOY_LOG(trace,
                "mssql_proxy: upstream transport socket is not yet connected, pending bytes: {}",
                data.length());
      pending_read_payload_.add(data);
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
    break;
  }
  case MessageHeader::PacketType::Sspi: {
    ENVOY_LOG(trace, "mssql_proxy: sspi message received from client");
    break;
  }
  case MessageHeader::PacketType::Prelogin: {
    uint8_t first_byte = data.peekInt<uint8_t>(MessageHeader::HeaderLength);
    ENVOY_LOG(trace, "mssql_proxy: prelogin message received from client: first_byte={}",
              first_byte);

    // FIXME: refactor continue_ssl_payload_
    if (client_session_state_ == SessionState::Handshake ||
        (first_byte >= MinSSLRecordType && first_byte <= MaxSSLRecordType)) {
      ENVOY_LOG(trace, "mssql_proxy: prelogin ssl message received from client");
      client_session_state_ = SessionState::Handshake;

      Buffer::OwnedImpl plaintext_data;
      plaintext_data.move(data, MessageHeader::HeaderLength);

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
          ENVOY_LOG(trace, "mssql_proxy: decrypted prelogin message received from client: {}",
                    message.toString());
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
          client_session_state_ = SessionState::EncryptionOn;
        }

        data.drain(data.length());
        return Result::Consumed;
      }
      break;
    } else {
      ENVOY_LOG(trace, "mssql_proxy: parse prelogin message received from client");
      auto message = PreloginMessage(data);
      ENVOY_LOG(trace, "mssql_proxy: prelogin message received from client: {}",
                message.toString());
    }
    break;
  }
  }

  // FIXME: should drain packet length
  data.drain(data.length());

  return Result::PassThrough;
}

Decoder::Result Decoder::decodeServerMessage(Buffer::Instance& data) {
  if (data.length() < MessageHeader::HeaderLength) {
    ENVOY_LOG(trace, "mssql_proxy: insufficient data: {}", data.length());
    return Result::NeedMoreData;
  }

  uint8_t packet_type = data.peekInt<uint8_t>();
  if (packet_type > MessageHeader::MaxPacketType) {
    ENVOY_LOG(trace, "mssql_proxy: received SSL packet: type({}) from server", packet_type);

    PANIC("ssl messages should be decrypted inside onWrite");
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
  case MessageHeader::PacketType::Reply: {
    ENVOY_LOG(trace, "mssql_proxy: reply message received from server");
    break;
  }
  case MessageHeader::PacketType::Prelogin: {
    uint8_t first_byte = data.peekInt<uint8_t>(MessageHeader::HeaderLength);
    ENVOY_LOG(trace,
              "mssql_proxy: prelogin message received from server: first_byte={}, "
              "continue_ssl_payload={}",
              first_byte, continue_ssl_payload_);

    // FIXME: refactor continue_ssl_payload_
    if (continue_ssl_payload_ ||
        (first_byte >= MinSSLRecordType && first_byte <= MaxSSLRecordType)) {
      ENVOY_LOG(trace, "mssql_proxy: prelogin ssl message received from server");

      Buffer::OwnedImpl plaintext_data;
      plaintext_data.move(data, MessageHeader::HeaderLength);

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
          ENVOY_LOG(trace, "mssql_proxy: decrypted prelogin message received from server: {}",
                    message.toString());
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
          upstream_encrypted_ = true;

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
            ENVOY_LOG(trace, "mssql_proxy: decrypted prelogin message received from server: {}",
                      message.toString());
          }

          pending_read_payload_.drain(pending_read_payload_.length());
        }

        // data.drain(header.packetLength() - MessageHeader::HeaderLength);
        ENVOY_LOG(trace, "mssql_proxy: remaining bytes: {}", data.length());
        return data.length() > 0 ? Result::HasMoreData : Result::Consumed;
      }
      break;
    } else {
      ENVOY_LOG(trace, "mssql_proxy: parse prelogin message received from server");
      auto message = PreloginMessage(data);
      ENVOY_LOG(trace, "mssql_proxy: prelogin message received from server: {}",
                message.toString());
    }
    break;
  }
  default:
    ENVOY_LOG(trace, "mssql_proxy: unexpected packet type; type={}", packet_type);
  }

  return Result::PassThrough;
}

#if 0 // old code
// FIXME:
//  it seems like it's better to write separate function for client/server
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
      PANIC("ssl messages should be decrypted inside onData");
    } else {
      // PANIC("ssl messages should be decrypted inside onWrite");
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
    if (upstream_tls_socket_.get() == nullptr) {
      // TODO: pass decrypted data properly
      ENVOY_LOG(trace, "mssql_proxy: upstream transport socket is not SSL socket");
      data.drain(data.length());
      return Result::PassThrough;
    }

    auto result = upstream_tls_socket_->doWrite(data, false);
    ENVOY_LOG(trace, "mssql_proxy: wrote {} bytes towards upstream SSL transport socket",
              result.bytes_processed_);

    Buffer::OwnedImpl write_buffer;
    auto read_result = upstream_tls_socket_pipe_->toRawSocket(write_buffer, absl::nullopt);
    if (read_result.ok()) {
      ENVOY_LOG(trace, "mssql_proxy: read {} bytes towards upstream transport socket",
                write_buffer.length());

      callbacks_->onClientSSLPayload(write_buffer);
      data.drain(data.length());
      return Result::Consumed;
    }
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
    auto message = LoginMessage(data);
    ENVOY_LOG(trace, "mssql_proxy: login message received from {}: {}",
              from_client ? "client" : "server", message.toString());

    if (upstream_tls_socket_.get() == nullptr) {
      // TODO: pass decrypted data properly
      ENVOY_LOG(trace, "mssql_proxy: upstream transport socket is not SSL socket");
      data.drain(data.length());
      return Result::PassThrough;
    }

    auto result = upstream_tls_socket_->doWrite(data, false);
    ENVOY_LOG(trace, "mssql_proxy: wrote {} bytes towards upstream SSL transport socket",
              result.bytes_processed_);
    if (!upstream_tls_socket_pipe_->connected()) {
      ENVOY_LOG(trace,
                "mssql_proxy: upstream transport socket is not yet connected, pending bytes: {}",
                data.length());
      pending_read_payload_.add(data);
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
            downstream_encrypted_ = true;
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
            upstream_encrypted_ = true;

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
#endif

} // namespace MssqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy