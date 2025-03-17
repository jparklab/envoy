#pragma once

#include <cstdint>
#include <vector>
#include <string>

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "envoy/network/io_handle.h"
#include "source/extensions/io_socket/user_space/io_handle_impl.h"

// for ssl
#include "openssl/md5.h"
#include "openssl/ssl.h"

#include "mssql_messages.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MssqlProxy {

class DecoderCallbacks {
public:
  virtual ~DecoderCallbacks() = default;

  virtual Network::Connection& session() PURE;

  // called for SSL traffic
  virtual void onPreloginServerSSLPayload(Buffer::Instance& payload) PURE;
  virtual void onPreloginClientSSLPayload(Buffer::Instance& payload) PURE;
  virtual void onClientSSLPayload(Buffer::Instance& payload) PURE;
  virtual void onServerSSLPayload(Buffer::Instance& payload) PURE;
};

class TLSSocketPipe : public Network::TransportSocketCallbacks,
                      Logger::Loggable<Logger::Id::filter> {
public:
  TLSSocketPipe(DecoderCallbacks* callbacks) : callbacks_(callbacks) {
    auto p = IoSocket::UserSpace::IoHandleFactory::createIoHandlePair();
    from_rawsocket_ = std::move(p.first);
    to_rawsocket_ = std::move(p.second);
  }

  bool connected() { return connected_; }

  Api::IoCallUint64Result fromRawSocket(Buffer::Instance& buffer) {
    return from_rawsocket_->write(buffer);
  }
  Api::IoCallUint64Result toRawSocket(Buffer::Instance& buffer,
                                      absl::optional<uint64_t> max_length) {
    return from_rawsocket_->read(buffer, max_length);
  }

  // fields for TransportSocketCallbacks
  Network::IoHandle& ioHandle() override {
    ENVOY_LOG(trace, "mssql_proxy: ioHandle() called");
    return *to_rawsocket_;
  }

  const Network::IoHandle& ioHandle() const override {
    ENVOY_LOG(trace, "mssql_proxy: ioHandle() const called");
    return *to_rawsocket_;
  }
  Network::Connection& connection() override { return callbacks_->session(); }

  void raiseEvent(Network::ConnectionEvent event) override {
    switch (event) {
    case Network::ConnectionEvent::Connected:
      ENVOY_LOG(trace, "mssql_proxy: raiseEvent(Connected) called");
      connected_ = true;
      break;
    default:
      ENVOY_LOG(trace, "mssql_proxy: raiseEvent({}) called", static_cast<int>(event));
      break;
    }
  }

  // should read buffer be drained?
  bool shouldDrainReadBuffer() override { return false; }
  void setTransportSocketIsReadable() override {
    ENVOY_LOG(trace, "mssql_proxy: setTransportSocketIsReadable called");
  }
  void flushWriteBuffer() override { PANIC("flushWriteBuffer not implemented"); }

private:
  DecoderCallbacks* callbacks_;
  IoSocket::UserSpace::IoHandleImplPtr from_rawsocket_;
  IoSocket::UserSpace::IoHandleImplPtr to_rawsocket_;

  bool connected_{false};
};

using TLSSocketPipePtr = std::unique_ptr<TLSSocketPipe>;

class Decoder : Logger::Loggable<Logger::Id::filter> {
public:
  enum class Result : uint8_t {
    NeedMoreData = 0, // Decoder needs more data to process the message.
    PassThrough,      // Decoder processed the message and the message can be forwarded to the next
                      // filter
    Consumed,    // Decoder processed the message and the message should not be forwarded to the
                 // next filter
    HasMoreData, // Decoder processed the message and there is more data to process
  };

  enum class SessionState : uint8_t {
    Init = 0,
    Handshake, // SSL handshake in progress
    EncryptionOn,
    EncryptionOff,
  };

  enum class SSLRecordType : uint8_t {
    CHANGE_CIPHER_SPEC = 20, // 0x14
    ALERT = 21,              // 0x15
    HANDSHAKE = 22,          // 0x16
    APPLICATION_DATA = 23,   // 0x17
    HEARTBEAT = 24,          // 0x18
  };

  constexpr static uint8_t MinSSLRecordType =
      static_cast<uint8_t>(SSLRecordType::CHANGE_CIPHER_SPEC);
  constexpr static uint8_t MaxSSLRecordType = static_cast<uint8_t>(SSLRecordType::HEARTBEAT);

  Decoder(DecoderCallbacks* callbacks, Network::TransportSocketPtr downstream_tls_socket,
          Network::TransportSocketPtr upstream_tls_socket);
  virtual ~Decoder() = default;

  Network::FilterStatus onData(Buffer::Instance& data);
  Network::FilterStatus onWrite(Buffer::Instance& data);

private:
  SessionState client_session_state_{SessionState::Init};
  SessionState server_session_state_{SessionState::Init};

  bool upstream_encrypted_{false};

  DecoderCallbacks* callbacks_;

  Buffer::OwnedImpl read_buffer_;
  Buffer::OwnedImpl write_buffer_;

  Buffer::OwnedImpl read_payload_;
  Buffer::OwnedImpl write_payload_;
  bool continue_ssl_payload_{false};

  Buffer::OwnedImpl pending_read_payload_;

  Network::TransportSocketPtr downstream_tls_socket_;
  Network::TransportSocketPtr upstream_tls_socket_;

  TLSSocketPipePtr downstream_tls_socket_pipe_;
  TLSSocketPipePtr upstream_tls_socket_pipe_;

  Result decodeClientMessage(Buffer::Instance& data);
  Result decodeServerMessage(Buffer::Instance& data);
};

} // namespace MssqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
