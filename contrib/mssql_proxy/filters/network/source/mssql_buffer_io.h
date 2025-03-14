#pragma once

#include <cstdint>
#include <vector>
#include <string>

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/common/network/io_socket_error_impl.h"
#include "envoy/network/io_handle.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MssqlProxy {

class BufferIoHandle : public Network::IoHandle {
public:
  explicit BufferIoHandle(Buffer::Instance& read_buffer, Buffer::Instance& write_buffer)
      : read_buffer_(read_buffer), write_buffer_(write_buffer) {}
  virtual ~BufferIoHandle() = default;

  // Read operations
  Api::IoCallUint64Result readv(uint64_t, Buffer::RawSlice*, uint64_t) override {
    return {0, Api::IoError::none()};
  }
  Api::IoCallUint64Result read(Buffer::Instance& buffer,
                               absl::optional<uint64_t> max_length) override {
    uint64_t bytes_to_read = max_length.value_or(read_buffer_.length());
    if (bytes_to_read == 0) {
      return {0, Api::IoError::none()};
    }

    buffer.move(read_buffer_, std::min(bytes_to_read, read_buffer_.length()));
    return {bytes_to_read, Api::IoError::none()};
  }

  // Write operations
  Api::IoCallUint64Result writev(const Buffer::RawSlice*, uint64_t) override {
    return {0, Api::IoError::none()};
  }
  Api::IoCallUint64Result write(Buffer::Instance& buffer) override {
    uint64_t bytes_written = buffer.length();
    write_buffer_.move(buffer);
    return {bytes_written, Api::IoError::none()};
  }

  // no-op or minimal implementatio
  os_fd_t fdDoNotUse() const override { return INVALID_SOCKET; }
  Api::IoCallUint64Result close() override { return {0, Api::IoError::none()}; }
  bool isOpen() const override { return true; }
  bool wasConnected() const override { return true; }

  Api::IoCallUint64Result sendmsg(const Buffer::RawSlice*, uint64_t, int,
                                  const Network::Address::Ip*,
                                  const Network::Address::Instance&) override {
    return {uint64_t(-1), Network::IoSocketError::create(SOCKET_ERROR_NOT_SUP)};
  }
  Api::IoCallUint64Result recvmmsg(RawSliceArrays&, uint32_t,
                                   const Network::IoHandle::UdpSaveCmsgConfig&,
                                   Network::IoHandle::RecvMsgOutput&) override {
    return {uint64_t(-1), Network::IoSocketError::create(SOCKET_ERROR_NOT_SUP)};
  }
  Api::IoCallUint64Result recv(void*, size_t, int) override { return {-1, SOCKET_ERROR_NOT_SUP}; }

  bool supportsMmsg() const override { return false; }
  bool supportsUdpGro() const override { return false; }
  Api::SysCallIntResult bind(Network::Address::InstanceConstSharedPtr) override {
    return {-1, SOCKET_ERROR_NOT_SUP};
  };
  Api::SysCallIntResult listen(int) override {
    ENVOY_BUG(false, "unsupported call to listen");
    return {-1, SOCKET_ERROR_NOT_SUP};
  }
  std::unique_ptr<IoHandle> accept(struct sockaddr*, socklen_t*) override { return nullptr; };

  Api::SysCallIntResult connect(Network::Address::InstanceConstSharedPtr) override {
    ENVOY_BUG(false, "unsupported call to connect");
    return {-1, SOCKET_ERROR_NOT_SUP};
  };
  Api::SysCallIntResult setOption(int, int, const void*, socklen_t) override {
    return {-1, SOCKET_ERROR_NOT_SUP};
  }
  Api::SysCallIntResult getOption(int, int, void*, socklen_t*) override {
    return {-1, SOCKET_ERROR_NOT_SUP};
  };
  Api::SysCallIntResult ioctl(unsigned long, void*, unsigned long, void*, unsigned long,
                              unsigned long*) override {
    return {-1, SOCKET_ERROR_NOT_SUP};
  };
  Api::SysCallIntResult setBlocking(bool) override { return {-1, SOCKET_ERROR_NOT_SUP}; }

  absl::optional<int> domain() override { return absl::nullopt; };

  absl::StatusOr<Network::Address::InstanceConstSharedPtr> localAddress() override {
    CONSTRUCT_ON_FIRST_USE(Network::Address::InstanceConstSharedPtr,
                           std::make_shared<const Network::Address::EnvoyInternalInstance>(
                               "internal_address_for_user_space_io_handle"));
  }

  absl::StatusOr<Network::Address::InstanceConstSharedPtr> peerAddress() override {
    CONSTRUCT_ON_FIRST_USE(Network::Address::InstanceConstSharedPtr,
                           std::make_shared<const Network::Address::EnvoyInternalInstance>(
                               "internal_address_for_user_space_io_handle"));
  }

  Network::IoHandlePtr duplicate() override {
    // duplicate() is supposed to be used on listener io handle while this implementation doesn't
    // support listen.
    ENVOY_BUG(false, "unsupported call to duplicate");
    return nullptr;
  }

  void initializeFileEvent(Event::Dispatcher&, Event::FileReadyCb, Event::FileTriggerType,
                           uint32_t) override {
    ENVOY_BUG(false, "unsupported call to initializeFileEvent");
  };

  void activateFileEvents(uint32_t) override {
    ENVOY_BUG(false, "unsupported call to activateFileEvents");
  };

  void enableFileEvents(uint32_t) override {
    ENVOY_BUG(false, "unsupported call to enableFileEvents");
  }

  void resetFileEvents() override { ENVOY_BUG(false, "unsupported call to resetFileEvents"); }

  Api::SysCallIntResult shutdown(int) override { return {-1, SOCKET_ERROR_NOT_SUP}; }

  absl::optional<std::chrono::milliseconds> lastRoundTripTime() override { return absl::nullopt; }

  absl::optional<uint64_t> congestionWindowInBytes() const override { return absl::nullopt; }

  /**
   * @return the interface name for the socket, if the OS supports it. Otherwise, absl::nullopt.
   */
  absl::optional<std::string> interfaceName() override { return absl::nullopt; };

private:
  Buffer::Instance& read_buffer_;
  Buffer::Instance& write_buffer_;
};

} // namespace MssqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
