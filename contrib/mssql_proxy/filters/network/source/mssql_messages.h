#pragma once

#include <cstdint>
#include <vector>
#include <string>

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MssqlProxy {

/**
 * Base class for all TDS messages
 *
 * References
 *  https://github.com/denisenkom/go-mssqldb/blob/master/tds.go
 *    probably most recent and up to date reference..
 *  https://klonkers.blogspot.com/2015/01/making-something-useful-out-of-ms-tds.html
 *  https://www.freetds.org/tds.html
 *  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/9b4a463c-2634-4a4b-ac35-bebfff2fb0f7
 */
class MessageHeader {
public:
  constexpr static uint32_t HeaderLength = 8;
  constexpr static uint8_t MaxPacketType = 18;
  enum class PacketType : uint8_t {
    Query = 1,
    PreTds7Login = 2,
    Rpc = 3,
    Reply = 4,
    AttnSignal = 6,
    BulkLoad = 7,
    FedAuthToken = 8,
    TransManagerReq = 14, /* transaction management */
    Normal = 15,
    Login = 16,
    Sspi = 17,
    Prelogin = 18,
  };

  MessageHeader(const Buffer::Instance& data)
      : packet_type_(static_cast<PacketType>(data.peekInt<uint8_t>())),
        packet_status_(data.peekInt<uint8_t>(1)), packet_length_(data.peekBEInt<uint16_t>(2)),
        session_id_(data.peekBEInt<uint16_t>(4)), packet_id_(data.peekInt<uint8_t>(6)),
        window_(data.peekInt<uint8_t>(7)) {}

  PacketType packetType() const { return packet_type_; }
  uint8_t packetStatus() const { return packet_status_; }
  uint16_t packetLength() const { return packet_length_; }
  uint16_t sessionId() const { return session_id_; }
  uint8_t packetId() const { return packet_id_; }
  // window should always be 0x00
  uint8_t window() const { return window_; }

private:
  const PacketType packet_type_;
  const uint8_t packet_status_;
  const uint16_t packet_length_;
  const uint16_t session_id_;
  const uint8_t packet_id_;
  const uint8_t window_;
};

class Message {
public:
  Message(const Buffer::Instance& data) : header_(data) {}
  virtual ~Message() = default;

  MessageHeader header() const { return header_; }

  virtual std::string toString() const PURE;

private:
  MessageHeader header_;
};

class PreloginMessage : public virtual Message, Logger::Loggable<Logger::Id::filter> {
public:
  PreloginMessage(const Buffer::Instance& data) : Message(data), data_(data) {
    // Parse the Pre-login message
    uint16_t offset = MessageHeader::HeaderLength;
    while (offset < data.length()) {
      PreLoginOptionType type = static_cast<PreLoginOptionType>(data.peekInt<uint8_t>(offset));
      if (type == PreLoginOptionType::TERMINATOR) {
        break;
      }
      uint16_t option_offset = data.peekBEInt<uint16_t>(offset + 1);
      uint16_t option_length = data.peekBEInt<uint16_t>(offset + 3);
      options_.push_back({type, option_offset, option_length});
      offset += 5;
    }
  }

  enum class PreLoginOptionType : uint8_t {
    VERSION = 0x00,    // Client version
    ENCRYPTION = 0x01, // Encryption setting
    INSTOPT = 0x02,    // Instance options
    THREADID = 0x03,   // Client thread ID
    MARS = 0x04,       // Multiple active result sets (MARS)
    TRACEID = 0x05,    // Trace ID for diagnostics
    TERMINATOR = 0xFF  // End of options
  };

  enum class Encryption : uint8_t {
    NotSuppored = 0x00,
    EncryptionOff = 0x01,
    EncryptionOn = 0x02,
    ClientNegotionRequired = 0x03,
  };

  // Structure for a single Pre-login option
  struct PreLoginOption {
    PreLoginOptionType type; // Option type
    uint16_t offset;         // Offset from the start of the message
    uint16_t length;         // Length of the option data
  };

#pragma pack(push, 1)
  struct Version {
    uint8_t major;
    uint8_t minor;
    uint16_t build;
  };
#pragma pack(pop)

  PreLoginOption option(PreLoginOptionType type) const {
    for (const auto& option : options_) {
      if (option.type == type) {
        return option;
      }
    }
    return {PreLoginOptionType::TERMINATOR, 0, 0};
  }

  Version version() const {
    for (const auto& option : options_) {
      if (option.type == PreLoginOptionType::VERSION) {
        Version version;
        data_.copyOut(option.offset + MessageHeader::HeaderLength, sizeof(Version), &version);
        return version;
      }
    }
    return {};
  }

  uint8_t encryption() const {
    for (const auto& option : options_) {
      if (option.type == PreLoginOptionType::ENCRYPTION) {
        return data_.peekInt<uint8_t>(option.offset + MessageHeader::HeaderLength);
      }
    }
    return 0;
  }

  bool mars() const {
    for (const auto& option : options_) {
      if (option.type == PreLoginOptionType::MARS) {
        return data_.peekInt<uint8_t>(option.offset) == 1;
      }
    }
    return false;
  }

  std::string toString() const override {
    Version v = version();
    return fmt::format(
        "PreloginMessage: packet_type={}, major={}, minor={}, build={}, encryption={}, mars={}",
        static_cast<uint8_t>(header().packetType()), v.major, v.minor, v.build, encryption(),
        mars());
  }

private:
  std::vector<PreLoginOption> options_;
  const Buffer::Instance& data_;
};

class LoginMessage : public virtual Message, Logger::Loggable<Logger::Id::filter> {
public:
  LoginMessage(const Buffer::Instance& data) : Message(data) {
    size_t offset = MessageHeader::HeaderLength;
    data.copyOut(MessageHeader::HeaderLength, sizeof(LoginHeader), &header_);

    char buffer[4096];
    // TODO: check if it is safe to blindly multiple length by 2
    // https://github.com/microsoft/go-mssqldb/blob/dad23d2a2b931673360a00d3810ceaea061fb4b0/tds.go#L532
    if (header_.clientname_length > 0) {
      data.copyOut(offset + header_.clientname_offset, header_.clientname_length * 2, buffer);
      clientname_ = std::string(buffer, header_.clientname_length * 2);
    }

    if (header_.username_length > 0) {
      data.copyOut(offset + header_.username_offset, header_.username_length * 2, buffer);
      username_ = std::string(buffer, header_.username_length * 2);
    }

    if (header_.password_length > 0) {
      data.copyOut(offset + header_.password_offset, header_.password_length * 2, buffer);
      password_ = std::string(buffer, header_.password_length * 2);
    }

    if (header_.app_name_length > 0) {
      data.copyOut(offset + header_.app_name_offset, header_.app_name_length * 2, buffer);
      app_name_ = std::string(buffer, header_.app_name_length * 2);
    }

    if (header_.server_name_length > 0) {
      data.copyOut(offset + header_.server_name_offset, header_.server_name_length * 2, buffer);
      server_name_ = std::string(buffer, header_.server_name_length * 2);
    }

    if (header_.library_name_length > 0) {
      data.copyOut(offset + header_.library_name_offset, header_.library_name_length * 2, buffer);
      library_name_ = std::string(buffer, header_.library_name_length * 2);
    }

    if (header_.database_length > 0) {
      data.copyOut(offset + header_.database_offset, header_.database_length * 2, buffer);
      database_ = std::string(buffer, header_.database_length * 2);
    }

    if (header_.sspi_length > 0) {
      data.copyOut(offset + header_.sspi_offset, header_.sspi_length, buffer);
      sspi_.add(buffer, header_.sspi_length);
    }

    authenticate();
  }

#pragma pack(push, 1)
  struct LoginHeader {
    uint32_t length;
    uint32_t tds_version;
    uint32_t packet_size;
    uint32_t client_program_version;
    uint32_t client_pid;
    uint32_t connection_id;
    uint8_t option_flags1;
    uint8_t option_flags2;
    uint8_t sql_type_flags;
    uint8_t reserved_flags;
    int32_t client_time_zone_;
    uint32_t client_lcid_;

    uint16_t clientname_offset;
    uint16_t clientname_length;
    uint16_t username_offset;
    uint16_t username_length;
    uint16_t password_offset;
    uint16_t password_length;
    uint16_t app_name_offset;
    uint16_t app_name_length;
    uint16_t server_name_offset;
    uint16_t server_name_length;
    uint16_t extension_offset;
    uint16_t extension_length;
    uint16_t library_name_offset;
    uint16_t library_name_length;
    uint16_t language_offset;
    uint16_t language_length;
    uint16_t database_offset;
    uint16_t database_length;

    uint8_t client_id[6];
    uint16_t sspi_offset;
    uint16_t sspi_length;
    uint16_t atchdbfile_offset;
    uint16_t atchdbfile_length;
    uint16_t change_password_offset;
    uint16_t change_password_length;
    uint32_t sspi_long_length;

    std::string toString() const {
      return fmt::format(
          "LoginHeader: length={}, tds_version=0x{:08x}, packet_size=0x{:08x}, "
          "client_program_version=0x{:08x}, "
          "client_pid={}, "
          "connection_id={}, option_flags1={}, option_flags2={}, sql_type_flags={}, "
          "reserved_flags={}, client_time_zone_={}, client_lcid_={}, clientname_offset={}, "
          "clientname_length={}, username_offset={}, username_length={}, password_offset={}, "
          "password_length={}, app_name_offset={}, app_name_length={}, server_name_offset={}, "
          "server_name_length={}, extension_offset={}, extension_length={}, "
          "library_name_offset={}, "
          "library_name_length={}, language_offset={}, language_length={}, database_offset={}, "
          "database_length={}, sspi_offset={}, sspi_length={}, atchdbfile_offset={}, "
          "atchdbfile_length={}, change_password_offset={}, change_password_length={}, "
          "sspi_long_length={}",
          length, tds_version, packet_size, client_program_version, client_pid, connection_id,
          option_flags1, option_flags2, sql_type_flags, reserved_flags, client_time_zone_,
          client_lcid_, clientname_offset, clientname_length, username_offset, username_length,
          password_offset, password_length, app_name_offset, app_name_length, server_name_offset,
          server_name_length, extension_offset, extension_length, library_name_offset,
          library_name_length, language_offset, language_length, database_offset, database_length,
          sspi_offset, sspi_length, atchdbfile_offset, atchdbfile_length, change_password_offset,
          change_password_length, sspi_long_length);
    }
  };
#pragma pack(pop)

  std::string toString() const override {
    return fmt::format("LoginMessage: packet_type={}, packet_status={}, header=({}), username={}, "
                       "servername={}, database={}",
                       static_cast<uint8_t>(header().packetType()), header().packetStatus(),
                       header_.toString(), username_, server_name_, database_);
  }

private:
  LoginHeader header_;
  std::string clientname_;
  std::string username_;
  std::string password_;
  std::string app_name_;
  std::string server_name_;
  std::string library_name_;
  std::string database_;
  Buffer::OwnedImpl sspi_;

  void authenticate();
};

} // namespace MssqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy