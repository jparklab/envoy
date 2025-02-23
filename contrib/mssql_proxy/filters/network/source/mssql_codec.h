#pragma once

#include <cstdint>
#include <vector>
#include <string>

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"

// for ssl
#include "openssl/md5.h"
#include "openssl/ssl.h"

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
class Message {};

class PreloginMessage : public Message {};

class LoginMessage : public Message {};

class DecoderCallbacks {
public:
  virtual ~DecoderCallbacks() = default;
};

class Decoder : Logger::Loggable<Logger::Id::filter> {};

} // namespace MssqlProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
