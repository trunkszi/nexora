#pragma once

#include <cstdint>

namespace nexora {

/// Application protocol offered or selected during TLS ALPN.
enum class AlpnProtocol : std::uint8_t {
  kNone = 0,  ///< No protocol was negotiated.
  kHttp11,    ///< HTTP/1.1 (`http/1.1`).
  kHttp2,     ///< HTTP/2 (`h2`).
};

}  // namespace nexora
