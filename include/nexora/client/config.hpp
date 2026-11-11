#pragma once
#include <cstddef>
#include <cstdint>
#include <nexora/pool/origin_pool.hpp>
#include <nexora/tls/tls_config.hpp>
#include <string>

namespace nexora {
struct ClientConfig {
  PoolConfig pool{};
  std::uint32_t connect_timeout_ms{10000};
  std::uint32_t default_timeout_ms{30000};
  std::uint32_t max_redirects{5};
  std::size_t max_body_size{16384};
  std::size_t max_request_body_size{16384};
  bool follow_redirects{true};
  bool prefer_http2{true};
  bool enable_tls{true};
  bool http2_prior_knowledge{false};
  const TlsClientConfig* tls_config{nullptr};
  std::string tls_server_name{};
};
}  // namespace nexora
