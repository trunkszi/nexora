#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <new>
#include <nexora/error/runtime_error.hpp>
#include <nexora/pool/endpoint_failover.hpp>
#include <nexora/socket/socket_word.hpp>

namespace nexora::detail {
struct ProbeState {
  std::uint64_t socket_raw{0};
  std::uint64_t now_ns{0};
  std::array<std::uint8_t, 9> frame{};
  std::array<std::uint8_t, 16> payload{};
  std::array<std::uint8_t, 4> mask{};
  alignas(EndpointFailover<>) std::array<std::byte, sizeof(EndpointFailover<>)> pool_storage{};
  bool pool_initialized{false};

  [[nodiscard]] void* PoolStorage() noexcept { return pool_storage.data(); }
  [[nodiscard]] EndpointFailover<>& Pool() noexcept { return *std::launder(static_cast<EndpointFailover<>*>(PoolStorage())); }
};
[[nodiscard]] ProbeState& MutableProbeState() noexcept;
}  // namespace nexora::detail
