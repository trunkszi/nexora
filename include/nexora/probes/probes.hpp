#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <nexora/probes/detail/state.hpp>

namespace nexora {
inline void ResetProbeState(std::uint64_t seed) noexcept {
  auto& state = detail::MutableProbeState();
  state.socket_raw = SocketWord::OpenWord().WithInFlight(static_cast<std::uint32_t>(seed & 0xffffU)).Raw();
  state.now_ns = seed;
  state.frame = {0, 0, static_cast<std::uint8_t>(seed), 0, 1, 0, 0, 0, 1};
  for (std::size_t i = 0; i < state.payload.size(); ++i) state.payload[i] = static_cast<std::uint8_t>(seed + i);
  state.mask = {static_cast<std::uint8_t>(seed), 0x37, 0x81, 0xab};
  if (state.pool_initialized) std::destroy_at(std::addressof(state.Pool()));
  std::construct_at(static_cast<EndpointFailover<>*>(state.PoolStorage()));
  state.pool_initialized = true;
  std::array<cares::Endpoint, 16> endpoints{};
  for (std::size_t i = 0; i < endpoints.size(); ++i)
    endpoints[i] = {cares::IpAddress::FromV4HostOrder(0x7f000001U), static_cast<std::uint16_t>(8000 + i)};
  state.Pool().Reset(endpoints);
}
}  // namespace nexora

extern "C" {
/// @pre nexora::ResetProbeState() has completed; the fixture is single-threaded.
[[nodiscard]] std::uint64_t nexora_probe_socket_step() noexcept;
/// @pre nexora::ResetProbeState() has completed.
[[nodiscard]] std::uint64_t nexora_probe_h2_frame_header() noexcept;
/// @pre nexora::ResetProbeState() has completed.
[[nodiscard]] std::uint64_t nexora_probe_ws_mask() noexcept;
/// @pre nexora::ResetProbeState() has completed.
[[nodiscard]] std::uint64_t nexora_probe_pool_select() noexcept;
}
