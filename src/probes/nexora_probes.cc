#include <cstring>
#include <limits>
#include <nexora/error/runtime_error.hpp>
#include <nexora/http2/frame.hpp>
#include <nexora/probes/probes.hpp>
#include <nexora/websocket/codec.hpp>

namespace nexora::detail {
constinit static ProbeState g_probe_state{};
ProbeState& MutableProbeState() noexcept { return g_probe_state; }
}  // namespace nexora::detail
extern "C" std::uint64_t nexora_probe_socket_step() noexcept {
  auto& state = nexora::detail::g_probe_state;
  state.socket_raw = nexora::SocketWord::FromRaw(state.socket_raw).BeginOp().Raw();
  return state.socket_raw;
}
extern "C" std::uint64_t nexora_probe_h2_frame_header() noexcept {
  const auto header = nexora::DecodeFrameHeader(nexora::detail::g_probe_state.frame);
  return header ? std::uint64_t{header->length} + header->stream_id + header->flags : 0;
}
extern "C" std::uint64_t nexora_probe_ws_mask() noexcept {
  auto& state = nexora::detail::g_probe_state;
  nexora::ApplyWebSocketMask(state.payload, state.mask);
  std::uint64_t result = 0;
  std::memcpy(&result, state.payload.data(), sizeof(result));
  return result;
}
extern "C" std::uint64_t nexora_probe_pool_select() noexcept {
  auto& state = nexora::detail::g_probe_state;
  const auto selected = state.Pool().SelectNext<nexora::EndpointSelectionPolicy::kRoundRobin>(state.now_ns);
  return selected ? *selected : std::numeric_limits<std::uint64_t>::max();
}
