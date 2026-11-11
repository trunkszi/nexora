#pragma once

#include <cstddef>
#include <cstdint>
#include <nexora/bytes/bytes.hpp>
#include <nexora/http2/connection.hpp>
#include <span>

namespace nexora::detail {

static_assert(requires(const nexora::Http2Event& ev) { ev.flow_control_bytes; });

[[nodiscard]] constexpr std::size_t EventFlowControlBytes(const auto& ev) noexcept {
  if constexpr (requires { ev.flow_control_bytes; }) {
    if (ev.flow_control_bytes != 0) return static_cast<std::size_t>(ev.flow_control_bytes);
  }
  if constexpr (requires { ev.Payload(); }) {
    return ev.Payload().size();
  } else {
    return ev.data.size();
  }
}

template <typename Conn>
void ReplenishConnectionWindow(Conn& conn, std::uint32_t& tracked, bool force, std::uint32_t half) noexcept {
  if constexpr (requires(const Conn& probe) { probe.ConnectionRecvWindow(); }) {
    const auto window = conn.ConnectionRecvWindow();
    using Window = decltype(window);
    std::uint32_t credit = 0;
    if (window < static_cast<Window>(half)) credit = static_cast<std::uint32_t>(static_cast<Window>(half) - window);
    if ((force || tracked >= half) && tracked > credit) credit = tracked;
    if (credit != 0 && conn.SubmitWindowUpdate(0, credit)) tracked = 0;
    return;
  }
  if (tracked > 0 && (force || tracked >= half)) {
    if (conn.SubmitWindowUpdate(0, tracked)) tracked = 0;
  }
}

template <std::size_t StagingCap, typename StepFn>
[[nodiscard]] Result<void> DrainHttp2Ingress(Http2Connection& conn, BytesMut<StagingCap>& staged,
                                             std::span<const std::uint8_t> incoming, StepFn&& step) noexcept {
  if (!staged.Empty() && !incoming.empty()) {
    if (auto appended = staged.Append(incoming); !appended) return appended;
    incoming = {};
  }
  std::span<const std::uint8_t> remaining = incoming;
  for (;;) {
    const bool from_staged = !staged.Empty();
    const std::span<const std::uint8_t> chunk = from_staged ? staged.ReadableSpan() : remaining;
    if (chunk.empty() && !conn.IsIngressPaused() && !conn.PeekEventView().has_value()) {
      return step();
    }
    const std::size_t out_before = conn.PendingOutput().size();
    const bool had_events = conn.PeekEventView().has_value();
    const Http2Read fed = conn.FeedBytes(chunk);
    if (!fed.Ok()) return std::unexpected(fed.ErrorValue());
    if (fed.Consumed() != 0) {
      if (from_staged)
        staged.Consume(fed.Consumed());
      else
        remaining = remaining.subspan(fed.Consumed());
    }
    const bool has_events = had_events || conn.PeekEventView().has_value();
    if (auto stepped = step(); !stepped) return stepped;
    const bool all_accepted = staged.Empty() && remaining.empty() && !conn.IsIngressPaused();
    if (all_accepted && !conn.PeekEventView().has_value()) return {};
    const bool progressed = (fed.Consumed() != 0) || (has_events && !conn.PeekEventView().has_value()) ||
                            (conn.PendingOutput().size() != out_before);
    if (!progressed) {
      if (conn.PendingOutput().empty()) return std::unexpected(Error::BufferOverflow());
      if (!remaining.empty()) {
        if (auto appended = staged.Append(remaining); !appended) return appended;
      }
      return {};
    }
  }
}

}  // namespace nexora::detail
