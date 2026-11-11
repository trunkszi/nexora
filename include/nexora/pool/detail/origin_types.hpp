#pragma once

#include <cares/cares.hpp>
#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <nexora/http/message.hpp>
#include <nexora/http/uri.hpp>
#include <nexora/pool/endpoint_failover.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <uarch/uarch.hpp>
#include <utility>
#include <vector>

namespace nexora {

struct OriginKey {
  Scheme scheme{Scheme::kHttp};
  std::string host{};
  std::uint16_t port{80};

  OriginKey() noexcept = default;
  OriginKey(Scheme s, std::string_view raw_host, std::uint16_t p) noexcept
      : scheme(s), host(NormalizeHost(raw_host)), port(p) {}

  [[nodiscard]] static OriginKey Create(Scheme s, std::string_view raw_host, std::uint16_t p) noexcept {
    return OriginKey{s, raw_host, p};
  }
  [[nodiscard]] static OriginKey FromUri(const Uri& uri) noexcept {
    return OriginKey{uri.Scheme(), uri.Host(), uri.EffectivePort()};
  }

  [[nodiscard]] std::string Authority() const noexcept {
    const bool ipv6 = host.contains(':');
    std::string formatted_host = ipv6 ? ("[" + host + "]") : host;
    if (port == SchemeDefaultPort(scheme)) return formatted_host;
    formatted_host.push_back(':');
    formatted_host.append(detail::FormatDecimalU16(port));
    return formatted_host;
  }

  [[nodiscard]] friend bool operator==(const OriginKey& a, const OriginKey& b) noexcept {
    return a.scheme == b.scheme && a.port == b.port && a.host == b.host;
  }
  [[nodiscard]] friend auto operator<=>(const OriginKey& a, const OriginKey& b) noexcept {
    if (auto cmp = a.scheme <=> b.scheme; cmp != 0) return cmp;
    if (auto cmp = a.port <=> b.port; cmp != 0) return cmp;
    return a.host <=> b.host;
  }

 private:
  [[nodiscard]] static std::string NormalizeHost(std::string_view raw) noexcept {
    std::string_view trimmed = raw;
    if (trimmed.size() >= 2 && trimmed.front() == '[' && trimmed.back() == ']') {
      trimmed = trimmed.substr(1, trimmed.size() - 2);
    }
    while (!trimmed.empty() && trimmed.back() == '.') trimmed.remove_suffix(1);
    return AsciiLowerCopy(trimmed);
  }
};

struct PoolConfig {
  std::size_t max_connections_per_origin{6};
  std::size_t max_idle_per_origin{6};
  std::uint64_t idle_timeout_ns{60'000'000'000ULL};
  std::uint64_t max_lifetime_ns{300'000'000'000ULL};
  std::uint32_t max_streams_per_h2_connection{100};
  std::chrono::milliseconds idle_timeout{60000};
  std::chrono::milliseconds max_lifetime{300000};
  std::uint32_t max_concurrent_streams_per_h2{100};
  std::uint64_t endpoint_base_cooldown_ns{1'000'000'000ULL};
  std::uint64_t endpoint_max_cooldown_ns{30'000'000'000ULL};

  [[nodiscard]] constexpr std::chrono::nanoseconds EffectiveIdleTimeout() const noexcept {
    if (idle_timeout != std::chrono::milliseconds{60000}) {
      return std::chrono::duration_cast<std::chrono::nanoseconds>(idle_timeout);
    }
    return std::chrono::nanoseconds{idle_timeout_ns};
  }
  [[nodiscard]] constexpr std::chrono::nanoseconds EffectiveMaxLifetime() const noexcept {
    if (max_lifetime != std::chrono::milliseconds{300000}) {
      return std::chrono::duration_cast<std::chrono::nanoseconds>(max_lifetime);
    }
    return std::chrono::nanoseconds{max_lifetime_ns};
  }
  [[nodiscard]] constexpr std::uint32_t EffectiveMaxH2Streams() const noexcept {
    return (max_streams_per_h2_connection != 100U) ? max_streams_per_h2_connection : max_concurrent_streams_per_h2;
  }
};

enum class OriginSuperstate : std::uint8_t {
  kInactive = 0,
  kEstablishing = 1,
  kActive = 2,
  kTeardown = 3,
};

enum class OriginState : std::uint8_t {
  kIdle = 0,
  kResolvingDns = 1,
  kConnecting = 2,
  kHandshaking = 3,
  kReadyHttp1 = 4,
  kReadyHttp2 = 5,
  kDraining = 6,
  kClosed = 7,
};

[[nodiscard]] constexpr OriginSuperstate OriginSuperstateOf(OriginState state) noexcept {
  switch (state) {
    case OriginState::kIdle:
    case OriginState::kClosed:
      return OriginSuperstate::kInactive;
    case OriginState::kResolvingDns:
    case OriginState::kConnecting:
    case OriginState::kHandshaking:
      return OriginSuperstate::kEstablishing;
    case OriginState::kReadyHttp1:
    case OriginState::kReadyHttp2:
      return OriginSuperstate::kActive;
    case OriginState::kDraining:
      return OriginSuperstate::kTeardown;
  }
  return OriginSuperstate::kInactive;
}

[[nodiscard]] constexpr std::uint8_t OriginAllowedNextMask(OriginState state) noexcept {
  constexpr auto bit = [](OriginState s) consteval noexcept -> std::uint8_t {
    return static_cast<std::uint8_t>(1U << std::to_underlying(s));
  };
  switch (state) {
    case OriginState::kIdle:
      return bit(OriginState::kResolvingDns) | bit(OriginState::kConnecting) | bit(OriginState::kReadyHttp1) |
             bit(OriginState::kReadyHttp2) | bit(OriginState::kDraining) | bit(OriginState::kClosed);
    case OriginState::kResolvingDns:
      return bit(OriginState::kIdle) | bit(OriginState::kConnecting) | bit(OriginState::kDraining) | bit(OriginState::kClosed);
    case OriginState::kConnecting:
      return bit(OriginState::kResolvingDns) | bit(OriginState::kConnecting) | bit(OriginState::kHandshaking) |
             bit(OriginState::kReadyHttp1) | bit(OriginState::kReadyHttp2) | bit(OriginState::kIdle) |
             bit(OriginState::kDraining) | bit(OriginState::kClosed);
    case OriginState::kHandshaking:
      return bit(OriginState::kConnecting) | bit(OriginState::kReadyHttp1) | bit(OriginState::kReadyHttp2) |
             bit(OriginState::kIdle) | bit(OriginState::kDraining) | bit(OriginState::kClosed);
    case OriginState::kReadyHttp1:
      return bit(OriginState::kResolvingDns) | bit(OriginState::kConnecting) | bit(OriginState::kReadyHttp1) |
             bit(OriginState::kIdle) | bit(OriginState::kDraining) | bit(OriginState::kClosed);
    case OriginState::kReadyHttp2:
      return bit(OriginState::kResolvingDns) | bit(OriginState::kConnecting) | bit(OriginState::kReadyHttp2) |
             bit(OriginState::kIdle) | bit(OriginState::kDraining) | bit(OriginState::kClosed);
    case OriginState::kDraining:
    case OriginState::kClosed:
      return bit(OriginState::kIdle) | bit(OriginState::kClosed);
  }
  return 0;
}

[[nodiscard]] constexpr bool CanTransitionOriginState(OriginState from, OriginState to) noexcept {
  const auto bit = static_cast<std::uint8_t>(1U << std::to_underlying(to));
  return (OriginAllowedNextMask(from) & bit) != 0;
}

struct PooledConnection {
  std::uint64_t connection_id{0};
  Version version{Version::kHttp11};
  bool busy{false};
  std::uint32_t active_streams{0};
  std::uint32_t max_concurrent_streams{100};
  std::chrono::steady_clock::time_point created_at{std::chrono::steady_clock::now()};
  std::chrono::steady_clock::time_point last_used_at{std::chrono::steady_clock::now()};
};

struct WaiterRemoval {
  bool removed{false};
  std::optional<OriginState> state{};
  std::vector<cares::QueryHandle> dns_handles{};
};

struct OriginEntry {
  OriginKey origin{};
  OriginState state{OriginState::kIdle};
  std::vector<cares::QueryHandle> dns_handles{};
  EndpointFailover<16> failover{};
  std::optional<std::uint64_t> active_connect{};
  std::vector<std::uint64_t> waiters{};
  std::vector<PooledConnection> connections{};

  OriginEntry() noexcept = default;
  explicit OriginEntry(OriginKey key) noexcept : origin(std::move(key)) {}

  [[nodiscard]] constexpr OriginSuperstate Superstate() const noexcept { return OriginSuperstateOf(state); }
  [[nodiscard]] constexpr bool CanTransitionTo(OriginState next) const noexcept {
    return CanTransitionOriginState(state, next);
  }
  constexpr bool TransitionTo(OriginState next) noexcept {
    if (!CanTransitionTo(next)) return false;
    state = next;
    return true;
  }
  [[nodiscard]] bool IsEvictable() const noexcept {
    return state == OriginState::kIdle && connections.empty() && waiters.empty() && !active_connect.has_value() &&
           dns_handles.empty();
  }
};

struct PoolSlotToken {
  using Word = std::uint64_t;
  std::uint16_t slot[[= uarch::bits::Field{0, 16}]] = 0;
  std::uint16_t generation[[= uarch::bits::Field{16, 16}]] = 0;
  std::uint32_t lease[[= uarch::bits::Field{32, 32}]] = 0;
  constexpr bool operator==(const PoolSlotToken&) const noexcept = default;
};
static_assert(uarch::NoPadding<PoolSlotToken> && uarch::RegisterPassable<PoolSlotToken>);

}  // namespace nexora
