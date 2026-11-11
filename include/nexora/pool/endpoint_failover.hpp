#pragma once

#include <algorithm>
#include <array>
#include <cares/cares.hpp>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <nexora/error/runtime_error.hpp>
#include <optional>
#include <span>
#include <type_traits>
#include <uarch/uarch.hpp>
#include <utility>

namespace nexora {

namespace detail {

template <std::size_t InlineBytes, typename R, typename... Args>
class alignas(16) InplaceDelegateImpl {
  struct Ops {
    R (*invoke)(void* storage, Args... args) noexcept;
    void (*copy_to)(const void* src, void* dst) noexcept;
    void (*move_to)(void* src, void* dst) noexcept;
    void (*destroy)(void* storage) noexcept;
  };
  alignas(16) mutable std::array<std::byte, InlineBytes> storage_{};
  const Ops* ops_{nullptr};

 public:
  constexpr InplaceDelegateImpl() noexcept = default;
  constexpr InplaceDelegateImpl(std::nullptr_t) noexcept {}

  template <typename F>
    requires(!std::same_as<std::decay_t<F>, InplaceDelegateImpl> && std::copy_constructible<std::decay_t<F>> &&
             std::is_nothrow_invocable_r_v<R, std::decay_t<F>&, Args...>)
  InplaceDelegateImpl(F&& fn) noexcept {
    using Decayed = std::decay_t<F>;
    static_assert(sizeof(Decayed) <= InlineBytes && alignof(Decayed) <= 16);
    static constexpr Ops ops{
        .invoke = +[](void* ptr, Args... call_args) noexcept -> R {
          return (*std::launder(static_cast<Decayed*>(ptr)))(std::forward<Args>(call_args)...);
        },
        .copy_to =
            +[](const void* src, void* dst) noexcept {
              std::construct_at(static_cast<Decayed*>(dst), *std::launder(static_cast<const Decayed*>(src)));
            },
        .move_to =
            +[](void* src, void* dst) noexcept {
              auto* s = std::launder(static_cast<Decayed*>(src));
              std::construct_at(static_cast<Decayed*>(dst), std::move(*s));
              std::destroy_at(s);
            },
        .destroy = +[](void* ptr) noexcept { std::destroy_at(std::launder(static_cast<Decayed*>(ptr))); },
    };
    void* dst = storage_.data();
    std::construct_at(static_cast<Decayed*>(dst), std::forward<F>(fn));
    ops_ = &ops;
  }

  constexpr InplaceDelegateImpl(const InplaceDelegateImpl& other) noexcept {
    if (other.ops_ != nullptr) {
      other.ops_->copy_to(other.storage_.data(), storage_.data());
      ops_ = other.ops_;
    }
  }

  constexpr InplaceDelegateImpl& operator=(const InplaceDelegateImpl& other) noexcept {
    if (this != &other) {
      Reset();
      if (other.ops_ != nullptr) {
        other.ops_->copy_to(other.storage_.data(), storage_.data());
        ops_ = other.ops_;
      }
    }
    return *this;
  }

  constexpr InplaceDelegateImpl(InplaceDelegateImpl&& other) noexcept {
    if (other.ops_ != nullptr) {
      other.ops_->move_to(other.storage_.data(), storage_.data());
      ops_ = std::exchange(other.ops_, nullptr);
    }
  }

  constexpr InplaceDelegateImpl& operator=(InplaceDelegateImpl&& other) noexcept {
    if (this != &other) {
      Reset();
      if (other.ops_ != nullptr) {
        other.ops_->move_to(other.storage_.data(), storage_.data());
        ops_ = std::exchange(other.ops_, nullptr);
      }
    }
    return *this;
  }

  constexpr ~InplaceDelegateImpl() noexcept { Reset(); }

  constexpr void Reset() noexcept {
    if (ops_ != nullptr) {
      std::exchange(ops_, nullptr)->destroy(storage_.data());
    }
  }

  [[nodiscard]] constexpr explicit operator bool() const noexcept { return ops_ != nullptr; }
  [[nodiscard]] constexpr bool HasValue() const noexcept { return ops_ != nullptr; }

  constexpr R operator()(Args... args) const noexcept { return ops_->invoke(storage_.data(), std::forward<Args>(args)...); }
};

}  // namespace detail

template <typename Signature, std::size_t InlineBytes = 48>
class InplaceDelegate;

template <typename R, typename... Args, std::size_t InlineBytes>
class InplaceDelegate<R(Args...) noexcept, InlineBytes> : public detail::InplaceDelegateImpl<InlineBytes, R, Args...> {
  using Base = detail::InplaceDelegateImpl<InlineBytes, R, Args...>;

 public:
  using Base::Base;
};

template <typename R, typename... Args, std::size_t InlineBytes>
class InplaceDelegate<R(Args...), InlineBytes> : public detail::InplaceDelegateImpl<InlineBytes, R, Args...> {
  using Base = detail::InplaceDelegateImpl<InlineBytes, R, Args...>;

 public:
  using Base::Base;
};

enum class EndpointSelectionPolicy : std::uint8_t {
  kRoundRobin = 0,
  kPickFirst = 1,
  kSticky = 2,
  kLatencyAware = 3,
  kRandom = 4,
};

enum class FailoverEventKind : std::uint8_t {
  kQuarantined = 0,
  kRecovered = 1,
  kSwitched = 2,
};

struct FailoverEvent {
  FailoverEventKind kind{FailoverEventKind::kQuarantined};
  std::size_t endpoint_index{0};
  cares::Endpoint endpoint{};
  std::uint32_t consecutive_failures{0};
  std::uint64_t quarantined_until_ns{0};
};

[[nodiscard]] constexpr bool ShouldFailoverWrite(bool bytes_sent_on_wire, bool idempotent) noexcept {
  return !bytes_sent_on_wire && idempotent;
}

struct EndpointFailoverConfig {
  std::uint32_t failure_threshold{1};
  std::uint64_t base_cooldown_ns{1'000'000'000ULL};
  std::uint64_t max_cooldown_ns{30'000'000'000ULL};
  EndpointSelectionPolicy policy{EndpointSelectionPolicy::kRoundRobin};
  std::uint64_t random_seed{0x9E3779B97F4A7C15ULL};
  InplaceDelegate<void(const FailoverEvent&) noexcept> observer{};
};

template <std::size_t MaxEndpoints = 16>
class EndpointFailover {
  static_assert(MaxEndpoints > 0 && MaxEndpoints <= 64, "MaxEndpoints must fit in uarch::Bitmap64");

  std::array<cares::Endpoint, MaxEndpoints> endpoints_{};
  std::array<std::uint64_t, MaxEndpoints> quarantined_until_ns_{};
  std::array<std::uint64_t, MaxEndpoints> ewma_rtt_ns_{};
  std::array<std::uint32_t, MaxEndpoints> failure_counts_{};
  uarch::Bitmap64 healthy_bits_{uarch::Bitmap64::empty()};
  uarch::Bitmap64 ready_bits_{uarch::Bitmap64::empty()};
  uarch::Bitmap64 configured_bits_{uarch::Bitmap64::empty()};
  std::uint32_t count_{0};
  std::uint32_t cursor_{0};
  std::uint64_t rng_state_{0x9E3779B97F4A7C15ULL};
  uarch::FastDivisorU32 divisor_{uarch::arithmetic::divisor_u32<1>()};
  EndpointFailoverConfig config_{};

  constexpr void EmitEvent(FailoverEventKind kind, std::size_t index) const noexcept {
    if (config_.observer) {
      config_.observer(FailoverEvent{
          .kind = kind,
          .endpoint_index = index,
          .endpoint = endpoints_[index],
          .consecutive_failures = failure_counts_[index],
          .quarantined_until_ns = quarantined_until_ns_[index],
      });
    }
  }

  [[nodiscard]] constexpr std::uint64_t NextRandomU64() noexcept {
    rng_state_ += 0x9E3779B97F4A7C15ULL;
    std::uint64_t z = rng_state_;
    z = (z ^ (z >> 30U)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27U)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31U);
  }

  template <bool Notify = true>
  constexpr void RecoverExpired(std::uint64_t now_ns) noexcept {
    uarch::Bitmap64 quarantined = configured_bits_.difference(healthy_bits_);
    while (auto bit = quarantined.pop_lowest_one()) {
      const std::uint32_t idx = *bit;
      if (now_ns >= quarantined_until_ns_[idx]) {
        quarantined_until_ns_[idx] = 0;
        healthy_bits_ = healthy_bits_.set(idx);
        if constexpr (Notify) EmitEvent(FailoverEventKind::kRecovered, idx);
      }
    }
  }

  [[nodiscard]] constexpr std::size_t AdvanceRoundRobin(uarch::Bitmap64 candidates) noexcept {
    auto candidate = candidates.next_one_from(cursor_);
    if (!candidate) candidate = candidates.lowest_one();
    const std::uint32_t chosen = *candidate;
    cursor_ = divisor_.rem(chosen + 1U);
    return chosen;
  }

 public:
  constexpr EndpointFailover() noexcept = default;

  constexpr explicit EndpointFailover(std::uint64_t cooldown_ns, std::uint32_t failure_threshold = 2) noexcept
      : config_{
            .failure_threshold = (failure_threshold == 0 ? 1U : failure_threshold),
            .base_cooldown_ns = cooldown_ns,
            .max_cooldown_ns = std::max<std::uint64_t>(cooldown_ns, 30'000'000'000ULL),
        } {}

  explicit constexpr EndpointFailover(EndpointFailoverConfig config) noexcept
      : rng_state_(config.random_seed == 0 ? 0x9E3779B97F4A7C15ULL : config.random_seed), config_(std::move(config)) {
    if (config_.failure_threshold == 0) {
      config_.failure_threshold = 1;
    }
  }

  constexpr EndpointFailover(std::span<const cares::Endpoint> endpoints, EndpointFailoverConfig config = {}) noexcept
      : EndpointFailover(std::move(config)) {
    Reset(endpoints);
  }

  constexpr void Reset(std::span<const cares::Endpoint> endpoints) noexcept {
    const std::size_t n = std::min(endpoints.size(), MaxEndpoints);
    healthy_bits_ = uarch::Bitmap64::empty();
    configured_bits_ = uarch::Bitmap64::empty();
    for (std::size_t i = 0; i < n; ++i) {
      endpoints_[i] = endpoints[i];
      quarantined_until_ns_[i] = 0;
      ewma_rtt_ns_[i] = 0;
      failure_counts_[i] = 0;
      const auto bit = static_cast<std::uint32_t>(i);
      healthy_bits_ = healthy_bits_.set(bit);
      configured_bits_ = configured_bits_.set(bit);
    }
    ready_bits_ = configured_bits_;
    count_ = static_cast<std::uint32_t>(n);
    cursor_ = 0;
    rng_state_ = (config_.random_seed == 0) ? 0x9E3779B97F4A7C15ULL : config_.random_seed;
    divisor_ = *uarch::FastDivisorU32::try_new(count_ == 0 ? 1U : count_);
  }

  [[nodiscard]] constexpr Result<void> SetEndpoints(std::span<const cares::Endpoint> endpoints) noexcept {
    if (endpoints.empty() || endpoints.size() > MaxEndpoints) {
      return std::unexpected(Error::InvalidArgument());
    }
    Reset(endpoints);
    return {};
  }

  constexpr void SetPolicy(EndpointSelectionPolicy policy) noexcept { config_.policy = policy; }

  constexpr void SetConfig(EndpointFailoverConfig config) noexcept {
    if (config.failure_threshold == 0) config.failure_threshold = 1;
    if (config.random_seed != 0 && config.random_seed != config_.random_seed) rng_state_ = config.random_seed;
    config_ = std::move(config);
  }

  [[nodiscard]] constexpr Result<bool> AddEndpoint(const cares::Endpoint& endpoint) noexcept {
    if (!endpoint.ip.IsV4() && !endpoint.ip.IsV6()) return std::unexpected(Error::InvalidArgument());
    if (FindEndpoint(endpoint).has_value()) return false;
    if (count_ >= MaxEndpoints) return std::unexpected(Error::BufferOverflow());
    const std::uint32_t idx = count_++;
    endpoints_[idx] = endpoint;
    quarantined_until_ns_[idx] = 0;
    ewma_rtt_ns_[idx] = 0;
    failure_counts_[idx] = 0;
    configured_bits_ = configured_bits_.set(idx);
    healthy_bits_ = healthy_bits_.set(idx);
    ready_bits_ = ready_bits_.set(idx);
    divisor_ = *uarch::FastDivisorU32::try_new(count_);
    return true;
  }

  [[nodiscard]] constexpr Result<void> ReconcileEndpoints(std::span<const cares::Endpoint> endpoints) noexcept {
    if (endpoints.empty() || endpoints.size() > MaxEndpoints) return std::unexpected(Error::InvalidArgument());
    std::array<cares::Endpoint, MaxEndpoints> next_eps{};
    std::array<std::uint64_t, MaxEndpoints> next_quarantine{};
    std::array<std::uint64_t, MaxEndpoints> next_ewma{};
    std::array<std::uint32_t, MaxEndpoints> next_failures{};
    uarch::Bitmap64 next_configured = uarch::Bitmap64::empty();
    uarch::Bitmap64 next_healthy = uarch::Bitmap64::empty();
    uarch::Bitmap64 next_ready = uarch::Bitmap64::empty();
    std::uint32_t next_count = 0;
    for (const auto& ep : endpoints) {
      if (!ep.ip.IsV4() && !ep.ip.IsV6()) return std::unexpected(Error::InvalidArgument());
      bool dup = false;
      for (std::uint32_t j = 0; j < next_count; ++j) {
        if (next_eps[j] == ep) {
          dup = true;
          break;
        }
      }
      if (dup) continue;
      const std::uint32_t idx = next_count++;
      next_eps[idx] = ep;
      next_configured = next_configured.set(idx);
      if (const auto old = FindEndpoint(ep)) {
        const auto old_bit = static_cast<std::uint32_t>(*old);
        next_quarantine[idx] = quarantined_until_ns_[*old];
        next_ewma[idx] = ewma_rtt_ns_[*old];
        next_failures[idx] = failure_counts_[*old];
        if (healthy_bits_.test(old_bit)) next_healthy = next_healthy.set(idx);
        if (ready_bits_.test(old_bit)) next_ready = next_ready.set(idx);
      } else {
        next_healthy = next_healthy.set(idx);
        next_ready = next_ready.set(idx);
      }
    }
    const auto next_div = *uarch::FastDivisorU32::try_new(next_count == 0 ? 1U : next_count);
    std::uint32_t next_cursor = next_div.rem(cursor_);
    if (cursor_ < count_) {
      for (std::uint32_t j = 0; j < next_count; ++j) {
        if (next_eps[j] == endpoints_[cursor_]) {
          next_cursor = j;
          break;
        }
      }
    }
    endpoints_ = next_eps;
    quarantined_until_ns_ = next_quarantine;
    ewma_rtt_ns_ = next_ewma;
    failure_counts_ = next_failures;
    configured_bits_ = next_configured;
    healthy_bits_ = next_healthy;
    ready_bits_ = next_ready;
    count_ = next_count;
    divisor_ = next_div;
    cursor_ = next_cursor;
    return {};
  }

  constexpr void SetReady(std::size_t index, bool ready) noexcept {
    if (index >= count_) {
      return;
    }
    const auto bit = static_cast<std::uint32_t>(index);
    ready_bits_ = ready ? ready_bits_.set(bit) : ready_bits_.clear(bit);
  }

  [[nodiscard]] constexpr bool IsReady(std::size_t index) const noexcept {
    return index < count_ && ready_bits_.test(static_cast<std::uint32_t>(index));
  }

  /// Specializes the configured round-robin policy; an observer requires the dynamic overload.
  template <EndpointSelectionPolicy Policy>
    requires(Policy == EndpointSelectionPolicy::kRoundRobin)
  [[nodiscard, gnu::always_inline]] constexpr Result<std::size_t> SelectNext(std::uint64_t now_ns = 0) noexcept {
    if (config_.policy != Policy || config_.observer) return std::unexpected(Error::InvalidArgument());
    if (count_ == 0) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kAllEndpointsUnhealthy));
    if (healthy_bits_ != configured_bits_) RecoverExpired<false>(now_ns);
    const auto candidates = healthy_bits_.intersection(ready_bits_);
    if (candidates.is_empty()) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kAllEndpointsUnhealthy));
    return AdvanceRoundRobin(candidates);
  }

  [[nodiscard, gnu::always_inline]] constexpr Result<std::size_t> SelectNext(std::uint64_t now_ns = 0) noexcept {
    if (count_ == 0) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kAllEndpointsUnhealthy));
    }
    if (healthy_bits_ != configured_bits_) {
      RecoverExpired(now_ns);
    }
    const uarch::Bitmap64 candidates = healthy_bits_.intersection(ready_bits_);
    if (candidates.is_empty()) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kAllEndpointsUnhealthy));
    }
    switch (config_.policy) {
      case EndpointSelectionPolicy::kRoundRobin:
        return AdvanceRoundRobin(candidates);
      case EndpointSelectionPolicy::kPickFirst:
        return static_cast<std::size_t>(*candidates.lowest_one());
      case EndpointSelectionPolicy::kSticky: {
        if (cursor_ < count_ && candidates.test(cursor_)) {
          return static_cast<std::size_t>(cursor_);
        }
        auto candidate = candidates.next_one_from(cursor_);
        if (!candidate.has_value()) {
          candidate = candidates.lowest_one();
        }
        const std::uint32_t chosen = *candidate;
        const bool switched = (chosen != cursor_);
        cursor_ = chosen;
        if (switched) {
          EmitEvent(FailoverEventKind::kSwitched, chosen);
        }
        return static_cast<std::size_t>(chosen);
      }
      case EndpointSelectionPolicy::kLatencyAware: {
        uarch::Bitmap64 scan = candidates;
        std::uint32_t best = *candidates.lowest_one();
        std::uint64_t best_rtt = ewma_rtt_ns_[best];
        bool best_ge_cursor = (best >= cursor_);
        while (auto bit = scan.pop_lowest_one()) {
          const std::uint32_t idx = *bit;
          const std::uint64_t rtt = ewma_rtt_ns_[idx];
          const bool ge_cursor = (idx >= cursor_);
          if (rtt < best_rtt || (rtt == best_rtt && ge_cursor && !best_ge_cursor)) {
            best = idx;
            best_rtt = rtt;
            best_ge_cursor = ge_cursor;
          }
        }
        cursor_ = divisor_.rem(best + 1U);
        return static_cast<std::size_t>(best);
      }
      case EndpointSelectionPolicy::kRandom: {
        auto target = static_cast<std::uint32_t>((static_cast<__uint128_t>(NextRandomU64()) * candidates.count()) >> 64U);
        uarch::Bitmap64 scan = candidates;
        while (auto bit = scan.pop_lowest_one()) {
          if (target == 0) {
            return static_cast<std::size_t>(*bit);
          }
          --target;
        }
        return static_cast<std::size_t>(*candidates.lowest_one());
      }
    }
    return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kAllEndpointsUnhealthy));
  }

  [[nodiscard, gnu::always_inline]] constexpr Result<cares::Endpoint> SelectEndpoint(std::uint64_t now_ns = 0) noexcept {
    auto idx = SelectNext(now_ns);
    if (!idx) {
      return std::unexpected(idx.error());
    }
    return endpoints_[*idx];
  }

  constexpr void MarkSuccess(std::size_t index) noexcept {
    if (index >= count_) {
      return;
    }
    const auto bit = static_cast<std::uint32_t>(index);
    const bool was_quarantined = !healthy_bits_.test(bit);
    failure_counts_[index] = 0;
    quarantined_until_ns_[index] = 0;
    healthy_bits_ = healthy_bits_.set(bit);
    if (was_quarantined) {
      EmitEvent(FailoverEventKind::kRecovered, index);
    }
  }

  constexpr void MarkSuccess(const cares::Endpoint& endpoint) noexcept {
    if (auto idx = FindEndpoint(endpoint)) {
      MarkSuccess(*idx);
    }
  }

  constexpr void RecordSuccess(std::size_t index, std::uint64_t rtt_ns) noexcept {
    if (index >= count_) {
      return;
    }
    MarkSuccess(index);
    ewma_rtt_ns_[index] =
        (ewma_rtt_ns_[index] == 0)
            ? rtt_ns
            : static_cast<std::uint64_t>(
                  (static_cast<__uint128_t>(ewma_rtt_ns_[index]) * 7U + static_cast<__uint128_t>(rtt_ns)) >> 3U);
  }

  constexpr void RecordSuccess(const cares::Endpoint& endpoint, std::uint64_t rtt_ns) noexcept {
    if (auto idx = FindEndpoint(endpoint)) {
      RecordSuccess(*idx, rtt_ns);
    }
  }

  constexpr void MarkFailure(std::size_t index, std::uint64_t now_ns = 0) noexcept {
    if (index >= count_) {
      return;
    }
    const std::uint32_t failures = uarch::saturating_add(failure_counts_[index], 1U);
    failure_counts_[index] = failures;
    const std::uint32_t threshold = (config_.failure_threshold == 0) ? 1U : config_.failure_threshold;
    if (failures >= threshold) {
      const auto bit = static_cast<std::uint32_t>(index);
      const bool was_healthy = healthy_bits_.test(bit);
      const std::uint32_t exp = std::min<std::uint32_t>(failures - threshold, 20U);
      const std::uint64_t scaled = uarch::saturating_mul(config_.base_cooldown_ns, std::uint64_t{1} << exp);
      const std::uint64_t cooldown = std::min(scaled, std::max(config_.base_cooldown_ns, config_.max_cooldown_ns));
      quarantined_until_ns_[index] = uarch::saturating_add(now_ns, cooldown);
      healthy_bits_ = healthy_bits_.clear(bit);
      if (was_healthy) {
        EmitEvent(FailoverEventKind::kQuarantined, index);
      }
    }
  }

  constexpr void MarkFailure(const cares::Endpoint& endpoint, std::uint64_t now_ns = 0) noexcept {
    if (auto idx = FindEndpoint(endpoint)) {
      MarkFailure(*idx, now_ns);
    }
  }

  [[nodiscard]] constexpr std::optional<std::size_t> FindEndpoint(const cares::Endpoint& endpoint) const noexcept {
    for (std::size_t i = 0; i < count_; ++i) {
      if (endpoints_[i] == endpoint) {
        return i;
      }
    }
    return std::nullopt;
  }

  [[nodiscard]] constexpr bool IsHealthy(std::size_t index, std::uint64_t now_ns = 0) const noexcept {
    if (index >= count_) {
      return false;
    }
    if (healthy_bits_.test(static_cast<std::uint32_t>(index))) {
      return true;
    }
    return now_ns >= quarantined_until_ns_[index];
  }

  [[nodiscard]] constexpr std::size_t HealthyCount(std::uint64_t now_ns = 0) const noexcept {
    std::size_t n = 0;
    for (std::size_t i = 0; i < count_; ++i) {
      if (IsHealthy(i, now_ns)) {
        ++n;
      }
    }
    return n;
  }

  [[nodiscard]] constexpr std::uint32_t FailureCount(std::size_t index) const noexcept {
    return (index < count_) ? failure_counts_[index] : 0U;
  }

  [[nodiscard]] constexpr std::uint64_t EwmaLatencyNs(std::size_t index) const noexcept {
    return (index < count_) ? ewma_rtt_ns_[index] : 0ULL;
  }

  [[nodiscard]] constexpr std::uint64_t QuarantinedUntilNs(std::size_t index) const noexcept {
    return (index < count_) ? quarantined_until_ns_[index] : 0ULL;
  }

  [[nodiscard]] constexpr std::size_t Size() const noexcept { return count_; }
  [[nodiscard]] constexpr bool Empty() const noexcept { return count_ == 0; }
  [[nodiscard]] constexpr const cares::Endpoint& EndpointAt(std::size_t index) const noexcept { return endpoints_[index]; }
  [[nodiscard]] constexpr std::span<const cares::Endpoint> Endpoints() const noexcept { return {endpoints_.data(), count_}; }
  [[nodiscard]] constexpr const EndpointFailoverConfig& Config() const noexcept { return config_; }
};

}  // namespace nexora
