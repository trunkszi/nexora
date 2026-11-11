#pragma once

#include <algorithm>
#include <array>
#include <cares/cares.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <nexora/pool/detail/origin_types.hpp>
#include <optional>
#include <span>
#include <tuple>
#include <uarch/uarch.hpp>
#include <utility>
#include <vector>

namespace nexora {

namespace detail {
struct OriginPoolTestPeer;
}  // namespace detail

template <std::size_t MaxSlots = 32>
class OriginPool {
  static_assert(MaxSlots > 0, "OriginPool MaxSlots must be > 0");
  friend struct detail::OriginPoolTestPeer;

  struct SlotEntry {
    static constexpr std::uint32_t kMaxLeaseEpoch = 0x00FF'FFFFU;
    static constexpr std::uint16_t kMaxGeneration = 0xFFFFU;

    bool allocated{false};
    bool retired{false};
    std::uint16_t generation{1};
    OriginKey key{};
    Version version{Version::kHttp11};
    bool busy{false};
    std::uint32_t active_streams{0};
    std::array<uarch::Bitmap64, 4> active_leases{uarch::Bitmap64::empty(), uarch::Bitmap64::empty(), uarch::Bitmap64::empty(),
                                                 uarch::Bitmap64::empty()};
    std::array<uarch::Bitmap64, 4> retired_leases{uarch::Bitmap64::empty(), uarch::Bitmap64::empty(), uarch::Bitmap64::empty(),
                                                  uarch::Bitmap64::empty()};
    std::array<std::uint32_t, 256> lease_epochs{};
    std::uint64_t created_at_ns{0};
    std::uint64_t last_used_at_ns{0};

    [[nodiscard]] std::uint32_t AllocateLease() noexcept {
      for (std::uint32_t w = 0; w < active_leases.size(); ++w) {
        for (;;) {
          const auto unavailable = active_leases[w] | retired_leases[w];
          const auto bit = unavailable.lowest_zero();
          if (!bit) break;
          const std::uint32_t idx = w * 64U + *bit;
          if (lease_epochs[idx] >= kMaxLeaseEpoch) {
            retired_leases[w] = retired_leases[w].set(*bit);
            continue;
          }
          const std::uint32_t epoch = lease_epochs[idx] + 1U;
          active_leases[w] = active_leases[w].set(*bit);
          lease_epochs[idx] = epoch;
          return (epoch << 8U) | idx;
        }
      }
      return 0U;
    }
    [[nodiscard]] bool ReleaseLease(std::uint32_t lease_token) noexcept {
      if (lease_token == 0U) return false;
      const std::uint32_t idx = lease_token & 0xFFU;
      const std::uint32_t epoch = lease_token >> 8U;
      const std::uint32_t w = idx >> 6U;
      const std::uint32_t b = idx & 63U;
      if (w >= active_leases.size() || !active_leases[w].test(b) || lease_epochs[idx] != epoch) return false;
      active_leases[w] = active_leases[w].clear(b);
      if (epoch >= kMaxLeaseEpoch) {
        retired_leases[w] = retired_leases[w].set(b);
      }
      return true;
    }
  };

  static constexpr std::uint32_t kMaxSlotH2Leases =
      static_cast<std::uint32_t>(std::tuple_size_v<decltype(SlotEntry::lease_epochs)>);

  PoolConfig config_{};
  std::array<OriginEntry, MaxSlots> origins_{};
  std::size_t origin_count_{0};
  std::array<SlotEntry, MaxSlots> slots_{};
  void* resolver_ctx_{nullptr};
  void (*cancel_query_fn_)(void* ctx, cares::QueryHandle handle) noexcept {nullptr};

  void CancelDnsHandles(std::span<const cares::QueryHandle> handles) noexcept {
    if (resolver_ctx_ != nullptr && cancel_query_fn_ != nullptr) {
      for (const auto& h : handles) cancel_query_fn_(resolver_ctx_, h);
    }
  }

  [[nodiscard]] OriginEntry* FindOriginMut(const OriginKey& key) noexcept {
    for (std::size_t i = 0; i < origin_count_; ++i) {
      if (origins_[i].origin == key) return &origins_[i];
    }
    return nullptr;
  }

  [[nodiscard]] const OriginEntry* FindOrigin(const OriginKey& key) const noexcept {
    for (std::size_t i = 0; i < origin_count_; ++i) {
      if (origins_[i].origin == key) return &origins_[i];
    }
    return nullptr;
  }

  [[nodiscard]] OriginEntry* GetOrCreateOrigin(OriginKey key) noexcept {
    if (auto* existing = FindOriginMut(key)) return existing;
    if (origin_count_ < MaxSlots) {
      origins_[origin_count_] = OriginEntry{std::move(key)};
      TuneFailover(origins_[origin_count_]);
      return &origins_[origin_count_++];
    }
    for (std::size_t i = 0; i < origin_count_; ++i) {
      if (origins_[i].IsEvictable()) {
        origins_[i] = OriginEntry{std::move(key)};
        TuneFailover(origins_[i]);
        return &origins_[i];
      }
    }
    return nullptr;
  }

  void TuneFailover(OriginEntry& entry) const noexcept {
    auto cfg = entry.failover.Config();
    cfg.base_cooldown_ns = config_.endpoint_base_cooldown_ns;
    cfg.max_cooldown_ns = config_.endpoint_max_cooldown_ns;
    entry.failover.SetConfig(cfg);
  }

  [[nodiscard]] std::uint32_t SlotMaxH2Streams(const OriginEntry& entry, std::size_t h2_ordinal) const noexcept {
    const std::uint32_t max_h2 = std::min(config_.EffectiveMaxH2Streams(), kMaxSlotH2Leases);
    std::size_t seen = 0;
    for (const auto& c : entry.connections) {
      if (c.version != Version::kHttp2) continue;
      if (seen == h2_ordinal) return std::min(c.max_concurrent_streams, max_h2);
      ++seen;
    }
    return max_h2;
  }

  void SyncH2StreamDelta(OriginEntry& entry, std::size_t h2_ordinal, bool inc) noexcept {
    std::size_t seen = 0;
    for (auto& c : entry.connections) {
      if (c.version != Version::kHttp2) continue;
      if (seen == h2_ordinal) {
        c.active_streams = inc ? uarch::saturating_add(c.active_streams, 1U) : uarch::saturating_sub(c.active_streams, 1U);
        return;
      }
      ++seen;
    }
  }

 public:
  explicit OriginPool(PoolConfig config = {}) noexcept : config_(config) {}

  template <typename ResolverT>
  void BindResolver(ResolverT& resolver) noexcept {
    resolver_ctx_ = static_cast<void*>(&resolver);
    cancel_query_fn_ = +[](void* ctx, cares::QueryHandle handle) noexcept {
      static_cast<void>(static_cast<ResolverT*>(ctx)->CancelQuery(handle));
    };
  }

  void UnbindResolver() noexcept {
    resolver_ctx_ = nullptr;
    cancel_query_fn_ = nullptr;
  }

  [[nodiscard]] Result<PoolSlotToken> Acquire(const OriginKey& key, Version version, std::uint64_t now_ns) noexcept {
    auto* entry = GetOrCreateOrigin(key);
    if (entry == nullptr) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kPoolExhausted));
    }
    std::size_t per_origin_count = 0;
    std::size_t h2_ordinal = 0;
    for (std::size_t i = 0; i < MaxSlots; ++i) {
      auto& s = slots_[i];
      if (!s.allocated || !(s.key == key)) continue;
      ++per_origin_count;
      if (s.version != version) continue;
      if (version == Version::kHttp2) {
        const std::size_t ord = h2_ordinal++;
        const std::uint32_t cap = SlotMaxH2Streams(*entry, ord);
        if (s.active_streams < cap) {
          const std::uint32_t lease = s.AllocateLease();
          if (lease == 0U) continue;
          s.active_streams = uarch::saturating_add(s.active_streams, 1U);
          s.busy = true;
          s.last_used_at_ns = now_ns;
          SyncH2StreamDelta(*entry, ord, true);
          return PoolSlotToken{static_cast<std::uint16_t>(i), s.generation, lease};
        }
        continue;
      }
      if (!s.busy) {
        const std::uint32_t lease = s.AllocateLease();
        if (lease == 0U) continue;
        s.busy = true;
        s.last_used_at_ns = now_ns;
        return PoolSlotToken{static_cast<std::uint16_t>(i), s.generation, lease};
      }
    }
    if (per_origin_count >= config_.max_connections_per_origin) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kPoolExhausted));
    }
    if (version == Version::kHttp2 && SlotMaxH2Streams(*entry, h2_ordinal) == 0) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kPoolExhausted));
    }
    for (std::size_t i = 0; i < MaxSlots; ++i) {
      if (!slots_[i].allocated && !slots_[i].retired) {
        const std::uint16_t gen = (slots_[i].generation == 0) ? std::uint16_t{1} : slots_[i].generation;
        const auto prev_retired = slots_[i].retired_leases;
        const auto prev_epochs = slots_[i].lease_epochs;
        slots_[i] = SlotEntry{
            .allocated = true,
            .retired = false,
            .generation = gen,
            .key = key,
            .version = version,
            .busy = true,
            .active_streams = 0U,
            .retired_leases = prev_retired,
            .lease_epochs = prev_epochs,
            .created_at_ns = now_ns,
            .last_used_at_ns = now_ns,
        };
        const std::uint32_t lease = slots_[i].AllocateLease();
        if (lease == 0U) {
          slots_[i].allocated = false;
          slots_[i].busy = false;
          continue;
        }
        if (version == Version::kHttp2) {
          slots_[i].active_streams = 1U;
          SyncH2StreamDelta(*entry, h2_ordinal, true);
        }
        return PoolSlotToken{static_cast<std::uint16_t>(i), gen, lease};
      }
    }
    return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kPoolExhausted));
  }

  bool Release(PoolSlotToken token, std::uint64_t now_ns) noexcept {
    if (token.slot >= MaxSlots || token.generation == 0) return false;
    auto& s = slots_[token.slot];
    if (!s.allocated || s.retired || s.generation != token.generation) return false;
    if (s.version == Version::kHttp2) {
      if (s.active_streams == 0 || !s.ReleaseLease(token.lease)) return false;
      --s.active_streams;
      s.busy = (s.active_streams > 0);
      if (auto* entry = FindOriginMut(s.key)) {
        std::size_t ord = 0;
        for (std::size_t i = 0; i < token.slot; ++i) {
          if (slots_[i].allocated && slots_[i].key == s.key && slots_[i].version == Version::kHttp2) ++ord;
        }
        SyncH2StreamDelta(*entry, ord, false);
      }
    } else {
      if (!s.busy || !s.ReleaseLease(token.lease)) return false;
      s.busy = false;
    }
    s.last_used_at_ns = now_ns;
    return true;
  }

  std::size_t EvictExpired(std::uint64_t now_ns) noexcept {
    std::size_t evicted = 0;
    const auto idle_limit_ns = static_cast<std::uint64_t>(config_.EffectiveIdleTimeout().count());
    const auto life_limit_ns = static_cast<std::uint64_t>(config_.EffectiveMaxLifetime().count());
    for (std::size_t i = 0; i < MaxSlots; ++i) {
      auto& s = slots_[i];
      if (!s.allocated || s.busy || s.active_streams > 0) continue;
      const bool idle_exp = (now_ns >= s.last_used_at_ns) && ((now_ns - s.last_used_at_ns) >= idle_limit_ns);
      const bool life_exp = (now_ns >= s.created_at_ns) && ((now_ns - s.created_at_ns) >= life_limit_ns);
      if (idle_exp || life_exp) {
        if (s.generation >= SlotEntry::kMaxGeneration) {
          s = SlotEntry{.retired = true, .generation = SlotEntry::kMaxGeneration};
        } else {
          const auto next_gen = static_cast<std::uint16_t>(s.generation + 1U);
          s = SlotEntry{.generation = next_gen};
        }
        ++evicted;
      }
    }
    return evicted;
  }

  [[nodiscard]] constexpr const PoolConfig& Config() const noexcept { return config_; }
  [[nodiscard]] const OriginEntry* Entry(const OriginKey& origin) const noexcept { return FindOrigin(origin); }
  [[nodiscard]] OriginEntry* EntryMut(const OriginKey& origin) noexcept { return FindOriginMut(origin); }
  [[nodiscard]] std::optional<OriginState> State(const OriginKey& origin) const noexcept {
    if (const auto* entry = FindOrigin(origin)) return entry->state;
    return std::nullopt;
  }
  bool TransitionOrigin(OriginKey origin, OriginState next) noexcept {
    auto* entry = GetOrCreateOrigin(std::move(origin));
    return entry != nullptr && entry->TransitionTo(next);
  }
  [[nodiscard]] bool BeginDns(OriginKey origin, std::uint64_t request_id) noexcept {
    auto* entry = GetOrCreateOrigin(std::move(origin));
    if (entry == nullptr) return false;
    if (std::find(entry->waiters.begin(), entry->waiters.end(), request_id) == entry->waiters.end()) {
      entry->waiters.push_back(request_id);
    }
    return (entry->state == OriginState::kIdle) && entry->TransitionTo(OriginState::kResolvingDns);
  }
  void SetQueryHandles(const OriginKey& origin, std::vector<cares::QueryHandle> handles) noexcept {
    if (auto* entry = FindOriginMut(origin)) entry->dns_handles = std::move(handles);
  }
  [[nodiscard]] std::vector<cares::QueryHandle> TakeQueryHandles(const OriginKey& origin) noexcept {
    if (auto* entry = FindOriginMut(origin)) return std::exchange(entry->dns_handles, {});
    return {};
  }
  [[nodiscard]] bool SetResolvedEndpoints(OriginKey origin, std::span<const cares::Endpoint> endpoints) noexcept {
    auto* entry = GetOrCreateOrigin(std::move(origin));
    if (entry == nullptr) return false;
    return entry->failover.ReconcileEndpoints(endpoints).has_value();
  }
  [[nodiscard]] Result<cares::Endpoint> SelectEndpoint(const OriginKey& origin, std::uint64_t now_ns = 0) noexcept {
    auto* entry = FindOriginMut(origin);
    if (entry == nullptr) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kAllEndpointsUnhealthy));
    return entry->failover.SelectEndpoint(now_ns);
  }
  void MarkEndpointSuccess(const OriginKey& origin, const cares::Endpoint& endpoint) noexcept {
    if (auto* entry = FindOriginMut(origin)) entry->failover.MarkSuccess(endpoint);
  }
  void MarkEndpointFailure(const OriginKey& origin, const cares::Endpoint& endpoint, std::uint64_t now_ns = 0) noexcept {
    if (auto* entry = FindOriginMut(origin)) entry->failover.MarkFailure(endpoint, now_ns);
  }
  bool PushWaiter(OriginKey origin, std::uint64_t request_id) noexcept {
    auto* entry = GetOrCreateOrigin(std::move(origin));
    if (entry == nullptr) return false;
    if (std::find(entry->waiters.begin(), entry->waiters.end(), request_id) == entry->waiters.end()) {
      entry->waiters.push_back(request_id);
    }
    return true;
  }
  [[nodiscard]] std::vector<std::uint64_t> TakeWaiters(const OriginKey& origin) noexcept {
    if (auto* entry = FindOriginMut(origin)) return std::exchange(entry->waiters, {});
    return {};
  }

  [[nodiscard]] std::vector<std::pair<OriginKey, WaiterRemoval>> RemoveWaiter(std::uint64_t request_id) noexcept {
    std::vector<std::pair<OriginKey, WaiterRemoval>> removals{};
    for (std::size_t i = 0; i < origin_count_; ++i) {
      auto& entry = origins_[i];
      const std::size_t before = entry.waiters.size();
      entry.waiters.erase(std::remove(entry.waiters.begin(), entry.waiters.end(), request_id), entry.waiters.end());
      if (entry.waiters.size() == before) continue;
      std::vector<cares::QueryHandle> dns_handles{};
      if (entry.waiters.empty() && entry.state == OriginState::kResolvingDns && entry.connections.empty()) {
        dns_handles = std::exchange(entry.dns_handles, {});
        CancelDnsHandles(dns_handles);
        static_cast<void>(entry.TransitionTo(OriginState::kIdle));
      }
      removals.push_back({entry.origin, WaiterRemoval{true, entry.state, std::move(dns_handles)}});
    }
    return removals;
  }

  [[nodiscard]] bool RegisterConnection(OriginKey origin, PooledConnection conn) noexcept {
    const Version version = conn.version;
    auto* entry = GetOrCreateOrigin(std::move(origin));
    if (entry == nullptr || entry->connections.size() >= config_.max_connections_per_origin) return false;
    entry->connections.push_back(conn);
    const OriginState target = (version == Version::kHttp2) ? OriginState::kReadyHttp2 : OriginState::kReadyHttp1;
    static_cast<void>(entry->TransitionTo(target));
    return true;
  }

  [[nodiscard]] std::optional<std::uint64_t> AcquireHttp1(
      const OriginKey& origin, std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) noexcept {
    auto* entry = FindOriginMut(origin);
    if (entry == nullptr) return std::nullopt;
    for (auto& conn : entry->connections) {
      if (conn.version == Version::kHttp11 && !conn.busy) {
        conn.busy = true;
        conn.last_used_at = now;
        return conn.connection_id;
      }
    }
    return std::nullopt;
  }

  void MarkIdle(const OriginKey& origin, std::uint64_t connection_id,
                std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) noexcept {
    if (auto* entry = FindOriginMut(origin)) {
      for (auto& c : entry->connections) {
        if (c.connection_id == connection_id) {
          c.busy = false;
          c.last_used_at = now;
          break;
        }
      }
    }
  }

  void MarkBusy(const OriginKey& origin, std::uint64_t connection_id,
                std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) noexcept {
    if (auto* entry = FindOriginMut(origin)) {
      for (auto& c : entry->connections) {
        if (c.connection_id == connection_id) {
          c.busy = true;
          c.last_used_at = now;
          break;
        }
      }
    }
  }

  [[nodiscard]] std::optional<std::uint64_t> AcquireHttp2Stream(
      const OriginKey& origin, std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) noexcept {
    auto* entry = FindOriginMut(origin);
    if (entry == nullptr) return std::nullopt;
    const std::uint32_t max_h2 = config_.EffectiveMaxH2Streams();
    for (auto& c : entry->connections) {
      if (c.version == Version::kHttp2 && c.active_streams < std::min(c.max_concurrent_streams, max_h2)) {
        c.active_streams = uarch::saturating_add(c.active_streams, 1U);
        c.last_used_at = now;
        return c.connection_id;
      }
    }
    return std::nullopt;
  }

  void ReleaseHttp2Stream(const OriginKey& origin, std::uint64_t connection_id,
                          std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) noexcept {
    if (auto* entry = FindOriginMut(origin)) {
      for (auto& c : entry->connections) {
        if (c.connection_id == connection_id) {
          c.active_streams = uarch::saturating_sub(c.active_streams, 1U);
          c.last_used_at = now;
          break;
        }
      }
    }
  }

  void RemoveConnection(std::uint64_t connection_id) noexcept {
    for (std::size_t i = 0; i < origin_count_; ++i) {
      auto& entry = origins_[i];
      const std::size_t before = entry.connections.size();
      entry.connections.erase(
          std::remove_if(entry.connections.begin(), entry.connections.end(),
                         [connection_id](const PooledConnection& c) noexcept { return c.connection_id == connection_id; }),
          entry.connections.end());
      if (entry.connections.size() == before) continue;
      if (entry.connections.empty() && entry.waiters.empty() && !entry.active_connect.has_value()) {
        auto handles = std::exchange(entry.dns_handles, {});
        CancelDnsHandles(handles);
        static_cast<void>(entry.TransitionTo(OriginState::kIdle));
      }
      break;
    }
  }

  [[nodiscard]] std::vector<std::uint64_t> Expired(std::chrono::steady_clock::time_point now) const noexcept {
    std::vector<std::uint64_t> expired_ids{};
    const auto idle_limit = config_.EffectiveIdleTimeout();
    const auto life_limit = config_.EffectiveMaxLifetime();
    for (std::size_t idx = 0; idx < origin_count_; ++idx) {
      const auto& entry = origins_[idx];
      const std::size_t total = entry.connections.size();
      for (std::size_t base = 0; base < total; base += 64) {
        const std::size_t end = std::min(base + 64, total);
        uarch::Bitmap64 expired_mask = uarch::Bitmap64::empty();
        for (std::size_t offset = 0; offset < (end - base); ++offset) {
          const auto& conn = entry.connections[base + offset];
          const bool idle_expired = !conn.busy && conn.active_streams == 0 && (now - conn.last_used_at) >= idle_limit;
          const bool lifetime_expired = !conn.busy && conn.active_streams == 0 && (now - conn.created_at) >= life_limit;
          if (idle_expired || lifetime_expired) {
            expired_mask = expired_mask.set(static_cast<std::uint32_t>(offset));
          }
        }
        while (auto bit = expired_mask.pop_lowest_one()) {
          expired_ids.push_back(entry.connections[base + *bit].connection_id);
        }
      }
    }
    return expired_ids;
  }
};

OriginPool(PoolConfig = {}) -> OriginPool<32>;

}  // namespace nexora
