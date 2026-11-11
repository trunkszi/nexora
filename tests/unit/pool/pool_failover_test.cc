#include <array>
#include <chrono>
#include <cstdint>
#include <nexora/pool/endpoint_failover.hpp>
#include <nexora/pool/origin_pool.hpp>
#include <string>
#include <vector>

namespace nexora::detail {
struct OriginPoolTestPeer {
  template <std::size_t MaxSlots>
  static void PrimeSaturation(OriginPool<MaxSlots>& pool, std::size_t slot, std::uint16_t gen, std::uint32_t epoch) noexcept {
    pool.slots_[slot].generation = gen;
    pool.slots_[slot].lease_epochs.fill(epoch);
  }
};
}  // namespace nexora::detail

namespace {

struct MockDnsResolver {
  std::vector<cares::QueryHandle> cancelled_handles{};

  void CancelQuery(cares::QueryHandle handle) noexcept { cancelled_handles.push_back(handle); }
};

int TestOriginKeyNormalization() noexcept {
  const auto k1 = nexora::OriginKey::Create(nexora::Scheme::kHttps, "EXAMPLE.COM.", 443);
  const auto k2 = nexora::OriginKey::Create(nexora::Scheme::kHttps, "example.com", 443);
  if (k1 != k2 || k1.Authority() != "example.com") {
    return 1;
  }
  const auto k_port = nexora::OriginKey::Create(nexora::Scheme::kHttps, "example.com", 8443);
  if (k_port.Authority() != "example.com:8443") {
    return 2;
  }
  const auto k_v6 = nexora::OriginKey::Create(nexora::Scheme::kHttp, "[::1]", 8080);
  if (k_v6.host != "::1" || k_v6.Authority() != "[::1]:8080") {
    return 3;
  }
  auto uri = nexora::Uri::Parse("https://Example.com:443/v1/stream");
  if (!uri || nexora::OriginKey::FromUri(*uri) != k1) {
    return 4;
  }
  return 0;
}

int TestOriginPoolWaiterCoalescingAndSlots() noexcept {
  nexora::PoolConfig cfg{};
  cfg.max_connections_per_origin = 128;
  cfg.max_concurrent_streams_per_h2 = 2;
  cfg.idle_timeout = std::chrono::milliseconds(100);
  cfg.max_lifetime = std::chrono::milliseconds(500);
  nexora::OriginPool pool{cfg};
  MockDnsResolver resolver{};
  pool.BindResolver(resolver);

  const auto origin = nexora::OriginKey::Create(nexora::Scheme::kHttps, "coalesce.example", 443);
  // 4 concurrent waiters coalesce onto 1 DNS resolution.
  if (!pool.BeginDns(origin, 101)) {
    return 10;
  }
  if (pool.BeginDns(origin, 102) || pool.BeginDns(origin, 103) || pool.BeginDns(origin, 104)) {
    return 11;
  }
  const auto q_a = cares::QueryHandle::Pack(1, 1, 1);
  const auto q_aaaa = cares::QueryHandle::Pack(2, 1, 2);
  pool.SetQueryHandles(origin, {q_a, q_aaaa});

  // Removing waiters 101..103 leaves waiter 104 active; resolver.CancelQuery is NOT called yet.
  static_cast<void>(pool.RemoveWaiter(101));
  static_cast<void>(pool.RemoveWaiter(102));
  auto rem3 = pool.RemoveWaiter(103);
  if (rem3.size() != 1 || !rem3[0].second.dns_handles.empty() || !resolver.cancelled_handles.empty() ||
      pool.State(origin) != nexora::OriginState::kResolvingDns) {
    return 12;
  }

  // Removing the last waiter 104 cancels both DNS handles on the bound resolver and resets state to kIdle.
  auto rem4 = pool.RemoveWaiter(104);
  if (rem4.size() != 1 || rem4[0].second.dns_handles.size() != 2 || resolver.cancelled_handles.size() != 2 ||
      pool.State(origin) != nexora::OriginState::kIdle) {
    return 13;
  }

  // Also test contract Acquire / Release / EvictExpired slot API.
  nexora::OriginPool<8> slot_pool{nexora::PoolConfig{
      .max_connections_per_origin = 2,
      .idle_timeout_ns = 1'000'000ULL,
      .max_lifetime_ns = 5'000'000ULL,
      .max_streams_per_h2_connection = 2,
  }};
  auto s0 = slot_pool.Acquire(origin, nexora::Version::kHttp11, 100);
  auto s1 = slot_pool.Acquire(origin, nexora::Version::kHttp11, 100);
  auto s2 = slot_pool.Acquire(origin, nexora::Version::kHttp11, 100);
  if (!s0 || !s1 || *s0 == *s1 || s2.has_value()) {
    return 14;
  }
  slot_pool.Release(*s0, 200);
  if (slot_pool.EvictExpired(1'000'250ULL) != 1) {
    return 15;
  }

  const auto t0 = std::chrono::steady_clock::now();
  if (!pool.RegisterConnection(origin, nexora::PooledConnection{
                                           .connection_id = 1,
                                           .version = nexora::Version::kHttp11,
                                           .busy = false,
                                           .active_streams = 0,
                                           .max_concurrent_streams = 1,
                                           .created_at = t0,
                                           .last_used_at = t0,
                                       })) {
    return 16;
  }
  auto h1 = pool.AcquireHttp1(origin, t0);
  if (!h1 || *h1 != 1 || pool.AcquireHttp1(origin, t0).has_value()) {
    return 17;
  }
  pool.MarkIdle(origin, 1, t0);

  // HTTP/2 stream admission with max_concurrent_streams_per_h2 == 2.
  const auto h2_origin = nexora::OriginKey::Create(nexora::Scheme::kHttps, "h2.example", 443);
  if (!pool.RegisterConnection(h2_origin, nexora::PooledConnection{
                                              .connection_id = 50,
                                              .version = nexora::Version::kHttp2,
                                              .busy = false,
                                              .active_streams = 0,
                                              .max_concurrent_streams = 10,
                                              .created_at = t0,
                                              .last_used_at = t0,
                                          })) {
    return 18;
  }
  if (pool.AcquireHttp2Stream(h2_origin, t0) != 50 || pool.AcquireHttp2Stream(h2_origin, t0) != 50 ||
      pool.AcquireHttp2Stream(h2_origin, t0).has_value()) {
    return 19;
  }
  pool.ReleaseHttp2Stream(h2_origin, 50, t0);
  pool.ReleaseHttp2Stream(h2_origin, 50, t0);

  // Verify Bitmap64 expiration across > 64 connections.
  const auto bulk_origin = nexora::OriginKey::Create(nexora::Scheme::kHttp, "bulk.example", 80);
  for (std::uint64_t id = 100; id < 170; ++id) {
    if (!pool.RegisterConnection(bulk_origin, nexora::PooledConnection{
                                                  .connection_id = id,
                                                  .version = nexora::Version::kHttp11,
                                                  .busy = false,
                                                  .active_streams = 0,
                                                  .max_concurrent_streams = 1,
                                                  .created_at = t0,
                                                  .last_used_at = t0,
                                              })) {
      return 20;
    }
  }
  const auto expired = pool.Expired(t0 + std::chrono::milliseconds(150));
  if (expired.size() != 72) {
    return 21;
  }
  pool.UnbindResolver();
  return 0;
}

int TestPoolExhaustionIsolation() noexcept {
  // Filling all 32 OriginPool<32> slots with active origins must reject a 33rd origin with kPoolExhausted without
  // overwriting slot 31.
  nexora::OriginPool<32> full_pool{};
  for (std::size_t i = 0; i < 32; ++i) {
    const auto key = nexora::OriginKey::Create(nexora::Scheme::kHttps, "origin-" + std::to_string(i) + ".example", 443);
    if (!full_pool.BeginDns(key, 1000 + i)) {
      return 22;
    }
    full_pool.SetQueryHandles(key, {cares::QueryHandle::Pack(static_cast<std::uint16_t>(i + 1), 1, 1)});
  }
  const auto key31 = nexora::OriginKey::Create(nexora::Scheme::kHttps, "origin-31.example", 443);
  const auto key32 = nexora::OriginKey::Create(nexora::Scheme::kHttps, "origin-32.example", 443);
  if (full_pool.BeginDns(key32, 2000) || full_pool.PushWaiter(key32, 2000)) {
    return 23;
  }
  auto acq32 = full_pool.Acquire(key32, nexora::Version::kHttp11, 5000);
  if (acq32.has_value() || acq32.error() != nexora::Error::FromRuntime(nexora::RuntimeErrorCode::kPoolExhausted)) {
    return 24;
  }
  const auto* entry31 = full_pool.Entry(key31);
  if (entry31 == nullptr || entry31->state != nexora::OriginState::kResolvingDns || entry31->waiters.size() != 1 ||
      entry31->waiters[0] != 1031 || entry31->dns_handles.size() != 1) {
    return 25;
  }

  // RemoveConnection for Origin A must leave Origin B's mid-connect and DNS state untouched.
  nexora::OriginPool<8> iso_pool{};
  MockDnsResolver resolver{};
  iso_pool.BindResolver(resolver);

  const auto origin_a = nexora::OriginKey::Create(nexora::Scheme::kHttps, "a.example", 443);
  const auto origin_b = nexora::OriginKey::Create(nexora::Scheme::kHttps, "b.example", 443);
  if (!iso_pool.RegisterConnection(origin_a, nexora::PooledConnection{.connection_id = 77})) {
    return 26;
  }
  if (!iso_pool.BeginDns(origin_b, 501)) {
    return 27;
  }
  iso_pool.SetQueryHandles(origin_b, {cares::QueryHandle::Pack(9, 1, 1)});
  static_cast<void>(iso_pool.TakeWaiters(origin_b));
  static_cast<void>(iso_pool.TransitionOrigin(origin_b, nexora::OriginState::kConnecting));
  if (auto* eb = iso_pool.EntryMut(origin_b)) {
    eb->active_connect = 888;
  }

  iso_pool.RemoveConnection(77);
  const auto* eb_after = iso_pool.Entry(origin_b);
  if (iso_pool.State(origin_a) != nexora::OriginState::kIdle || eb_after == nullptr ||
      eb_after->state != nexora::OriginState::kConnecting || eb_after->active_connect != 888 ||
      eb_after->dns_handles.size() != 1 || !resolver.cancelled_handles.empty()) {
    return 28;
  }
  return 0;
}

int TestEndpointFailoverQuarantineAndRecovery() noexcept {
  const std::array<cares::Endpoint, 3> eps{
      cares::Endpoint{cares::IpAddress::FromV4({10, 0, 0, 1}), 8080},
      cares::Endpoint{cares::IpAddress::FromV4({10, 0, 0, 2}), 8080},
      cares::Endpoint{cares::IpAddress::FromV4({10, 0, 0, 3}), 8080},
  };
  nexora::EndpointFailover<16> failover{1'000'000'000ULL, 1};
  if (failover.SetEndpoints({}).has_value() || !failover.SetEndpoints(eps)) {
    return 29;
  }

  // Round-robin across healthy endpoints 0, 1, 2, 0.
  if (failover.SelectNext(100) != 0U || failover.SelectNext(100) != 1U || failover.SelectNext(100) != 2U ||
      failover.SelectNext(100) != 0U) {
    return 30;
  }

  // Quarantine endpoint 1 at t = 1_000ns (until 1_000_001_000ns).
  failover.MarkFailure(1, 1000);
  if (failover.IsHealthy(1, 2000) || failover.HealthyCount(2000) != 2) {
    return 31;
  }
  // Selections skip index 1 and alternate between 2 and 0.
  if (failover.SelectNext(2000) != 2U || failover.SelectNext(2000) != 0U || failover.SelectNext(2000) != 2U) {
    return 32;
  }

  // Quarantine 0 and 2 as well -> kAllEndpointsUnhealthy.
  failover.MarkFailure(0, 2000);
  failover.MarkFailure(2, 2000);
  auto none = failover.SelectNext(3000);
  if (none.has_value() || none.error() != nexora::Error::FromRuntime(nexora::RuntimeErrorCode::kAllEndpointsUnhealthy)) {
    return 33;
  }

  // Advance clock past endpoint 1's cooldown (1_000_001_000ns), while 0 and 2 are quarantined until 1_000_002_000ns.
  auto recovered = failover.SelectNext(1'000'001'500ULL);
  if (!recovered || *recovered != 1U) {
    return 34;
  }
  failover.MarkSuccess(1);
  if (failover.FailureCount(1) != 0) {
    return 35;
  }
  return 0;
}

int TestEndpointFailoverPoliciesReadyBitsAndObserver() noexcept {
  static_assert(!nexora::ShouldFailoverWrite(false, false));
  static_assert(nexora::ShouldFailoverWrite(false, true));
  static_assert(!nexora::ShouldFailoverWrite(true, false));
  static_assert(!nexora::ShouldFailoverWrite(true, true));

  const std::array<cares::Endpoint, 3> eps{
      cares::Endpoint{cares::IpAddress::FromV4({10, 1, 0, 1}), 9001},
      cares::Endpoint{cares::IpAddress::FromV4({10, 1, 0, 2}), 9002},
      cares::Endpoint{cares::IpAddress::FromV4({10, 1, 0, 3}), 9003},
  };

  // 1. kPickFirst + SetReady / IsReady gating without cursor rotation.
  nexora::EndpointFailover<16> pick_first{eps, nexora::EndpointFailoverConfig{
                                                   .failure_threshold = 1,
                                                   .base_cooldown_ns = 1'000ULL,
                                                   .policy = nexora::EndpointSelectionPolicy::kPickFirst,
                                               }};
  if (!pick_first.IsReady(0) || pick_first.SelectNext(10) != 0U || pick_first.SelectNext(10) != 0U) {
    return 40;
  }
  pick_first.SetReady(0, false);
  if (pick_first.IsReady(0) || pick_first.SelectNext(10) != 1U || pick_first.SelectNext(10) != 1U) {
    return 41;
  }
  pick_first.MarkFailure(1, 10);
  if (pick_first.SelectNext(20) != 2U) {
    return 42;
  }
  pick_first.SetReady(0, true);
  if (pick_first.SelectNext(20) != 0U) {
    return 43;
  }

  // 2. kSticky + FailoverEvent observer (kSwitched, kQuarantined, kRecovered).
  std::vector<nexora::FailoverEvent> events{};
  nexora::EndpointFailover<16> sticky{eps,
                                      nexora::EndpointFailoverConfig{
                                          .failure_threshold = 1,
                                          .base_cooldown_ns = 500ULL,
                                          .max_cooldown_ns = 5'000ULL,
                                          .policy = nexora::EndpointSelectionPolicy::kSticky,
                                          .observer = [&](const nexora::FailoverEvent& ev) noexcept { events.push_back(ev); },
                                      }};
  if (sticky.SelectNext(100) != 0U || sticky.SelectNext(100) != 0U || !events.empty()) {
    return 44;
  }
  sticky.SetReady(0, false);
  if (sticky.SelectNext(100) != 1U || sticky.SelectNext(100) != 1U || events.size() != 1 ||
      events[0].kind != nexora::FailoverEventKind::kSwitched || events[0].endpoint_index != 1U) {
    return 45;
  }
  sticky.MarkFailure(1, 200);
  if (events.size() != 2 || events[1].kind != nexora::FailoverEventKind::kQuarantined || events[1].endpoint_index != 1U ||
      events[1].quarantined_until_ns != 700ULL || sticky.QuarantinedUntilNs(1) != 700ULL) {
    return 46;
  }
  if (sticky.SelectNext(250) != 2U || events.size() != 3 || events[2].kind != nexora::FailoverEventKind::kSwitched ||
      events[2].endpoint_index != 2U) {
    return 47;
  }
  // Advancing past 700ns recovers endpoint 1 and emits kRecovered while keeping sticky cursor on healthy endpoint 2.
  if (sticky.SelectNext(800) != 2U || events.size() != 4 || events[3].kind != nexora::FailoverEventKind::kRecovered ||
      events[3].endpoint_index != 1U) {
    return 48;
  }

  // 3. kLatencyAware probes unmeasured endpoints then tracks minimum integer EWMA RTT.
  nexora::EndpointFailover<16> latency{eps, nexora::EndpointFailoverConfig{
                                                .policy = nexora::EndpointSelectionPolicy::kLatencyAware,
                                            }};
  if (latency.SelectNext(0) != 0U) {
    return 49;
  }
  latency.RecordSuccess(0, 800'000ULL);
  if (latency.SelectNext(0) != 1U) {
    return 50;
  }
  latency.RecordSuccess(1, 100'000ULL);
  if (latency.SelectNext(0) != 2U) {
    return 51;
  }
  latency.RecordSuccess(2, 300'000ULL);
  if (latency.EwmaLatencyNs(1) != 100'000ULL || latency.SelectNext(0) != 1U || latency.SelectNext(0) != 1U) {
    return 52;
  }
  for (int i = 0; i < 6; ++i) {
    latency.RecordSuccess(1, 2'000'000ULL);
  }
  if (latency.EwmaLatencyNs(1) <= latency.EwmaLatencyNs(2) || latency.SelectNext(0) != 2U) {
    return 53;
  }

  // 4. kRandom deterministic SplitMix64 over ready+healthy candidates only.
  nexora::EndpointFailover<16> rnd{eps, nexora::EndpointFailoverConfig{
                                            .policy = nexora::EndpointSelectionPolicy::kRandom,
                                            .random_seed = 0x123456789ABCDEF0ULL,
                                        }};
  rnd.SetReady(1, false);
  bool saw0 = false;
  bool saw2 = false;
  for (int i = 0; i < 32; ++i) {
    auto chosen = rnd.SelectNext(0);
    if (!chosen || *chosen == 1U) {
      return 54;
    }
    saw0 = saw0 || (*chosen == 0U);
    saw2 = saw2 || (*chosen == 2U);
  }
  if (!saw0 || !saw2) {
    return 55;
  }
  return 0;
}

int TestZeroGlueReconcileEwmaMaxAndLeaseTokens() noexcept {
  // 1. UINT64_MAX EWMA saturation/overflow-free update.
  const std::array<cares::Endpoint, 2> eps{
      cares::Endpoint{cares::IpAddress::FromV4({10, 2, 0, 1}), 8081},
      cares::Endpoint{cares::IpAddress::FromV4({10, 2, 0, 2}), 8082},
  };
  nexora::EndpointFailover<16> ewma_pool{
      eps, nexora::EndpointFailoverConfig{.policy = nexora::EndpointSelectionPolicy::kLatencyAware}};
  ewma_pool.RecordSuccess(0, UINT64_MAX);
  ewma_pool.RecordSuccess(0, UINT64_MAX);
  if (ewma_pool.EwmaLatencyNs(0) != UINT64_MAX) {
    return 60;
  }

  // 2. AddEndpoint, SetPolicy, SetConfig, and ReconcileEndpoints preserving health/EWMA/quarantine/cursor.
  const auto ep3 = cares::Endpoint{cares::IpAddress::FromV4({10, 2, 0, 3}), 8083};
  if (!ewma_pool.AddEndpoint(ep3) || ewma_pool.Size() != 3) {
    return 61;
  }
  ewma_pool.SetConfig(nexora::EndpointFailoverConfig{
      .failure_threshold = 1,
      .base_cooldown_ns = 1'000'000ULL,
      .max_cooldown_ns = 10'000'000ULL,
      .policy = nexora::EndpointSelectionPolicy::kRoundRobin,
  });
  ewma_pool.SetPolicy(nexora::EndpointSelectionPolicy::kSticky);
  ewma_pool.RecordSuccess(1, 250'000ULL);
  if (ewma_pool.SelectNext(100) != 0U) {
    return 62;
  }
  ewma_pool.MarkFailure(0, 500);
  if (ewma_pool.SelectNext(600) != 1U) {
    return 63;
  }
  const std::array<cares::Endpoint, 3> reordered{
      eps[1],
      eps[0],
      cares::Endpoint{cares::IpAddress::FromV4({10, 2, 0, 4}), 8084},
  };
  if (!ewma_pool.ReconcileEndpoints(reordered) || ewma_pool.IsHealthy(1, 700) || ewma_pool.EwmaLatencyNs(0) != 250'000ULL ||
      ewma_pool.EwmaLatencyNs(1) != UINT64_MAX || ewma_pool.FailureCount(1) != 1 || ewma_pool.SelectNext(700) != 0U) {
    return 64;
  }

  // OriginPool::SetResolvedEndpoints preserves quarantine across re-resolution and rejects empty span.
  nexora::OriginPool<8> origin_pool{};
  const auto origin = nexora::OriginKey::Create(nexora::Scheme::kHttps, "reconcile.example", 443);
  if (origin_pool.SetResolvedEndpoints(origin, {}) || !origin_pool.SetResolvedEndpoints(origin, eps)) {
    return 65;
  }
  if (auto* entry = origin_pool.EntryMut(origin)) {
    entry->failover.MarkFailure(0, 100);
  }
  if (!origin_pool.SetResolvedEndpoints(origin, eps)) {
    return 66;
  }
  const auto* reconciled_entry = origin_pool.Entry(origin);
  if (reconciled_entry == nullptr || reconciled_entry->failover.IsHealthy(0, 200)) {
    return 67;
  }

  // 3. PoolSlotToken generation + double-release rejection + Acquire HTTP/2 stream cap alignment.
  nexora::OriginPool<8> lease_pool{nexora::PoolConfig{
      .max_connections_per_origin = 1,
      .idle_timeout_ns = 1'000ULL,
      .max_lifetime_ns = 10'000ULL,
      .max_streams_per_h2_connection = 4,
  }};
  const auto h1_tok = lease_pool.Acquire(origin, nexora::Version::kHttp11, 100);
  if (!h1_tok || lease_pool.Acquire(origin, nexora::Version::kHttp11, 100).has_value()) {
    return 68;
  }
  const auto stale_tok = *h1_tok;
  lease_pool.Release(*h1_tok, 200);
  auto reacquired = lease_pool.Acquire(origin, nexora::Version::kHttp11, 250);
  if (!reacquired) {
    return 69;
  }
  // Double-releasing stale_tok must NOT release the newly acquired lease.
  lease_pool.Release(stale_tok, 260);
  if (lease_pool.Acquire(origin, nexora::Version::kHttp11, 270).has_value()) {
    return 70;
  }
  lease_pool.Release(*reacquired, 300);
  if (lease_pool.EvictExpired(2'000ULL) != 1) {
    return 71;
  }
  auto gen2_tok = lease_pool.Acquire(origin, nexora::Version::kHttp11, 2'100ULL);
  if (!gen2_tok || gen2_tok->generation == stale_tok.generation) {
    return 72;
  }
  lease_pool.Release(stale_tok, 2'200ULL);
  if (lease_pool.Acquire(origin, nexora::Version::kHttp11, 2'250ULL).has_value()) {
    return 73;
  }
  lease_pool.Release(*gen2_tok, 2'300ULL);

  const auto h2_origin = nexora::OriginKey::Create(nexora::Scheme::kHttps, "h2cap.example", 443);
  if (!lease_pool.RegisterConnection(h2_origin, nexora::PooledConnection{
                                                    .connection_id = 91,
                                                    .version = nexora::Version::kHttp2,
                                                    .max_concurrent_streams = 2,
                                                })) {
    return 74;
  }
  auto l1 = lease_pool.Acquire(h2_origin, nexora::Version::kHttp2, 100);
  auto l2 = lease_pool.Acquire(h2_origin, nexora::Version::kHttp2, 100);
  if (!l1 || !l2 || lease_pool.Acquire(h2_origin, nexora::Version::kHttp2, 100).has_value()) {
    return 75;
  }
  lease_pool.Release(*l1, 150);
  lease_pool.Release(*l1, 160);
  if (lease_pool.Entry(h2_origin)->connections[0].active_streams != 1) {
    return 76;
  }
  lease_pool.Release(*l2, 170);
  return 0;
}

int TestH2LeaseOverBitmap() noexcept {
  nexora::OriginPool<4> pool{nexora::PoolConfig{
      .max_connections_per_origin = 2,
      .max_streams_per_h2_connection = 300,
  }};
  const auto origin = nexora::OriginKey::Create(nexora::Scheme::kHttps, "lease.example", 443);
  std::vector<nexora::PoolSlotToken> tokens;
  tokens.reserve(300);
  std::array<int, 4> per_slot{};
  for (int i = 0; i < 300; ++i) {
    auto tok = pool.Acquire(origin, nexora::Version::kHttp2, 1000);
    if (!tok || tok->lease == 0U || tok->slot >= per_slot.size()) return 1;
    ++per_slot[tok->slot];
    tokens.push_back(*tok);
  }
  if (per_slot[0] != 256 || per_slot[1] != 44 || per_slot[2] != 0) return 2;
  for (const auto& tok : tokens) {
    if (!pool.Release(tok, 2000)) return 3;
  }
  for (int i = 0; i < 300; ++i) {
    auto tok = pool.Acquire(origin, nexora::Version::kHttp2, 3000);
    if (!tok || tok->lease == 0U || !pool.Release(*tok, 3001)) return 4;
  }
  return 0;
}

int TestTokenSaturationNeverWraps() noexcept {
  const auto origin = nexora::OriginKey::Create(nexora::Scheme::kHttps, "sat.example", 443);
  nexora::OriginPool<1> lease_sat{nexora::PoolConfig{
      .max_connections_per_origin = 1,
      .max_streams_per_h2_connection = 256,
  }};
  nexora::detail::OriginPoolTestPeer::PrimeSaturation(lease_sat, 0, 1, 0x00FF'FFFEU);
  std::array<nexora::PoolSlotToken, 256> max_leases{};
  for (std::uint32_t i = 0; i < 256; ++i) {
    auto tok = lease_sat.Acquire(origin, nexora::Version::kHttp2, 10);
    if (!tok || (tok->lease >> 8U) != 0x00FF'FFFFU || (tok->lease & 0xFFU) != i) return 80;
    max_leases[i] = *tok;
  }
  for (const auto& tok : max_leases) {
    if (!lease_sat.Release(tok, 20)) return 81;
  }
  if (lease_sat.Release(max_leases[0], 21) || lease_sat.Release(nexora::PoolSlotToken{0, 1, (1U << 8U) | 0U}, 21)) return 82;
  auto exhausted_lease = lease_sat.Acquire(origin, nexora::Version::kHttp2, 30);
  if (exhausted_lease.has_value() ||
      exhausted_lease.error() != nexora::Error::FromRuntime(nexora::RuntimeErrorCode::kPoolExhausted))
    return 83;

  nexora::OriginPool<1> gen_sat{nexora::PoolConfig{
      .max_connections_per_origin = 1,
      .idle_timeout_ns = 10ULL,
      .max_lifetime_ns = 100ULL,
  }};
  auto gen1 = gen_sat.Acquire(origin, nexora::Version::kHttp11, 10);
  if (!gen1 || gen1->generation != 1 || !gen_sat.Release(*gen1, 15) || gen_sat.EvictExpired(30) != 1) return 84;
  nexora::detail::OriginPoolTestPeer::PrimeSaturation(gen_sat, 0, 0xFFFEU, 0U);
  auto gen_prev = gen_sat.Acquire(origin, nexora::Version::kHttp11, 40);
  if (!gen_prev || gen_prev->generation != 0xFFFEU || !gen_sat.Release(*gen_prev, 45) || gen_sat.EvictExpired(60) != 1)
    return 85;
  auto gen_max = gen_sat.Acquire(origin, nexora::Version::kHttp11, 70);
  if (!gen_max || gen_max->generation != 0xFFFFU || !gen_sat.Release(*gen_max, 75) || gen_sat.EvictExpired(90) != 1) return 86;
  auto exhausted_slot = gen_sat.Acquire(origin, nexora::Version::kHttp11, 100);
  if (exhausted_slot.has_value() ||
      exhausted_slot.error() != nexora::Error::FromRuntime(nexora::RuntimeErrorCode::kPoolExhausted))
    return 87;
  if (gen_sat.Release(*gen1, 110) || gen_sat.Release(*gen_max, 110)) return 88;
  return 0;
}

}  // namespace

int main() {
  if (const int rc = TestOriginKeyNormalization(); rc != 0) return rc;
  if (const int rc = TestOriginPoolWaiterCoalescingAndSlots(); rc != 0) return rc;
  if (const int rc = TestPoolExhaustionIsolation(); rc != 0) return rc;
  if (const int rc = TestEndpointFailoverQuarantineAndRecovery(); rc != 0) return rc;
  if (const int rc = TestEndpointFailoverPoliciesReadyBitsAndObserver(); rc != 0) return rc;
  if (const int rc = TestZeroGlueReconcileEwmaMaxAndLeaseTokens(); rc != 0) return rc;
  if (const int rc = TestH2LeaseOverBitmap(); rc != 0) return rc;
  if (const int rc = TestTokenSaturationNeverWraps(); rc != 0) return rc;
  return 0;
}
