#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <nexora/dispatch/completion_routes.hpp>
#include <type_traits>
#include <vector>

namespace {

static_assert(!std::is_copy_constructible_v<nexora::detail::SocketDmaQuarantine>);
static_assert(!std::is_move_constructible_v<nexora::detail::SocketDmaQuarantine>);
static_assert(!std::is_copy_assignable_v<nexora::detail::SocketDmaQuarantine>);
static_assert(!std::is_move_assignable_v<nexora::detail::SocketDmaQuarantine>);

static_assert(!std::is_copy_constructible_v<nexora::CompletionRoutes<4>>);
static_assert(!std::is_move_constructible_v<nexora::CompletionRoutes<4>>);
static_assert(!std::is_copy_assignable_v<nexora::CompletionRoutes<4>>);
static_assert(!std::is_move_assignable_v<nexora::CompletionRoutes<4>>);

struct MockSubsystemRoute {
  std::uint8_t subsystem_id{0};
  std::vector<std::int32_t> results{};

  [[nodiscard]] constexpr bool Accepts(std::uint8_t id) const noexcept { return id == subsystem_id; }

  [[nodiscard]] uring::Result<void> Dispatch(const uring::Delivery& delivery) noexcept {
    this->results.push_back(delivery.completion.result);
    return {};
  }
};

uring::Delivery MakeDelivery(std::uint8_t subsystem_id, std::uint16_t slot, std::int32_t result) noexcept {
  const auto token = uring::MakeToken(slot, 0, subsystem_id, 1);
  return uring::Delivery{
      .key = {.token = token, .ring_instance = 1},
      .completion = {.token = token, .result = result, .flags = 0},
  };
}

int TestFixedCapacityCompletionRoutesTable() noexcept {
  nexora::CompletionRoutes<4> table{};
  std::vector<std::int32_t> dns_cqe{};
  std::vector<std::int32_t> sock_cqe{};

  const nexora::CompletionRoute r_dns{
      .subsystem_id = nexora::kDnsSubsystemId,
      .ctx = &dns_cqe,
      .on_cqe =
          +[](void* ctx, nexora::CompletionEvent cqe) noexcept {
            static_cast<std::vector<std::int32_t>*>(ctx)->push_back(cqe.result);
          },
  };
  const auto r_sock = nexora::CompletionRoute::Make<nexora::kSocketSubsystemId>(
      &sock_cqe, +[](void* ctx, nexora::CompletionEvent cqe) noexcept {
        static_cast<std::vector<std::int32_t>*>(ctx)->push_back(cqe.result);
      });

  if (!table.Register(r_dns) || !table.Register(r_sock) || table.Size() != 2) {
    return 1;
  }
  // Reject duplicate subsystem ID or reserved IDs 0 and 255.
  if (table.Register(r_dns).has_value()) {
    return 2;
  }
  if (table.Register(nexora::CompletionRoute{.subsystem_id = 0, .ctx = &dns_cqe, .on_cqe = r_dns.on_cqe}).has_value() ||
      table.Register(nexora::CompletionRoute{.subsystem_id = 255, .ctx = &dns_cqe, .on_cqe = r_dns.on_cqe}).has_value()) {
    return 3;
  }

  table.OnCompletion(MakeDelivery(nexora::kDnsSubsystemId, 1, 111).completion);
  table(MakeDelivery(nexora::kSocketSubsystemId, 2, 222).completion);
  if (dns_cqe != std::vector<std::int32_t>{111} || sock_cqe != std::vector<std::int32_t>{222}) {
    return 4;
  }
  return 0;
}

int TestRouteChainingAndBatchDispatch() noexcept {
  MockSubsystemRoute dns_route{.subsystem_id = nexora::kDnsSubsystemId};
  MockSubsystemRoute sock_route{.subsystem_id = nexora::kSocketSubsystemId};
  MockSubsystemRoute inbox_route{.subsystem_id = nexora::kInboxSubsystemId};

  const auto r1 = nexora::CompletionRoute::Bind(dns_route);
  const auto r2 = nexora::CompletionRoute::Bind(sock_route);
  const auto r3 = nexora::CompletionRoute::Bind(inbox_route);

  auto routes = r1.Chain(r2).Chain(r3);
  static_assert(!std::is_copy_constructible_v<decltype(routes)>);
  static_assert(!std::is_move_constructible_v<decltype(routes)>);
  static_assert(!std::is_copy_assignable_v<decltype(routes)>);
  static_assert(!std::is_move_assignable_v<decltype(routes)>);
  if (!routes.CanRoute(nexora::kDnsSubsystemId) || !routes.CanRoute(nexora::kSocketSubsystemId) ||
      !routes.CanRoute(nexora::kInboxSubsystemId)) {
    return 10;
  }
  if (routes.CanRoute(0) || routes.CanRoute(255) || routes.CanRoute(99)) {
    return 11;
  }

  const std::array<uring::Delivery, 3> batch{
      MakeDelivery(nexora::kDnsSubsystemId, 1, 10),
      MakeDelivery(nexora::kSocketSubsystemId, 2, 20),
      MakeDelivery(nexora::kInboxSubsystemId, 3, 30),
  };
  if (auto res = routes.DispatchBatch(batch); !res) {
    return 12;
  }
  if (dns_route.results != std::vector<std::int32_t>{10} || sock_route.results != std::vector<std::int32_t>{20} ||
      inbox_route.results != std::vector<std::int32_t>{30}) {
    return 13;
  }

  // Unrouted subsystem ID returns kNoEntry.
  const auto unrouted = routes.Dispatch(MakeDelivery(42, 4, 0));
  if (unrouted.has_value() || unrouted.error() != uring::UringErrorCode::kNoEntry) {
    return 14;
  }

  // Reserved subsystem ID 0 returns kInvalid.
  const auto reserved = routes.Dispatch(MakeDelivery(0, 5, 0));
  if (reserved.has_value() || reserved.error() != uring::UringErrorCode::kInvalid) {
    return 15;
  }

  // Overlapping subsystem IDs return kInvalid.
  MockSubsystemRoute dup_dns{.subsystem_id = nexora::kDnsSubsystemId};
  auto overlapping =
      nexora::MakeCompletionRoutes(nexora::CompletionRoute::Bind(dns_route), nexora::CompletionRoute::Bind(dup_dns));
  const auto overlap_res = overlapping.Dispatch(MakeDelivery(nexora::kDnsSubsystemId, 6, 99));
  if (overlap_res.has_value() || overlap_res.error() != uring::UringErrorCode::kInvalid) {
    return 16;
  }
  return 0;
}

struct ClaimingSocket {
  uring::UserDataToken token{};
  int hits{0};
  std::int32_t result{0};

  [[nodiscard]] static constexpr bool Accepts(std::uint8_t id) noexcept { return id == nexora::kSocketSubsystemId; }

  [[nodiscard]] bool Dispatch(const uring::Delivery& delivery) noexcept {
    if (delivery.completion.token != token) return false;
    ++hits;
    result = delivery.completion.result;
    return true;
  }
};

int TestClaimingSubscribersShareSocketSubsystem() noexcept {
  ClaimingSocket first{};
  ClaimingSocket second{};
  first.token = uring::MakeToken(1, 0, nexora::kSocketSubsystemId, 1);
  second.token = uring::MakeToken(2, 0, nexora::kSocketSubsystemId, 1);
  nexora::CompletionRoutes<4> table{};
  if (!table.Register(nexora::CompletionRoute::Bind(first)) || !table.Register(nexora::CompletionRoute::Bind(second)) ||
      table.Size() != 2) {
    return 20;
  }
  if (auto claimed = table.Dispatch(MakeDelivery(nexora::kSocketSubsystemId, 2, 42));
      !claimed || second.hits != 1 || second.result != 42 || first.hits != 0) {
    return 21;
  }
  if (auto claimed = table.Dispatch(MakeDelivery(nexora::kSocketSubsystemId, 1, 7));
      !claimed || first.hits != 1 || first.result != 7 || second.hits != 1) {
    return 22;
  }
  if (!table.Unregister(&first) || table.Size() != 1 || table.Unregister(&first)) return 23;
  const auto orphan = table.Dispatch(MakeDelivery(nexora::kSocketSubsystemId, 1, 9));
  if (orphan.has_value() || orphan.error() != uring::UringErrorCode::kNoEntry || first.hits != 1) return 24;
  if (!table.Unregister(&second) || !table.Empty()) return 25;
  return 0;
}

struct BoolClaim {
  uring::UserDataToken token{};
  int hits{0};
  [[nodiscard]] bool OnDelivery(const uring::Delivery& delivery) noexcept {
    if (delivery.completion.token != token) return false;
    ++hits;
    return true;
  }
};

struct ResultClaim {
  uring::UserDataToken token{};
  int hits{0};
  [[nodiscard]] uring::Result<int> OnDelivery(const uring::Delivery& delivery) noexcept {
    if (delivery.completion.token != token) return std::unexpected(uring::UringErrorCode::kNoEntry);
    ++hits;
    return delivery.completion.result;
  }
};

uring::Result<bool> AcceptSocket(void*, std::uint8_t id, const uring::Delivery*) noexcept {
  if (id == nexora::kSocketSubsystemId) return true;
  return std::unexpected(uring::UringErrorCode::kNoEntry);
}

uring::Result<bool> AcceptDns(void*, std::uint8_t id, const uring::Delivery*) noexcept {
  if (id == nexora::kDnsSubsystemId) return true;
  return std::unexpected(uring::UringErrorCode::kNoEntry);
}

int TestClaimTypeOverlap() noexcept {
  BoolClaim left{};
  ResultClaim right{};
  left.token = uring::MakeToken(3, 0, nexora::kSocketSubsystemId, 1);
  right.token = uring::MakeToken(4, 0, nexora::kSocketSubsystemId, 1);
  nexora::CompletionRoutes<4> table{};
  const auto left_route =
      nexora::CompletionRoute::BindClaiming<nexora::kSocketSubsystemId, BoolClaim, &BoolClaim::OnDelivery>(&left);
  const auto right_route =
      nexora::CompletionRoute::BindClaiming<nexora::kSocketSubsystemId, ResultClaim, &ResultClaim::OnDelivery>(&right);
  if (left_route.exclusive || right_route.exclusive) return 30;
  if (!table.Register(left_route) || !table.Register(right_route)) return 31;
  if (auto claimed = table.Dispatch(MakeDelivery(nexora::kSocketSubsystemId, 4, 11));
      !claimed || right.hits != 1 || left.hits != 0) {
    return 32;
  }
  if (auto claimed = table.Dispatch(MakeDelivery(nexora::kSocketSubsystemId, 3, 12)); !claimed || left.hits != 1) return 33;

  nexora::CompletionRoute exclusive_socket{
      .subsystem_id = 0,
      .ctx = nullptr,
      .on_cqe = nullptr,
      .step = &AcceptSocket,
      .exclusive = true,
  };
  nexora::CompletionRoute exclusive_dns{
      .subsystem_id = 0,
      .ctx = nullptr,
      .on_cqe = nullptr,
      .step = &AcceptDns,
      .exclusive = true,
  };
  nexora::CompletionRoutes<4> exclusive{};
  if (!exclusive.Register(exclusive_dns)) return 34;
  if (exclusive.Register(exclusive_socket)) {
    const auto dup =
        nexora::CompletionRoute::Make<nexora::kSocketSubsystemId>(&left, +[](void*, nexora::CompletionEvent) noexcept {});
    if (exclusive.Register(dup)) return 35;
  } else {
    return 36;
  }
  const auto overlap =
      nexora::CompletionRoute::Make<nexora::kDnsSubsystemId>(&left, +[](void*, nexora::CompletionEvent) noexcept {});
  if (exclusive.Register(overlap)) return 37;
  if (!table.Unregister(&left) || !table.Unregister(&right)) return 38;
  return 0;
}

int TestQuarantineClosesOverflow() noexcept {
  nexora::detail::SocketDmaQuarantine quarantine{};
  const int overflow_fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (overflow_fd < 0) return 40;
  for (std::uint16_t slot = 0; slot < nexora::detail::SocketDmaQuarantine::kCapacity; ++slot) {
    const auto token = uring::MakeToken(slot, 0, nexora::kSocketSubsystemId, 1);
    quarantine.Park(9, -1, std::vector<std::uint8_t>(8, 1), {}, token, std::nullopt, std::nullopt);
  }
  const auto extra = uring::MakeToken(80, 0, nexora::kSocketSubsystemId, 1);
  quarantine.Park(9, overflow_fd, std::vector<std::uint8_t>(8, 2), {}, extra, std::nullopt, std::nullopt);
  if (quarantine.ActiveCount() != nexora::detail::SocketDmaQuarantine::kCapacity + 1) return 41;
  quarantine.CloseAllFds();
  if (quarantine.ActiveCount() != nexora::detail::SocketDmaQuarantine::kCapacity + 1) return 42;
  const auto kept = uring::MakeToken(0, 0, nexora::kSocketSubsystemId, 1);
  if (!quarantine.TryRetire(kept, 0, -ECANCELED) ||
      quarantine.ActiveCount() != nexora::detail::SocketDmaQuarantine::kCapacity) {
    return 43;
  }
  if (!quarantine.TryRetire(extra, 9, -ECANCELED) || ::fcntl(overflow_fd, F_GETFD) != -1 || errno != EBADF) return 44;
  return 0;
}

struct SiblingClaim {
  nexora::CompletionRoutes<4>* table{nullptr};
  int hits{0};
  bool drop_self{false};
  bool claim{false};

  [[nodiscard]] static constexpr bool Accepts(std::uint8_t id) noexcept { return id == nexora::kSocketSubsystemId; }

  [[nodiscard]] bool Dispatch(const uring::Delivery&) noexcept {
    ++hits;
    if (drop_self && table != nullptr && !table->Unregister(this)) return false;
    return claim;
  }
};

int TestReentrantUnregisterStillClaims() noexcept {
  nexora::CompletionRoutes<4> table{};
  SiblingClaim a{};
  SiblingClaim b{};
  SiblingClaim c{};
  b.table = &table;
  b.drop_self = true;
  c.claim = true;
  if (!table.Register(nexora::CompletionRoute::Bind(a)) || !table.Register(nexora::CompletionRoute::Bind(b)) ||
      !table.Register(nexora::CompletionRoute::Bind(c)) || table.Size() != 3) {
    return 80;
  }
  if (auto claimed = table.Dispatch(MakeDelivery(nexora::kSocketSubsystemId, 9, 5));
      !claimed || a.hits != 1 || b.hits != 1 || c.hits != 1 || table.Size() != 2) {
    return 81;
  }
  return 0;
}

int TestOverflowKeepsSocketAccepts() noexcept {
  nexora::CompletionRoutes<2> table{};
  const int overflow_fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (overflow_fd < 0) return 90;
  for (std::uint16_t slot = 0; slot < nexora::detail::SocketDmaQuarantine::kCapacity; ++slot) {
    const auto token = uring::MakeToken(slot, 0, nexora::kSocketSubsystemId, 1);
    table.Quarantine().Park(9, -1, std::vector<std::uint8_t>{}, {}, token, std::nullopt, std::nullopt);
  }
  const auto extra = uring::MakeToken(65, 0, nexora::kSocketSubsystemId, 1);
  table.Quarantine().Park(9, overflow_fd, std::vector<std::uint8_t>{}, {}, extra, std::nullopt, std::nullopt);
  for (std::uint16_t slot = 0; slot < nexora::detail::SocketDmaQuarantine::kCapacity; ++slot) {
    const auto token = uring::MakeToken(slot, 0, nexora::kSocketSubsystemId, 1);
    if (!table.Quarantine().TryRetire(token, 9, -ECANCELED)) return 91;
  }
  if (!table.Empty() || !table.Accepts(nexora::kSocketSubsystemId) || ::fcntl(overflow_fd, F_GETFD) == -1) return 92;
  const uring::Delivery delivery{
      .key = {.token = extra, .ring_instance = 9},
      .completion = {.token = extra, .result = -ECANCELED, .flags = 0},
  };
  if (!table.Dispatch(delivery) || table.Accepts(nexora::kSocketSubsystemId) || ::fcntl(overflow_fd, F_GETFD) != -1 ||
      errno != EBADF) {
    return 93;
  }
  return 0;
}

bool RetireParkedOwner(void* owner, uring::UserDataToken, std::uint64_t) noexcept {
  ++*static_cast<int*>(owner);
  return true;
}

int TestParkedRouteKeepsAccepts() noexcept {
  int hits = 0;
  nexora::CompletionRoutes<2> table{};
  const auto route =
      nexora::CompletionRoute::Make<nexora::kDnsSubsystemId>(&hits, +[](void*, nexora::CompletionEvent) noexcept {});
  if (!table.Register(route)) return 100;
  const auto token = uring::MakeToken(11, 1, nexora::kDnsSubsystemId, 2);
  if (!nexora::detail::SharedParkedRegistry().Register(token, 4, {&hits, &RetireParkedOwner})) return 101;
  if (!table.Unregister(&hits) || !table.Empty()) return 102;
  if (!table.Accepts(nexora::kDnsSubsystemId)) return 103;
  const uring::Delivery delivery{
      .key = {.token = token, .ring_instance = 4},
      .completion = {.token = token, .result = -125, .flags = 0},
  };
  if (!table.Dispatch(delivery) || hits != 1) return 104;
  if (table.Accepts(nexora::kDnsSubsystemId) || nexora::detail::SharedParkedRegistry().ActiveCount() != 0) return 105;
  return 0;
}

}  // namespace

int main() {
  if (const int rc = TestFixedCapacityCompletionRoutesTable(); rc != 0) {
    return rc;
  }
  if (const int rc = TestRouteChainingAndBatchDispatch(); rc != 0) {
    return rc;
  }
  if (const int rc = TestClaimingSubscribersShareSocketSubsystem(); rc != 0) {
    return rc;
  }
  if (const int rc = TestClaimTypeOverlap(); rc != 0) {
    return rc;
  }
  if (const int rc = TestQuarantineClosesOverflow(); rc != 0) {
    return rc;
  }
  if (const int rc = TestReentrantUnregisterStillClaims(); rc != 0) {
    return rc;
  }
  if (const int rc = TestOverflowKeepsSocketAccepts(); rc != 0) {
    return rc;
  }
  if (const int rc = TestParkedRouteKeepsAccepts(); rc != 0) {
    return rc;
  }
  return 0;
}
