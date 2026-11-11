#pragma once
#include <cstdlib>
#include <nexora/dispatch/completion_routes.hpp>
#include <nexora/dispatch/parked_registry.hpp>

namespace nexora::detail {
[[nodiscard]] inline bool HasRoute(CompletionRoute route) noexcept {
  return route.step != nullptr || (route.on_cqe != nullptr && route.subsystem_id != uring::kInternalSubsystemId &&
                                   route.subsystem_id != uring::kMailboxSubsystemId);
}
// Only the convenience driver owns this ring; an unrelated delivery violates that ownership.
[[nodiscard]] inline CompletionRoute PrivateRingRoute() noexcept {
  CompletionRoute route{};
  route.step = +[](void*, std::uint8_t, const uring::Delivery* delivery) noexcept -> uring::Result<bool> {
    if (delivery != nullptr && !RetireParked(delivery->completion.token, delivery->key.ring_instance)) std::abort();
    return true;
  };
  return route;
}
}  // namespace nexora::detail
