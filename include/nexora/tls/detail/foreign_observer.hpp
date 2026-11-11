#pragma once
#include <cares/cares.hpp>
#include <nexora/dispatch/parked_registry.hpp>
#include <optional>
#include <span>
#include <uring/uring.hpp>

namespace nexora::detail {
// A resolver pump can reap completions owned by this transport or the caller's router.
template <typename Router>
class ForeignObserverScope {
  cares::Resolver<>* resolver_;
  Router* router_;
  cares::ForeignBatchObserver previous_{};
  std::optional<uring::UringErrorCode> error_{};

 public:
  ForeignObserverScope(cares::Resolver<>* resolver, Router& router) noexcept : resolver_(resolver), router_(&router) {
    if (resolver_) {
      previous_ = resolver_->ForeignObserver();
      resolver_->BindForeignRouter(this);
    }
  }
  ForeignObserverScope(const ForeignObserverScope&) = delete ("observer binding must be restored by one scope");
  ForeignObserverScope& operator=(const ForeignObserverScope&) = delete ("observer binding must be restored by one scope");
  ~ForeignObserverScope() noexcept {
    if (resolver_) resolver_->SetForeignBatchObserver(previous_);
  }
  [[nodiscard]] bool CanRoute(std::uint8_t id) const noexcept { return router_->CanRoute(id) || static_cast<bool>(previous_); }
  [[nodiscard]] bool Owns(const uring::Delivery& delivery) const noexcept {
    if constexpr (requires { router_->CanRouteDelivery(delivery); })
      return router_->CanRouteDelivery(delivery);
    else
      return router_->CanRoute(uring::Subsystem(delivery.completion.token));
  }
  [[nodiscard]] uring::Result<void> DispatchBatch(std::span<const uring::Delivery> deliveries) noexcept {
    error_.reset();
    for (const auto& delivery : deliveries) {
      const auto one = std::span<const uring::Delivery>(&delivery, 1);
      if (RetireParked(delivery.completion.token, delivery.key.ring_instance)) continue;
      if (Owns(delivery)) {
        if (auto dispatched = router_->DispatchBatch(one); !dispatched && !error_) error_ = dispatched.error();
      } else if (previous_)
        previous_(one);
      else if (!error_)
        error_ = uring::UringErrorCode::kInvalid;
    }
    if (error_) return std::unexpected(*error_);
    return {};
  }
  void OnForeignDeliveries(std::span<const uring::Delivery> deliveries) noexcept {
    if (const auto dispatched = DispatchBatch(deliveries); !dispatched && !error_) error_ = dispatched.error();
  }
  [[nodiscard]] auto Error() const noexcept { return error_; }
};
}  // namespace nexora::detail
