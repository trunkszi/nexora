#pragma once
#include <cares/cares.hpp>
#include <chrono>
#include <nexora/client/detail/private_ring_route.hpp>
#include <nexora/dispatch/completion_routes.hpp>
#include <nexora/tls/secure_stream.hpp>
#include <utility>

namespace nexora::detail {
class EndpointResolution {
  cares::Resolver<>* resolver_;
  CompletionRoute fallback_;

 public:
  std::optional<cares::Result<cares::EndpointList>> result{};
  EndpointResolution(cares::Resolver<>& resolver, CompletionRoute fallback) noexcept
      : resolver_(&resolver), fallback_(fallback) {}
  void OnResult(cares::Result<cares::EndpointList> value) noexcept { result.emplace(std::move(value)); }
  [[nodiscard]] bool CanRoute(std::uint8_t id) const noexcept { return resolver_->CanRoute(id) || fallback_.Accepts(id); }
  [[nodiscard]] uring::Result<void> DispatchBatch(std::span<const uring::Delivery> deliveries) noexcept {
    std::optional<uring::UringErrorCode> error;
    for (const auto& delivery : deliveries) {
      if (resolver_->CanRoute(uring::Subsystem(delivery.completion.token)))
        resolver_->OnCompletions(std::span<const uring::Delivery>(&delivery, 1));
      else if (auto routed = fallback_.Dispatch(delivery); !routed && !error)
        error = routed.error();
    }
    if (error) return std::unexpected(*error);
    return {};
  }
};
[[nodiscard]] inline Result<cares::EndpointList> ResolveEndpoints(uring::Proactor& proactor, cares::Resolver<>& resolver,
                                                                  std::string_view target, std::uint16_t port,
                                                                  Deadline deadline, CompletionRoute fallback) noexcept {
  if (!HasRoute(fallback)) return std::unexpected(Error::InvalidArgument());
  EndpointResolution wait(resolver, fallback);
  ForeignObserverScope dispatcher(&resolver, wait);
  auto handle = resolver.SubmitEndpoints(target, port, cares::EndpointsCallback::Bind<&EndpointResolution::OnResult>(&wait));
  if (!handle) return std::unexpected(Error::DnsFailed(handle.error().raw_code));
  while (!wait.result) {
    resolver.StepDriver();
    if (dispatcher.Error()) {
      static_cast<void>(resolver.CancelQuery(*handle));
      return std::unexpected(Error::UringFailed(static_cast<std::int32_t>(std::to_underlying(*dispatcher.Error()))));
    }
    if (wait.result) break;
    const auto remaining = Remaining(deadline);
    if (remaining == 0) {
      static_cast<void>(resolver.CancelQuery(*handle));
      return std::unexpected(Error::Timeout());
    }
    auto driven = proactor.WaitCompletions(1, std::chrono::milliseconds(remaining), dispatcher);
    if (!driven && driven.error() == uring::UringErrorCode::kBusy) driven = proactor.Tick(dispatcher);
    if (!driven && driven.error() != uring::UringErrorCode::kTimedOut) {
      static_cast<void>(resolver.CancelQuery(*handle));
      return std::unexpected(Error::UringFailed(static_cast<std::int32_t>(std::to_underlying(driven.error()))));
    }
  }
  if (!*wait.result) return std::unexpected(Error::DnsFailed(wait.result->error().raw_code));
  return **wait.result;
}
}  // namespace nexora::detail
