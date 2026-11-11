#pragma once

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <nexora/dispatch/dma_quarantine.hpp>
#include <nexora/dispatch/parked_registry.hpp>
#include <nexora/error/runtime_error.hpp>
#include <optional>
#include <span>
#include <tuple>
#include <type_traits>
#include <uarch/uarch.hpp>
#include <uring/uring.hpp>
#include <utility>

namespace nexora {

using CompletionEvent = uring::Completion;

// Canonical uring::Proactor Subsystem ID table (0 and 255 are reserved by uring).
inline constexpr std::uint8_t kDefaultSocketIoSubsystemId = 1;
inline constexpr std::uint8_t kDnsSubsystemId = 2;
inline constexpr std::uint8_t kSocketSubsystemId = 3;
inline constexpr std::uint8_t kInboxSubsystemId = 4;
inline constexpr std::uint8_t kServerSubsystemId = 5;

namespace detail {

template <typename Ret>
[[nodiscard]] inline uring::Result<bool> AsClaim(Ret&& ret) noexcept {
  using T = std::remove_cvref_t<Ret>;
  if constexpr (std::same_as<T, bool>) {
    return static_cast<bool>(ret);
  } else if constexpr (std::same_as<T, uring::Result<void>>) {
    if (!ret) return std::unexpected(ret.error());
    return true;
  } else if constexpr (std::same_as<T, Result<void>>) {
    if (!ret) return std::unexpected(uring::UringErrorCode::kInvalid);
    return true;
  } else if constexpr (requires { ret.has_value(); }) {
    if (!ret) {
      using Err = std::remove_cvref_t<decltype(ret.error())>;
      if constexpr (std::same_as<Err, uring::UringErrorCode>)
        return std::unexpected(ret.error());
      else
        return std::unexpected(uring::UringErrorCode::kInvalid);
    }
    if constexpr (requires { requires std::same_as<std::remove_cvref_t<decltype(*ret)>, bool>; }) {
      return static_cast<bool>(*ret);
    } else {
      return true;
    }
  } else {
    return true;
  }
}

template <typename R>
[[nodiscard]] constexpr bool RouteAccepts(const R& route, std::uint8_t subsystem_id) noexcept {
  if constexpr (requires {
                  { route.Accepts(subsystem_id) } -> std::convertible_to<bool>;
                }) {
    return route.Accepts(subsystem_id);
  } else if constexpr (requires {
                         { route.CanRoute(subsystem_id) } -> std::convertible_to<bool>;
                       }) {
    return route.CanRoute(subsystem_id);
  } else if constexpr (requires {
                         { route.IsRoutable(subsystem_id) } -> std::convertible_to<bool>;
                       }) {
    return route.IsRoutable(subsystem_id);
  } else {
    return false;
  }
}

template <typename R>
[[nodiscard]] inline uring::Result<void> RouteDispatchOne(R& route, const uring::Delivery& delivery) noexcept {
  if constexpr (requires { route.Dispatch(delivery); }) {
    using Ret = decltype(route.Dispatch(delivery));
    if constexpr (std::is_void_v<Ret>) {
      route.Dispatch(delivery);
      return {};
    } else {
      auto claim = AsClaim(route.Dispatch(delivery));
      if (!claim) return std::unexpected(claim.error());
      if (!*claim) return std::unexpected(uring::UringErrorCode::kNoEntry);
      return {};
    }
  } else if constexpr (requires { route.DispatchBatch(std::span<const uring::Delivery>{&delivery, 1}); }) {
    const std::span<const uring::Delivery> single{&delivery, 1};
    auto res = route.DispatchBatch(single);
    if (!res) return std::unexpected(res.error());
    return {};
  } else {
    return std::unexpected(uring::UringErrorCode::kNoEntry);
  }
}

}  // namespace detail

template <typename R>
concept CompletionRouteLike =
    (requires(const std::remove_cvref_t<R>& route, std::uint8_t id) {
      { route.Accepts(id) } -> std::convertible_to<bool>;
    } || requires(const std::remove_cvref_t<R>& route, std::uint8_t id) {
      { route.CanRoute(id) } -> std::convertible_to<bool>;
    }) &&
    (requires(std::remove_cvref_t<R>& route, const uring::Delivery& delivery) { route.Dispatch(delivery); } ||
     requires(std::remove_cvref_t<R>& route, std::span<const uring::Delivery> batch) { route.DispatchBatch(batch); });

template <CompletionRouteLike... Routes>
class ChainedCompletionRoutes;

struct CompletionRoute {
  using OnCqeFn = void (*)(void* ctx, CompletionEvent cqe) noexcept;
  using StepFn = uring::Result<bool> (*)(void* context, std::uint8_t subsystem_id, const uring::Delivery* delivery) noexcept;

  std::uint8_t subsystem_id{0};
  void* ctx{nullptr};
  OnCqeFn on_cqe{nullptr};
  StepFn step{nullptr};
  bool exclusive{true};

  template <std::uint8_t SubsystemId>
  [[nodiscard]] static constexpr CompletionRoute Make(void* context, OnCqeFn fn) noexcept {
    static_assert(SubsystemId != uring::kInternalSubsystemId && SubsystemId != uring::kMailboxSubsystemId,
                  "subsystem ID 0 and 255 are reserved");
    return CompletionRoute{
        .subsystem_id = SubsystemId,
        .ctx = context,
        .on_cqe = fn,
        .step = nullptr,
    };
  }

  template <typename T>
    requires CompletionRouteLike<T>
  [[nodiscard]] static constexpr CompletionRoute Bind(T& target) noexcept {
    return CompletionRoute{
        .subsystem_id = 0,
        .ctx = static_cast<void*>(&target),
        .on_cqe = nullptr,
        .step = +[](void* context, std::uint8_t id, const uring::Delivery* delivery) noexcept -> uring::Result<bool> {
          auto* self = static_cast<T*>(context);
          if (delivery == nullptr) {
            return detail::RouteAccepts(*self, id);
          }
          if (!detail::RouteAccepts(*self, id)) {
            return std::unexpected(uring::UringErrorCode::kNoEntry);
          }
          auto res = detail::RouteDispatchOne(*self, *delivery);
          if (!res) {
            return std::unexpected(res.error());
          }
          return true;
        },
        .exclusive = false,
    };
  }

  template <std::uint8_t SubsystemId, typename T, auto Method>
  [[nodiscard]] static constexpr CompletionRoute BindMethod(T* instance) noexcept {
    static_assert(SubsystemId != uring::kInternalSubsystemId && SubsystemId != uring::kMailboxSubsystemId,
                  "subsystem ID 0 and 255 are reserved");
    return CompletionRoute{
        .subsystem_id = SubsystemId,
        .ctx = static_cast<void*>(instance),
        .on_cqe =
            +[](void* context, CompletionEvent cqe) noexcept {
              auto* self = static_cast<T*>(context);
              if constexpr (requires { (self->*Method)(cqe); }) {
                static_cast<void>((self->*Method)(cqe));
              } else {
                const uring::Delivery delivery{.key = {cqe.token, 0}, .completion = cqe};
                static_cast<void>((self->*Method)(delivery));
              }
            },
        .step = +[](void* context, std::uint8_t id, const uring::Delivery* delivery) noexcept -> uring::Result<bool> {
          if (delivery == nullptr) {
            return id == SubsystemId;
          }
          if (id != SubsystemId) {
            return std::unexpected(uring::UringErrorCode::kNoEntry);
          }
          auto* self = static_cast<T*>(context);
          if constexpr (requires { (self->*Method)(*delivery); }) {
            using Ret = decltype((self->*Method)(*delivery));
            if constexpr (std::is_void_v<Ret>) {
              (self->*Method)(*delivery);
              return true;
            } else {
              return detail::AsClaim((self->*Method)(*delivery));
            }
          } else if constexpr (requires { (self->*Method)(delivery->completion); }) {
            using Ret = decltype((self->*Method)(delivery->completion));
            if constexpr (std::is_void_v<Ret>) {
              (self->*Method)(delivery->completion);
              return true;
            } else {
              return detail::AsClaim((self->*Method)(delivery->completion));
            }
          }
          return false;
        },
    };
  }

  template <std::uint8_t SubsystemId, typename T, auto Method>
  [[nodiscard]] static constexpr CompletionRoute BindClaiming(T* instance) noexcept {
    auto route = BindMethod<SubsystemId, T, Method>(instance);
    route.exclusive = false;
    return route;
  }

  [[nodiscard, gnu::always_inline]] constexpr bool Accepts(std::uint8_t id) const noexcept {
    if (id == uring::kInternalSubsystemId || id == uring::kMailboxSubsystemId) return false;
    if (step != nullptr) {
      auto res = step(ctx, id, nullptr);
      return res.has_value() && *res;
    }
    return on_cqe != nullptr && subsystem_id == id;
  }
  [[nodiscard, gnu::always_inline]] constexpr bool CanRoute(std::uint8_t id) const noexcept { return Accepts(id); }
  [[nodiscard, gnu::always_inline]] constexpr bool IsRoutable(std::uint8_t id) const noexcept { return Accepts(id); }

  [[nodiscard, gnu::always_inline]] uring::Result<void> Dispatch(const uring::Delivery& delivery) const noexcept {
    const std::uint8_t id = uring::Subsystem(delivery.completion.token);
    if (id == uring::kInternalSubsystemId || id == uring::kMailboxSubsystemId) {
      return std::unexpected(uring::UringErrorCode::kInvalid);
    }
    if (step != nullptr) {
      auto res = step(ctx, id, &delivery);
      if (!res) return std::unexpected(res.error());
      if (!*res) return std::unexpected(uring::UringErrorCode::kNoEntry);
      return {};
    }
    if (on_cqe != nullptr && subsystem_id == id) {
      on_cqe(ctx, delivery.completion);
      return {};
    }
    return std::unexpected(uring::UringErrorCode::kNoEntry);
  }

  [[nodiscard]] uring::Result<void> DispatchBatch(std::span<const uring::Delivery> deliveries) const noexcept {
    std::optional<uring::UringErrorCode> first_error{};
    for (const auto& delivery : deliveries) {
      auto res = Dispatch(delivery);
      if (!res && !first_error.has_value()) first_error = res.error();
    }
    if (first_error.has_value()) return std::unexpected(*first_error);
    return {};
  }

  template <CompletionRouteLike Next>
  [[nodiscard]] constexpr ChainedCompletionRoutes<CompletionRoute, std::decay_t<Next>> Chain(Next&& next) const noexcept;
};

template <CompletionRouteLike... Routes>
class ChainedCompletionRoutes {
  static_assert(sizeof...(Routes) >= 2, "ChainedCompletionRoutes requires at least two routes");
  std::tuple<Routes...> routes_;

 public:
  template <typename... Args>
    requires(sizeof...(Args) == sizeof...(Routes) && (std::constructible_from<Routes, Args> && ...))
  explicit constexpr ChainedCompletionRoutes(Args&&... args) noexcept : routes_(std::forward<Args>(args)...) {}

  ChainedCompletionRoutes(const ChainedCompletionRoutes&) =
      delete ("CompletionRoutes is pinned by bound sockets and Proactor callbacks");
  ChainedCompletionRoutes& operator=(const ChainedCompletionRoutes&) =
      delete ("CompletionRoutes is pinned by bound sockets and Proactor callbacks");
  ChainedCompletionRoutes(ChainedCompletionRoutes&&) =
      delete ("CompletionRoutes is pinned by bound sockets and Proactor callbacks");
  ChainedCompletionRoutes& operator=(ChainedCompletionRoutes&&) =
      delete ("CompletionRoutes is pinned by bound sockets and Proactor callbacks");

  [[nodiscard]] constexpr auto& FirstRoute() noexcept { return std::get<0>(routes_); }
  [[nodiscard]] constexpr const auto& FirstRoute() const noexcept { return std::get<0>(routes_); }
  [[nodiscard]] constexpr auto& SecondRoute() noexcept { return std::get<1>(routes_); }
  [[nodiscard]] constexpr const auto& SecondRoute() const noexcept { return std::get<1>(routes_); }

  [[nodiscard, gnu::always_inline]] constexpr bool Accepts(std::uint8_t subsystem_id) const noexcept {
    if (subsystem_id == uring::kInternalSubsystemId || subsystem_id == uring::kMailboxSubsystemId) {
      return false;
    }
    return [&]<std::size_t... Is>(std::index_sequence<Is...>) noexcept {
      return (detail::RouteAccepts(std::get<Is>(routes_), subsystem_id) || ...);
    }(std::index_sequence_for<Routes...>{});
  }
  [[nodiscard, gnu::always_inline]] constexpr bool CanRoute(std::uint8_t subsystem_id) const noexcept {
    return Accepts(subsystem_id);
  }
  [[nodiscard, gnu::always_inline]] constexpr bool IsRoutable(std::uint8_t subsystem_id) const noexcept {
    return Accepts(subsystem_id);
  }

  [[nodiscard, gnu::always_inline]] uring::Result<void> Dispatch(const uring::Delivery& delivery) noexcept {
    const std::uint8_t subsystem_id = uring::Subsystem(delivery.completion.token);
    if (subsystem_id == uring::kInternalSubsystemId || subsystem_id == uring::kMailboxSubsystemId) {
      return std::unexpected(uring::UringErrorCode::kInvalid);
    }
    std::size_t matches = 0;
    [&]<std::size_t... Is>(std::index_sequence<Is...>) noexcept {
      ((matches += detail::RouteAccepts(std::get<Is>(routes_), subsystem_id) ? 1U : 0U), ...);
    }(std::index_sequence_for<Routes...>{});
    if (matches == 0) return std::unexpected(uring::UringErrorCode::kNoEntry);
    if (matches > 1) return std::unexpected(uring::UringErrorCode::kInvalid);
    uring::Result<void> result{};
    [&]<std::size_t... Is>(std::index_sequence<Is...>) noexcept {
      ((detail::RouteAccepts(std::get<Is>(routes_), subsystem_id)
            ? static_cast<void>((result = detail::RouteDispatchOne(std::get<Is>(routes_), delivery)))
            : static_cast<void>(0)),
       ...);
    }(std::index_sequence_for<Routes...>{});
    return result;
  }

  [[nodiscard]] uring::Result<void> DispatchBatch(std::span<const uring::Delivery> deliveries) noexcept {
    std::optional<uring::UringErrorCode> first_error{};
    for (const auto& delivery : deliveries) {
      auto res = Dispatch(delivery);
      if (!res && !first_error.has_value()) {
        first_error = res.error();
      }
    }
    if (first_error.has_value()) {
      return std::unexpected(*first_error);
    }
    return {};
  }

  void OnCompletion(CompletionEvent cqe) noexcept {
    const uring::Delivery delivery{.key = {cqe.token, 0}, .completion = cqe};
    const auto claimed = Dispatch(delivery);
    static_cast<void>(claimed);
  }
  void operator()(CompletionEvent cqe) noexcept { OnCompletion(cqe); }

  template <CompletionRouteLike Next>
  [[nodiscard]] constexpr ChainedCompletionRoutes<Routes..., std::decay_t<Next>> Chain(Next&& next) const& noexcept {
    return [&]<std::size_t... Is>(std::index_sequence<Is...>) noexcept {
      return ChainedCompletionRoutes<Routes..., std::decay_t<Next>>{std::get<Is>(routes_)..., std::forward<Next>(next)};
    }(std::index_sequence_for<Routes...>{});
  }

  template <CompletionRouteLike Next>
  [[nodiscard]] constexpr ChainedCompletionRoutes<Routes..., std::decay_t<Next>> Chain(Next&& next) && noexcept {
    return [&]<std::size_t... Is>(std::index_sequence<Is...>) noexcept {
      return ChainedCompletionRoutes<Routes..., std::decay_t<Next>>{std::move(std::get<Is>(routes_))...,
                                                                    std::forward<Next>(next)};
    }(std::index_sequence_for<Routes...>{});
  }
};

template <CompletionRouteLike Next>
constexpr ChainedCompletionRoutes<CompletionRoute, std::decay_t<Next>> CompletionRoute::Chain(Next&& next) const noexcept {
  return ChainedCompletionRoutes<CompletionRoute, std::decay_t<Next>>{*this, std::forward<Next>(next)};
}

template <CompletionRouteLike First, CompletionRouteLike Second>
[[nodiscard]] constexpr ChainedCompletionRoutes<std::decay_t<First>, std::decay_t<Second>> MakeCompletionRoutes(
    First&& first, Second&& second) noexcept {
  return ChainedCompletionRoutes<std::decay_t<First>, std::decay_t<Second>>{std::forward<First>(first),
                                                                            std::forward<Second>(second)};
}

template <std::size_t MaxRoutes = 8>
class CompletionRoutes {
  static_assert(MaxRoutes > 0, "MaxRoutes must be > 0");

  std::array<CompletionRoute, MaxRoutes> routes_{};
  std::size_t count_{0};
  detail::SocketDmaQuarantine quarantine_{};

 public:
  constexpr CompletionRoutes() noexcept = default;
  CompletionRoutes(const CompletionRoutes&) = delete ("CompletionRoutes is pinned by bound sockets and Proactor callbacks");
  CompletionRoutes& operator=(const CompletionRoutes&) =
      delete ("CompletionRoutes is pinned by bound sockets and Proactor callbacks");
  CompletionRoutes(CompletionRoutes&&) = delete ("CompletionRoutes is pinned by bound sockets and Proactor callbacks");
  CompletionRoutes& operator=(CompletionRoutes&&) =
      delete ("CompletionRoutes is pinned by bound sockets and Proactor callbacks");

  [[nodiscard]] constexpr detail::SocketDmaQuarantine& Quarantine() noexcept { return quarantine_; }
  [[nodiscard]] constexpr const detail::SocketDmaQuarantine& Quarantine() const noexcept { return quarantine_; }

  [[nodiscard]] static constexpr bool ConcreteSubsystem(std::uint8_t id) noexcept {
    return id != uring::kInternalSubsystemId && id != uring::kMailboxSubsystemId;
  }

  [[nodiscard]] static constexpr bool RoutesOverlap(const CompletionRoute& lhs, const CompletionRoute& rhs) noexcept {
    if (!lhs.exclusive && !rhs.exclusive) return false;
    if (ConcreteSubsystem(lhs.subsystem_id) && rhs.Accepts(lhs.subsystem_id)) return true;
    if (ConcreteSubsystem(rhs.subsystem_id) && lhs.Accepts(rhs.subsystem_id)) return true;
    if (!ConcreteSubsystem(lhs.subsystem_id) || !ConcreteSubsystem(rhs.subsystem_id)) {
      for (unsigned id = 1; id < 255; ++id) {
        const auto subsystem_id = static_cast<std::uint8_t>(id);
        if (lhs.Accepts(subsystem_id) && rhs.Accepts(subsystem_id)) return true;
      }
    }
    return false;
  }

  [[nodiscard]] constexpr Result<void> Register(CompletionRoute route) noexcept {
    if (route.step == nullptr) {
      if (!ConcreteSubsystem(route.subsystem_id) || route.on_cqe == nullptr) {
        return std::unexpected(Error::InvalidArgument());
      }
    } else if (route.subsystem_id == uring::kMailboxSubsystemId) {
      return std::unexpected(Error::InvalidArgument());
    }
    for (std::size_t i = 0; i < count_; ++i) {
      if (RoutesOverlap(route, routes_[i])) return std::unexpected(Error::InvalidArgument());
    }
    if (count_ >= MaxRoutes) return std::unexpected(Error::BufferOverflow());
    routes_[count_++] = route;
    return {};
  }

  [[nodiscard]] constexpr bool Unregister(const void* ctx) noexcept {
    std::size_t kept = 0;
    bool removed = false;
    for (std::size_t i = 0; i < count_; ++i) {
      if (routes_[i].ctx == ctx) {
        removed = true;
        continue;
      }
      if (kept != i) routes_[kept] = routes_[i];
      ++kept;
    }
    for (std::size_t i = kept; i < count_; ++i) routes_[i] = {};
    count_ = kept;
    return removed;
  }

  [[nodiscard]] constexpr bool ContainsRoute(const CompletionRoute& entry) const noexcept {
    for (std::size_t i = 0; i < count_; ++i) {
      if (routes_[i].ctx == entry.ctx && routes_[i].subsystem_id == entry.subsystem_id && routes_[i].on_cqe == entry.on_cqe &&
          routes_[i].step == entry.step) {
        return true;
      }
    }
    return false;
  }

  [[nodiscard, gnu::always_inline]] bool Accepts(std::uint8_t subsystem_id) const noexcept {
    if (subsystem_id == uring::kInternalSubsystemId || subsystem_id == uring::kMailboxSubsystemId) return false;
    if (subsystem_id == kSocketSubsystemId && quarantine_.ActiveCount() > 0) return true;
    if (detail::SharedParkedRegistry().HasSubsystem(subsystem_id)) return true;
    for (std::size_t i = 0; i < count_; ++i) {
      if (routes_[i].Accepts(subsystem_id)) return true;
    }
    return false;
  }
  [[nodiscard, gnu::always_inline]] bool CanRoute(std::uint8_t subsystem_id) const noexcept { return Accepts(subsystem_id); }
  [[nodiscard, gnu::always_inline]] bool IsRoutable(std::uint8_t subsystem_id) const noexcept { return Accepts(subsystem_id); }

  [[nodiscard, gnu::always_inline]] uring::Result<void> Dispatch(const uring::Delivery& delivery) noexcept {
    const std::uint8_t id = uring::Subsystem(delivery.completion.token);
    if (id == uring::kInternalSubsystemId || id == uring::kMailboxSubsystemId) {
      return std::unexpected(uring::UringErrorCode::kInvalid);
    }
    if (quarantine_.TryRetire(delivery.completion.token, delivery.key.ring_instance, delivery.completion.result)) {
      return {};
    }
    if (detail::RetireParked(delivery.completion.token, delivery.key.ring_instance)) return {};
    // Callbacks may Unregister and compact routes_. Invoke a stack copy so a
    // sibling registered after the caller is not skipped by ++i.
    std::array<std::optional<CompletionRoute>, MaxRoutes> matched;
    std::size_t matched_count = 0;
    for (std::size_t i = 0; i < count_; ++i) {
      if (!routes_[i].Accepts(id)) continue;
      matched[matched_count++].emplace(routes_[i]);
    }
    for (std::size_t i = 0; i < matched_count; ++i) {
      const CompletionRoute entry = *matched[i];
      if (!ContainsRoute(entry)) continue;
      auto claimed = entry.Dispatch(delivery);
      if (claimed) return {};
      const bool unowned = claimed.error() == uring::UringErrorCode::kNoEntry;
      if (!entry.exclusive && unowned) continue;
      return std::unexpected(claimed.error());
    }
    return std::unexpected(uring::UringErrorCode::kNoEntry);
  }

  [[nodiscard]] uring::Result<void> DispatchBatch(std::span<const uring::Delivery> deliveries) noexcept {
    std::optional<uring::UringErrorCode> first_error{};
    for (const auto& delivery : deliveries) {
      auto res = Dispatch(delivery);
      if (!res && !first_error.has_value()) first_error = res.error();
    }
    if (first_error.has_value()) return std::unexpected(*first_error);
    return {};
  }

  void OnCompletion(CompletionEvent cqe) noexcept {
    const uring::Delivery delivery{.key = {cqe.token, 0}, .completion = cqe};
    const auto claimed = Dispatch(delivery);
    static_cast<void>(claimed);
  }
  void OnCompletion(const uring::Delivery& delivery) noexcept {
    const auto claimed = Dispatch(delivery);
    static_cast<void>(claimed);
  }

  void operator()(CompletionEvent cqe) noexcept { OnCompletion(cqe); }
  void operator()(const uring::Delivery& delivery) noexcept { OnCompletion(delivery); }

  [[nodiscard]] constexpr std::size_t Size() const noexcept { return count_; }
  [[nodiscard]] constexpr bool Empty() const noexcept { return count_ == 0; }
};

CompletionRoutes() -> CompletionRoutes<8>;

}  // namespace nexora
