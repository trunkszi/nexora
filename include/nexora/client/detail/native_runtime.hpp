#pragma once
#include <cares/cares.hpp>
#include <nexora/error/runtime_error.hpp>
#include <optional>
#include <uring/uring.hpp>
#include <utility>

namespace nexora::detail {
struct NativeRuntime {
  uring::Result<uring::Proactor> proactor{uring::Proactor::Create()};
  std::optional<cares::Resolver<>> resolver{};
  [[nodiscard]] Result<void> Init() noexcept {
    if (!proactor) return std::unexpected(Error::UringFailed(static_cast<std::int32_t>(std::to_underlying(proactor.error()))));
    auto created = cares::Resolver<>::FromSystem(*proactor);
    if (!created) return std::unexpected(Error::DnsFailed(created.error().raw_code));
    resolver.emplace(std::move(*created));
    return {};
  }
};
}  // namespace nexora::detail
