/** @file @brief Compact 8-byte register-passable Error value and Result<T> alias. */
#pragma once

#include <compare>
#include <cstdint>
#include <expected>
#include <format>
#include <nexora/error/error_codes.hpp>
#include <string_view>
#include <uarch/core/layout/assertions.hpp>
#include <uarch/core/layout/no_padding.hpp>
#include <uarch/core/layout/register_passable.hpp>
#include <utility>

namespace nexora {

struct [[nodiscard]] Error {
  ErrorDomain domain{ErrorDomain::kNone};
  std::uint8_t reserved{0};
  std::int16_t sys_errno{0};
  std::int32_t code{0};

  [[nodiscard]] constexpr bool Ok() const noexcept { return domain == ErrorDomain::kNone && code == 0; }

  [[nodiscard]] constexpr std::int32_t SysErrno() const noexcept {
    return (domain == ErrorDomain::kErrno) ? code : static_cast<std::int32_t>(sys_errno);
  }

  [[nodiscard]] static constexpr Error FromProto(ProtoErrorCode c) noexcept {
    if (c == ProtoErrorCode::kOk) {
      return Error{};
    }
    return Error{.domain = ErrorDomain::kProto, .code = static_cast<std::int32_t>(std::to_underlying(c))};
  }

  [[nodiscard]] static constexpr Error FromHttp2(Http2ErrorCode c) noexcept {
    if (c == Http2ErrorCode::kNoError) {
      return Error{};
    }
    return Error{.domain = ErrorDomain::kHttp2, .code = static_cast<std::int32_t>(std::to_underlying(c))};
  }

  [[nodiscard]] static constexpr Error FromRuntime(RuntimeErrorCode c) noexcept {
    if (c == RuntimeErrorCode::kOk) {
      return Error{};
    }
    return Error{.domain = ErrorDomain::kRuntime, .code = static_cast<std::int32_t>(std::to_underlying(c))};
  }

  [[nodiscard]] static constexpr Error FromErrno(std::int32_t err) noexcept {
    if (err == 0) {
      return Error{};
    }
    return Error{
        .domain = ErrorDomain::kErrno,
        .reserved = 0,
        .sys_errno = static_cast<std::int16_t>(err),
        .code = err,
    };
  }

  [[nodiscard]] static constexpr Error DnsFailed(std::int32_t raw_cares_code = 0) noexcept {
    return Error{
        .domain = ErrorDomain::kRuntime,
        .reserved = 0,
        .sys_errno = static_cast<std::int16_t>(raw_cares_code),
        .code = static_cast<std::int32_t>(std::to_underlying(RuntimeErrorCode::kDnsError)),
    };
  }

  [[nodiscard]] static constexpr Error UringFailed(std::int32_t raw_uring_code = 0) noexcept {
    return Error{
        .domain = ErrorDomain::kRuntime,
        .reserved = 0,
        .sys_errno = static_cast<std::int16_t>(raw_uring_code),
        .code = static_cast<std::int32_t>(std::to_underlying(RuntimeErrorCode::kUringError)),
    };
  }

  [[nodiscard]] static constexpr Error Timeout() noexcept { return FromRuntime(RuntimeErrorCode::kTimedOut); }

  [[nodiscard]] static constexpr Error Cancelled() noexcept { return FromRuntime(RuntimeErrorCode::kCancelled); }

  [[nodiscard]] static constexpr Error InvalidArgument() noexcept { return FromProto(ProtoErrorCode::kInvalidArgument); }

  [[nodiscard]] static constexpr Error Incomplete() noexcept { return FromProto(ProtoErrorCode::kIncomplete); }

  [[nodiscard]] static constexpr Error BufferOverflow() noexcept { return FromProto(ProtoErrorCode::kBufferOverflow); }

  [[nodiscard]] constexpr std::string_view Message() const noexcept {
    switch (domain) {
      case ErrorDomain::kNone:
        return "ok";
      case ErrorDomain::kProto:
        return ProtoErrorMessage(static_cast<ProtoErrorCode>(code));
      case ErrorDomain::kHttp2:
        return Http2ErrorMessage(Http2ErrorCodeFromU32(static_cast<std::uint32_t>(code)));
      case ErrorDomain::kRuntime:
        return RuntimeErrorMessage(static_cast<RuntimeErrorCode>(code));
      case ErrorDomain::kErrno:
        return SysErrnoMessage(code);
    }
    return "unknown error";
  }

  constexpr auto operator<=>(const Error&) const noexcept = default;
};

static_assert(uarch::layout::CallTrivial<Error> && sizeof(Error) == 8);
static_assert(uarch::layout::NoPadding<Error> && uarch::layout::RegisterPassable<Error>);

template <typename T>
using Result = std::expected<T, Error>;

}  // namespace nexora

template <>
struct std::formatter<nexora::Error> : std::formatter<std::string_view> {
  constexpr auto format(const nexora::Error& err, std::format_context& ctx) const {
    return std::formatter<std::string_view>::format(err.Message(), ctx);
  }
};
