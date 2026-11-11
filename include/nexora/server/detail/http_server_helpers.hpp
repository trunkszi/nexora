#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <nexora/error/runtime_error.hpp>
#include <nexora/http/message.hpp>
#include <nexora/http2/connection.hpp>
#include <optional>
#include <string>
#include <string_view>

namespace nexora::detail {

struct ServerWorkSpec {
  using Word = std::uint64_t;
  bool headers_sent[[= uarch::bits::Flag{0}]];
  bool close_after[[= uarch::bits::Flag{1}]];
};

struct ServerDriveSpec {
  using Word = std::uint64_t;
  bool driving[[= uarch::bits::Flag{0}]];
  bool stop_reading[[= uarch::bits::Flag{1}]];
  bool close_when_flushed[[= uarch::bits::Flag{2}]];
};

[[nodiscard]] inline bool HasHeaderTokenIgnoreCase(const Headers<>& headers, std::string_view key,
                                                   std::string_view token) noexcept {
  for (const auto& field : headers.Fields()) {
    if (field.name != key) continue;
    std::string_view rest = field.value;
    while (!rest.empty()) {
      const auto comma = rest.find(',');
      std::string_view item = (comma == std::string_view::npos) ? rest : rest.substr(0, comma);
      while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) item.remove_prefix(1);
      while (!item.empty() && (item.back() == ' ' || item.back() == '\t')) item.remove_suffix(1);
      if (AsciiEqualsIgnoreCase(item, token)) return true;
      if (comma == std::string_view::npos) break;
      rest.remove_prefix(comma + 1);
    }
  }
  return false;
}

[[nodiscard]] inline bool IsValidAuthorityWire(std::string_view authority) noexcept {
  if (authority.empty() || authority.find_first_of("/?#@\\") != std::string_view::npos) return false;
  return std::ranges::all_of(authority, [](char ch) noexcept {
    const auto byte = static_cast<unsigned char>(ch);
    return byte > 0x20 && byte < 0x7f;
  });
}

[[nodiscard]] inline std::optional<std::string_view> ResolveHttp2Authority(const Http2Event& event) noexcept {
  std::optional<std::string_view> host_header{};
  for (const auto& field : event.headers.Fields()) {
    if (field.name != "host") continue;
    if (host_header.has_value() || field.value.empty()) return std::nullopt;
    host_header = std::string_view{field.value};
  }
  if (!event.authority.empty() && host_header.has_value() && !AsciiEqualsIgnoreCase(event.authority, *host_header)) {
    return std::nullopt;
  }
  const std::string_view chosen =
      !event.authority.empty() ? std::string_view{event.authority} : host_header.value_or(std::string_view{});
  if (!IsValidAuthorityWire(chosen)) return std::nullopt;
  return chosen;
}

[[nodiscard]] inline std::optional<Request> BuildValidatedHttp2Request(Http2Event& event) noexcept {
  if (event.scheme != "http" && event.scheme != "https" && event.scheme != "ws" && event.scheme != "wss") {
    return std::nullopt;
  }
  const auto authority = ResolveHttp2Authority(event);
  if (!authority.has_value()) return std::nullopt;
  const bool asterisk = (event.method == Method::kOptions && event.path == "*");
  if ((!asterisk && !event.path.starts_with('/')) || event.path.contains('#')) return std::nullopt;
  for (const char ch : event.path) {
    const auto byte = static_cast<unsigned char>(ch);
    if (byte <= 0x20 || byte >= 0x7f) return std::nullopt;
  }
  const std::string_view target = asterisk ? std::string_view{"/"} : std::string_view{event.path};
  std::string url{};
  url.reserve(event.scheme.size() + 3 + authority->size() + target.size());
  url.append(event.scheme).append("://").append(*authority).append(target);
  auto request = Request::Build(event.method, url);
  if (!request) return std::nullopt;
  request->headers = std::move(event.headers);
  request->version = Version::kHttp2;
  return std::move(*request);
}

[[nodiscard]] constexpr bool ResponseOmitsBody(Method method, StatusCode status) noexcept {
  const auto code = status.AsU16();
  return method == Method::kHead || code == 101 || code == 204 || code == 304;
}

}  // namespace nexora::detail
