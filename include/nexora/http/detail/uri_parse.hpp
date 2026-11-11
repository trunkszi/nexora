/** @file @brief Internal RFC 3986 URI authority, IPv6 literal, and dot-segment helpers. */
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <nexora/bytes/scan.hpp>
#include <nexora/error/runtime_error.hpp>
#include <optional>
#include <span>
#include <string_view>

namespace nexora {

enum class Scheme : std::uint8_t {
  kHttp = 0,
  kHttps = 1,
  kWs = 2,
  kWss = 3,
  kWebSocket = kWs,
  kWebSocketSecure = kWss,
};

[[nodiscard]] constexpr std::uint16_t SchemeDefaultPort(Scheme s) noexcept {
  switch (s) {
    case Scheme::kHttp:
    case Scheme::kWs:
      return 80;
    case Scheme::kHttps:
    case Scheme::kWss:
      return 443;
  }
  return 80;
}

[[nodiscard]] constexpr std::string_view SchemeAsStr(Scheme s) noexcept {
  switch (s) {
    case Scheme::kHttp:
      return "http";
    case Scheme::kHttps:
      return "https";
    case Scheme::kWs:
      return "ws";
    case Scheme::kWss:
      return "wss";
  }
  return "http";
}

[[nodiscard]] constexpr bool SchemeIsTls(Scheme s) noexcept { return s == Scheme::kHttps || s == Scheme::kWss; }

[[nodiscard]] constexpr bool SchemeIsWebSocket(Scheme s) noexcept { return s == Scheme::kWs || s == Scheme::kWss; }

inline constexpr std::size_t kMaxUriLength = 2048uz;

namespace detail {

template <std::size_t Capacity>
class UriText {
 public:
  constexpr UriText() noexcept = default;
  constexpr UriText(const UriText& other) noexcept : len_(other.len_) { CopyActiveBytes(other); }
  constexpr UriText(UriText&& other) noexcept : len_(other.len_) { CopyActiveBytes(other); }

  constexpr UriText& operator=(const UriText& other) noexcept {
    if (this != &other) {
      len_ = other.len_;
      CopyActiveBytes(other);
    }
    return *this;
  }

  constexpr UriText& operator=(UriText&& other) noexcept {
    if (this != &other) {
      len_ = other.len_;
      CopyActiveBytes(other);
    }
    return *this;
  }

  ~UriText() noexcept = default;

  [[nodiscard]] constexpr bool Append(std::string_view sv) noexcept {
    if (sv.size() > Capacity - len_) return false;
    if consteval {
      for (std::size_t i = 0uz; i < sv.size(); ++i) buf_[len_ + i] = sv[i];
    } else {
      if (!sv.empty()) std::memcpy(buf_.data() + len_, sv.data(), sv.size());
    }
    len_ = static_cast<std::uint16_t>(len_ + sv.size());
    return true;
  }

  [[nodiscard]] constexpr bool PushBack(char c) noexcept {
    if (len_ >= Capacity) return false;
    buf_[len_++] = c;
    return true;
  }

  constexpr void Truncate(std::uint16_t new_len) noexcept {
    if (new_len < len_) len_ = new_len;
  }

  constexpr void LowercaseRange(std::uint16_t offset, std::uint16_t count) noexcept {
    if (offset + count <= len_) AsciiLowerInPlace(std::span<char>(buf_.data() + offset, count));
  }

  [[nodiscard]] constexpr std::string_view View() const noexcept { return {buf_.data(), len_}; }
  [[nodiscard]] constexpr operator std::string_view() const noexcept { return View(); }
  [[nodiscard]] constexpr std::string_view Subview(std::uint16_t offset, std::uint16_t count) const noexcept {
    return {buf_.data() + offset, count};
  }
  [[nodiscard]] constexpr std::uint16_t Size() const noexcept { return len_; }
  [[nodiscard]] constexpr bool Empty() const noexcept { return len_ == 0; }

  [[nodiscard]] friend constexpr bool operator==(const UriText& a, std::string_view b) noexcept { return a.View() == b; }

 private:
  constexpr void CopyActiveBytes(const UriText& other) noexcept {
    if consteval {
      for (std::size_t i = 0uz; i < len_; ++i) buf_[i] = other.buf_[i];
    } else {
      if (len_ > 0) std::memcpy(buf_.data(), other.buf_.data(), len_);
    }
  }

  std::array<char, Capacity> buf_{};
  std::uint16_t len_{0};
};

[[nodiscard]] constexpr bool IsAsciiAlpha(char c) noexcept { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }

[[nodiscard]] constexpr bool IsAsciiHexDigit(char c) noexcept {
  return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

[[nodiscard]] constexpr bool IsAsciiAlnum(char c) noexcept { return (c >= '0' && c <= '9') || IsAsciiAlpha(c); }

[[nodiscard]] constexpr bool HasUriScheme(std::string_view ref) noexcept {
  for (std::size_t i = 0uz; i < ref.size(); ++i) {
    const char c = ref[i];
    if (c == ':') return i > 0uz;
    if (c == '/' || c == '?' || c == '#') return false;
  }
  return false;
}

[[nodiscard]] constexpr bool IsValidIpv6Literal(std::string_view host) noexcept {
  if (host.size() < 2uz) return false;
  std::size_t groups = 0uz;
  std::size_t i = 0uz;
  bool zip = false;
  auto take_v4 = [&](std::size_t at) constexpr -> bool {
    for (int octets = 0; octets < 4; ++octets) {
      if (at >= host.size() || host[at] < '0' || host[at] > '9') return false;
      const char first_digit = host[at];
      unsigned val = 0U;
      int digits = 0;
      while (at < host.size() && host[at] >= '0' && host[at] <= '9') {
        val = val * 10U + static_cast<unsigned>(host[at++] - '0');
        if (++digits > 3 || val > 255U) return false;
      }
      if (digits > 1 && first_digit == '0') return false;
      if (octets < 3 && (at >= host.size() || host[at++] != '.')) return false;
    }
    return at == host.size();
  };
  if (host[0] == ':') {
    if (host[1] != ':') return false;
    zip = true;
    i = 2uz;
    if (i == host.size()) return true;
    if (host[i] == ':') return false;
  }
  while (i < host.size()) {
    std::size_t hex = 0uz;
    const auto start = i;
    while (i < host.size() && IsAsciiHexDigit(host[i]) && hex < 5uz) {
      ++i;
      ++hex;
    }
    if (i < host.size() && host[i] == '.') {
      if (!take_v4(start)) return false;
      groups += 2uz;
      break;
    }
    if (hex == 0uz || hex > 4uz) return false;
    if (++groups > 8uz) return false;
    if (i == host.size()) break;
    if (host[i++] != ':') return false;
    if (i == host.size()) return false;
    if (host[i] == ':') {
      if (zip) return false;
      zip = true;
      ++i;
      if (i == host.size()) break;
      if (host[i] == ':') return false;
    }
  }
  return groups <= 8uz && (zip ? (groups < 8uz) : (groups == 8uz));
}

[[nodiscard]] constexpr bool IsValidPercentEncoding(std::string_view value, std::size_t index) noexcept {
  return index + 2uz < value.size() && IsAsciiHexDigit(value[index + 1uz]) && IsAsciiHexDigit(value[index + 2uz]);
}

[[nodiscard]] constexpr bool IsValidRegName(std::string_view host) noexcept {
  for (std::size_t i = 0uz; i < host.size(); ++i) {
    const char c = host[i];
    if (c == '%' && !IsValidPercentEncoding(host, i)) return false;
    const bool ok = IsAsciiAlnum(c) || c == '-' || c == '.' || c == '_' || c == '~' || c == '%' || c == '!' || c == '$' ||
                    c == '&' || c == '\'' || c == '(' || c == ')' || c == '*' || c == '+' || c == ',' || c == ';' || c == '=';
    if (!ok) return false;
  }
  return true;
}

[[nodiscard]] constexpr bool IsValidRequestChars(std::string_view value) noexcept {
  for (std::size_t i = 0uz; i < value.size(); ++i) {
    const auto b = static_cast<unsigned char>(value[i]);
    if (b <= 0x20U || b >= 0x7fU) return false;
    const char c = value[i];
    if (c == '\\' || c == '<' || c == '>' || c == '"' || c == '`' || c == '{' || c == '}' || c == '|' || c == '^') {
      return false;
    }
    if (c == '%' && !IsValidPercentEncoding(value, i)) return false;
  }
  return true;
}

[[nodiscard]] constexpr Result<std::uint16_t> ParsePortDecimal(std::string_view raw) noexcept {
  if (raw.empty()) return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
  std::uint32_t acc = 0;
  for (char c : raw) {
    if (c < '0' || c > '9') return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
    acc = acc * 10U + static_cast<std::uint32_t>(c - '0');
    if (acc > 65535U) return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
  }
  if (acc == 0U) return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
  return static_cast<std::uint16_t>(acc);
}

struct ParsedAuthorityView {
  std::string_view host{};
  std::uint16_t port{0};
  std::optional<std::uint16_t> explicit_port{};
  bool ipv6_literal{false};
};

[[nodiscard]] constexpr Result<ParsedAuthorityView> ParseUriAuthority(std::string_view authority, Scheme scheme) noexcept {
  if (authority.empty() || authority.contains('@')) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
  }
  if (authority.starts_with('[')) {
    const auto close = authority.find(']');
    if (close == std::string_view::npos) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
    }
    const std::string_view host_part = authority.substr(1uz, close - 1uz);
    if (host_part.empty() || !IsValidIpv6Literal(host_part)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
    }
    const std::string_view rest = authority.substr(close + 1uz);
    std::optional<std::uint16_t> explicit_port;
    if (!rest.empty()) {
      if (!rest.starts_with(':')) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
      }
      auto p = ParsePortDecimal(rest.substr(1uz));
      if (!p.has_value()) return std::unexpected(p.error());
      explicit_port = *p;
    }
    return ParsedAuthorityView{
        .host = host_part,
        .port = explicit_port.value_or(SchemeDefaultPort(scheme)),
        .explicit_port = explicit_port,
        .ipv6_literal = true,
    };
  }

  std::string_view host_part = authority;
  std::optional<std::uint16_t> explicit_port;
  const auto colon = authority.find(':');
  if (colon != std::string_view::npos) {
    host_part = authority.substr(0uz, colon);
    const std::string_view port_str = authority.substr(colon + 1uz);
    if (port_str.contains(':')) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
    }
    auto p = ParsePortDecimal(port_str);
    if (!p.has_value()) return std::unexpected(p.error());
    explicit_port = *p;
  }
  if (host_part.empty() || !IsValidRegName(host_part)) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
  }
  return ParsedAuthorityView{
      .host = host_part,
      .port = explicit_port.value_or(SchemeDefaultPort(scheme)),
      .explicit_port = explicit_port,
      .ipv6_literal = false,
  };
}

[[nodiscard]] constexpr UriText<8> FormatDecimalU16(std::uint16_t v) noexcept {
  UriText<8> out;
  if (v == 0) {
    static_cast<void>(out.PushBack('0'));
    return out;
  }
  std::array<char, 8> rev{};
  std::size_t count = 0uz;
  for (std::uint16_t n = v; n > 0; n = static_cast<std::uint16_t>(n / 10U)) {
    rev[count++] = static_cast<char>('0' + (n % 10U));
  }
  while (count > 0uz) static_cast<void>(out.PushBack(rev[--count]));
  return out;
}

[[nodiscard]] constexpr Result<UriText<kMaxUriLength>> MergeRelativePath(std::string_view base_path,
                                                                         std::string_view rel_path) noexcept {
  UriText<kMaxUriLength> out;
  const auto slash = base_path.rfind('/');
  const std::string_view prefix = (slash != std::string_view::npos) ? base_path.substr(0uz, slash + 1uz) : "/";
  if (!out.Append(prefix) || !out.Append(rel_path)) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
  }
  return out;
}

[[nodiscard]] constexpr Result<UriText<kMaxUriLength>> RemoveDotSegments(std::string_view path) noexcept {
  std::string_view input = path;
  UriText<kMaxUriLength> out;
  std::array<std::uint16_t, 1024> seg_starts{};
  std::size_t seg_count = 0uz;

  while (!input.empty()) {
    if (input.starts_with("../")) {
      input.remove_prefix(3uz);
    } else if (input.starts_with("./") || input.starts_with("/./")) {
      input.remove_prefix(2uz);
    } else if (input == "/.") {
      input = "/";
    } else if (input.starts_with("/../") || input == "/..") {
      if (input == "/..") {
        input = "/";
      } else {
        input.remove_prefix(3uz);
      }
      if (seg_count > 0uz) out.Truncate(seg_starts[--seg_count]);
    } else if (input == "." || input == "..") {
      input = "";
    } else {
      const auto next = input.find('/', input.starts_with('/') ? 1uz : 0uz);
      const std::size_t split = (next == std::string_view::npos) ? input.size() : next;
      if (seg_count >= seg_starts.size()) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
      }
      seg_starts[seg_count++] = out.Size();
      if (!out.Append(input.substr(0uz, split))) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
      }
      input.remove_prefix(split);
    }
  }

  if (out.Empty()) {
    static_cast<void>(out.PushBack('/'));
    return out;
  }
  if (!out.View().starts_with('/')) {
    UriText<kMaxUriLength> prefixed;
    if (!prefixed.PushBack('/') || !prefixed.Append(out.View())) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
    }
    return prefixed;
  }
  return out;
}

}  // namespace detail
}  // namespace nexora
