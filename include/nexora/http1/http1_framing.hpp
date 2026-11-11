#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <nexora/bytes/bytes.hpp>
#include <nexora/bytes/scan.hpp>
#include <nexora/http/message.hpp>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

namespace nexora {

enum class Http1KeepAlive : std::uint8_t { kClose = 0, kKeepAlive = 1, kUpgrade = 2 };

template <typename Message>
struct Http1Decoded {
  Message message{};
  Http1KeepAlive keep_alive{Http1KeepAlive::kKeepAlive};
  std::size_t consumed{0};
};

namespace http1_detail {

struct Framing {
  enum class Kind : std::uint8_t { kAbsent, kLength, kChunked };
  Kind kind{Kind::kAbsent};
  std::size_t length{0};
};

struct BodyParts {
  Bytes body{};
  Headers<> trailers{};
  std::size_t consumed{0};
};

struct Head {
  std::string_view start{};
  Headers<> headers{};
  std::size_t head_len{0};
};

[[nodiscard]] inline bool TokenByte(unsigned char c) noexcept { return detail::kHttpTokenTable[c]; }

[[nodiscard]] inline std::optional<std::size_t> CheckedAdd(std::size_t a, std::size_t b) noexcept {
  if (a > std::numeric_limits<std::size_t>::max() - b) {
    return std::nullopt;
  }
  return a + b;
}

[[nodiscard]] inline bool HasToken(const Headers<>& headers, std::string_view name, std::string_view token) noexcept {
  for (const auto& field : headers) {
    if (!AsciiEqualsIgnoreCase(field.name, name)) {
      continue;
    }
    std::string_view raw(field.value);
    std::size_t start = 0;
    while (start <= raw.size()) {
      const auto comma = raw.find(',', start);
      const auto part = (comma == std::string_view::npos) ? raw.substr(start) : raw.substr(start, comma - start);
      if (AsciiEqualsIgnoreCase(TrimAsciiWhitespace(part), token)) {
        return true;
      }
      if (comma == std::string_view::npos) {
        break;
      }
      start = comma + 1;
    }
  }
  return false;
}

[[nodiscard]] inline std::size_t FieldCount(const Headers<>& headers, std::string_view name) noexcept {
  std::size_t count = 0;
  for (const auto& field : headers) {
    if (AsciiEqualsIgnoreCase(field.name, name)) {
      ++count;
    }
  }
  return count;
}

[[nodiscard]] inline bool AuthorityHasPort(std::string_view authority) noexcept {
  if (authority.starts_with('[')) {
    const auto close = authority.find(']');
    return close != std::string_view::npos && close + 1 < authority.size() && authority[close + 1] == ':';
  }
  return authority.find(':') != std::string_view::npos;
}

[[nodiscard]] inline Result<void> ValidateAuthority(std::string_view authority) noexcept {
  if (authority.empty()) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
  }
  for (char c : authority) {
    if (c == '/' || c == '@' || c == '?' || c == '#') {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
    }
  }
  std::array<char, 2048> raw{};
  constexpr std::string_view prefix = "http://";
  if (authority.size() + prefix.size() + 1 > raw.size()) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1MessageTooLarge));
  }
  std::memcpy(raw.data(), prefix.data(), prefix.size());
  std::memcpy(raw.data() + prefix.size(), authority.data(), authority.size());
  raw[prefix.size() + authority.size()] = '/';
  auto parsed = Uri::Parse(std::string_view(raw.data(), prefix.size() + authority.size() + 1));
  if (!parsed.has_value()) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
  }
  return {};
}

[[nodiscard]] inline Result<std::pair<std::string_view, std::string_view>> ParseField(std::string_view line) noexcept {
  const auto colon = line.find(':');
  if (colon == std::string_view::npos || colon == 0) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderName));
  }
  const auto name = line.substr(0, colon);
  if (!IsValidHeaderName(name)) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderName));
  }
  const auto raw_value = line.substr(colon + 1);
  if (!IsValidHeaderValue(raw_value)) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
  }
  return std::pair<std::string_view, std::string_view>{name, TrimAsciiWhitespace(raw_value)};
}

[[nodiscard]] inline Result<std::optional<Head>> ParseHead(std::span<const std::uint8_t> data,
                                                           std::size_t max_header) noexcept {
  const auto end = FindHeaderEnd(data);
  if (!end.has_value()) {
    if (data.size() > max_header) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1MessageTooLarge));
    }
    return std::optional<Head>{};
  }
  const auto head_len = CheckedAdd(*end, 4);
  if (!head_len.has_value() || *head_len > max_header) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1MessageTooLarge));
  }
  Head head;
  head.head_len = *head_len;
  const auto block = data.first(*end);
  std::size_t pos = 0;
  bool first = true;
  while (pos < block.size()) {
    const auto rel = FindCrLf(block.subspan(pos));
    const std::size_t line_end = rel.has_value() ? pos + *rel : block.size();
    const std::string_view line(reinterpret_cast<const char*>(block.data() + pos), line_end - pos);
    if (first) {
      for (char c : line) {
        const auto b = static_cast<unsigned char>(c);
        if (b < 0x20U || b == 0x7fU) {
          return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
        }
      }
      head.start = line;
      first = false;
    } else {
      auto field = ParseField(line);
      if (!field.has_value()) {
        return std::unexpected(field.error());
      }
      auto added = head.headers.Add(field->first, field->second);
      if (!added.has_value()) {
        return std::unexpected(added.error());
      }
    }
    if (!rel.has_value()) {
      break;
    }
    pos = line_end + 2;
  }
  if (first) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
  }
  if (FieldCount(head.headers, "host") > 1) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
  }
  return std::optional<Head>(std::move(head));
}

[[nodiscard]] inline Result<Framing> MessageFraming(const Headers<>& headers, Version version) noexcept {
  const bool has_length = headers.Contains("content-length");
  const bool has_transfer = headers.Contains("transfer-encoding");
  if (has_length && has_transfer) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ConflictingFraming));
  }
  if (has_transfer) {
    if (version == Version::kHttp10) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    bool saw = false;
    for (const auto& field : headers) {
      if (field.name != "transfer-encoding") {
        continue;
      }
      std::string_view raw(field.value);
      std::size_t start = 0;
      while (true) {
        const auto comma = raw.find(',', start);
        const auto part =
            TrimAsciiWhitespace((comma == std::string_view::npos) ? raw.substr(start) : raw.substr(start, comma - start));
        if (!saw) {
          if (!AsciiEqualsIgnoreCase(part, "chunked")) {
            return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
          }
          saw = true;
        } else {
          return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
        }
        if (comma == std::string_view::npos) {
          break;
        }
        start = comma + 1;
      }
    }
    if (!saw) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    return Framing{Framing::Kind::kChunked, 0};
  }
  auto length = headers.ContentLength();
  if (!length.has_value()) {
    return std::unexpected(length.error());
  }
  if (!length->has_value()) {
    return Framing{Framing::Kind::kAbsent, 0};
  }
  return Framing{Framing::Kind::kLength, **length};
}

[[nodiscard]] inline Result<void> ValidateUpgradeFraming(const Headers<>& headers, Framing framing,
                                                         std::size_t body_size) noexcept {
  if (!HasToken(headers, "upgrade", "websocket")) {
    return {};
  }
  const bool empty_framed =
      framing.kind == Framing::Kind::kAbsent || (framing.kind == Framing::Kind::kLength && framing.length == 0);
  if (body_size != 0 || !empty_framed) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
  }
  return {};
}

[[nodiscard]] inline Result<void> ValidateStatusFraming(StatusCode status, Framing framing) noexcept {
  if (status.AsU16() == 205 && framing.kind == Framing::Kind::kLength && framing.length != 0) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
  }
  if ((status.IsInformational() || status.AsU16() == StatusCode::kNoContent) && framing.kind != Framing::Kind::kAbsent) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
  }
  return {};
}

[[nodiscard]] inline Http1KeepAlive Persistence(Version version, const Headers<>& headers, bool upgrade) noexcept {
  if (upgrade) {
    return Http1KeepAlive::kUpgrade;
  }
  if (HasToken(headers, "connection", "close") ||
      (version == Version::kHttp10 && !HasToken(headers, "connection", "keep-alive"))) {
    return Http1KeepAlive::kClose;
  }
  return Http1KeepAlive::kKeepAlive;
}

[[nodiscard]] inline Result<Uri> RequestTarget(Method method, std::string_view target, Version version,
                                               const Headers<>& headers) noexcept {
  const auto host_field = headers.Get("host");
  if (version == Version::kHttp11 && (!host_field.has_value() || host_field->empty())) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
  }
  const std::string_view host = host_field.has_value() && !host_field->empty() ? *host_field : std::string_view("localhost");
  auto authority = ValidateAuthority(host);
  if (!authority.has_value()) {
    return std::unexpected(authority.error());
  }
  if (method == Method::kConnect) {
    if (!AuthorityHasPort(target)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
    }
    for (char c : target) {
      if (c == '/' || c == '@' || c == '?' || c == '#') {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
      }
    }
    std::array<char, 2048> raw{};
    constexpr std::string_view prefix = "http://";
    if (target.size() + prefix.size() + 1 > raw.size()) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1MessageTooLarge));
    }
    std::memcpy(raw.data(), prefix.data(), prefix.size());
    std::memcpy(raw.data() + prefix.size(), target.data(), target.size());
    raw[prefix.size() + target.size()] = '/';
    return Uri::Parse(std::string_view(raw.data(), prefix.size() + target.size() + 1));
  }
  const auto scheme = target.find("://");
  if (scheme != std::string_view::npos) {
    const auto scheme_text = target.substr(0, scheme);
    if (AsciiEqualsIgnoreCase(scheme_text, "http") || AsciiEqualsIgnoreCase(scheme_text, "https")) {
      return Uri::Parse(target);
    }
  }
  if (!target.starts_with('/') && !(target == "*" && method == Method::kOptions)) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
  }
  const std::string_view path = (target == "*") ? std::string_view("/*") : target;
  std::array<char, 8192> raw{};
  constexpr std::string_view prefix = "http://";
  if (prefix.size() + host.size() + path.size() > raw.size()) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1MessageTooLarge));
  }
  std::memcpy(raw.data(), prefix.data(), prefix.size());
  std::memcpy(raw.data() + prefix.size(), host.data(), host.size());
  std::memcpy(raw.data() + prefix.size() + host.size(), path.data(), path.size());
  return Uri::Parse(std::string_view(raw.data(), prefix.size() + host.size() + path.size()));
}

template <std::size_t N>
class HeadWriter {
 public:
  [[nodiscard]] Result<void> Add(std::string_view text) noexcept {
    if (text.size() > N - len_) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1MessageTooLarge));
    }
    if (!text.empty()) {
      std::memcpy(data_.data() + len_, text.data(), text.size());
      len_ += text.size();
    }
    return {};
  }

  [[nodiscard]] Result<void> AddCrLf() noexcept { return Add("\r\n"); }

  [[nodiscard]] Result<void> AddDec(std::size_t value) noexcept {
    std::array<char, 20> rev{};
    std::size_t n = 0;
    if (value == 0) {
      rev[n++] = '0';
    } else {
      while (value > 0) {
        rev[n++] = static_cast<char>('0' + static_cast<unsigned>(value % 10U));
        value /= 10U;
      }
    }
    while (n > 0) {
      auto added = Add(std::string_view(&rev[n - 1], 1));
      if (!added.has_value()) {
        return added;
      }
      --n;
    }
    return {};
  }

  [[nodiscard]] Result<void> AddHex(std::size_t value) noexcept {
    constexpr std::array<char, 16> digits{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::array<char, 16> rev{};
    std::size_t n = 0;
    if (value == 0) {
      rev[n++] = '0';
    } else {
      while (value > 0) {
        rev[n++] = digits[value & 0xfU];
        value >>= 4U;
      }
    }
    while (n > 0) {
      auto added = Add(std::string_view(&rev[n - 1], 1));
      if (!added.has_value()) {
        return added;
      }
      --n;
    }
    return {};
  }

  [[nodiscard]] Result<void> AddHeaders(const Headers<>& headers) noexcept {
    for (const auto& field : headers) {
      if (!IsValidHeaderName(field.name) || !IsValidHeaderValue(field.value)) {
        return std::unexpected(Error::FromProto(IsValidHeaderName(field.name) ? ProtoErrorCode::kInvalidHeaderValue
                                                                              : ProtoErrorCode::kInvalidHeaderName));
      }
      auto name = Add(field.name);
      if (!name.has_value()) {
        return name;
      }
      auto colon = Add(": ");
      if (!colon.has_value()) {
        return colon;
      }
      auto value = Add(field.value);
      if (!value.has_value()) {
        return value;
      }
      auto crlf = AddCrLf();
      if (!crlf.has_value()) {
        return crlf;
      }
    }
    if (FieldCount(headers, "host") > 1) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    if (const auto host = headers.Get("host"); host.has_value()) {
      auto authority = ValidateAuthority(*host);
      if (!authority.has_value()) {
        return authority;
      }
    }
    return {};
  }

  [[nodiscard]] Result<void> AddLength(Framing framing, std::size_t size) noexcept {
    if (framing.kind == Framing::Kind::kLength && framing.length != size) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    if (framing.kind != Framing::Kind::kAbsent) {
      return {};
    }
    auto label = Add("content-length: ");
    if (!label.has_value()) {
      return label;
    }
    auto digits = AddDec(size);
    if (!digits.has_value()) {
      return digits;
    }
    return AddCrLf();
  }

  [[nodiscard]] std::span<const std::uint8_t> Bytes() const noexcept {
    return {reinterpret_cast<const std::uint8_t*>(data_.data()), len_};
  }

  [[nodiscard]] std::size_t Size() const noexcept { return len_; }

 private:
  std::array<char, N> data_{};
  std::size_t len_{0};
};

template <std::size_t Cap>
[[nodiscard]] inline Result<BytesMut<Cap>> Assemble(std::span<const std::uint8_t> head, std::span<const std::uint8_t> body,
                                                    Framing framing) noexcept {
  BytesMut<Cap> out;
  auto wrote = out.Append(head);
  if (!wrote.has_value()) {
    return std::unexpected(wrote.error());
  }
  if (framing.kind == Framing::Kind::kChunked) {
    if (!body.empty()) {
      HeadWriter<32> chunk;
      auto hex = chunk.AddHex(body.size());
      if (!hex.has_value()) {
        return std::unexpected(hex.error());
      }
      auto crlf = chunk.AddCrLf();
      if (!crlf.has_value()) {
        return std::unexpected(crlf.error());
      }
      auto size_line = out.Append(chunk.Bytes());
      if (!size_line.has_value()) {
        return std::unexpected(size_line.error());
      }
      auto payload = out.Append(body);
      if (!payload.has_value()) {
        return std::unexpected(payload.error());
      }
      auto tail = out.AppendString("\r\n");
      if (!tail.has_value()) {
        return std::unexpected(tail.error());
      }
    }
    auto end = out.AppendString("0\r\n\r\n");
    if (!end.has_value()) {
      return std::unexpected(end.error());
    }
    return out;
  }
  auto payload = out.Append(body);
  if (!payload.has_value()) {
    return std::unexpected(payload.error());
  }
  return out;
}

}  // namespace http1_detail
}  // namespace nexora
