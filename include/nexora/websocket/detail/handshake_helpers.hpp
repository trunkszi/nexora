/** @file @brief RFC 6455 WebSocket handshake token, extension, key, and SHA-1 helpers. */
#pragma once

#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <nexora/bytes/scan.hpp>
#include <nexora/http/message.hpp>
#include <span>
#include <string_view>

namespace nexora::ws_detail {

inline constexpr std::string_view kAcceptGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
inline constexpr std::string_view kBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

[[nodiscard]] inline int Base64Value(char c) noexcept {
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z') {
    return c - 'a' + 26;
  }
  if (c >= '0' && c <= '9') {
    return c - '0' + 52;
  }
  if (c == '+') {
    return 62;
  }
  if (c == '/') {
    return 63;
  }
  return -1;
}

[[nodiscard]] inline Result<std::array<std::uint8_t, 16>> DecodeKey(std::string_view key) noexcept {
  if (key.size() != 24 || key[22] != '=' || key[23] != '=') {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
  }
  std::array<std::uint8_t, 16> out{};
  std::size_t produced = 0;
  for (std::size_t i = 0; i < 24; i += 4) {
    const int a = Base64Value(key[i]);
    const int b = Base64Value(key[i + 1]);
    const bool pad = key[i + 2] == '=';
    const int c = pad ? 0 : Base64Value(key[i + 2]);
    const int d = key[i + 3] == '=' ? 0 : Base64Value(key[i + 3]);
    if (a < 0 || b < 0 || c < 0 || d < 0) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    if (pad != (key[i + 3] == '=') || (pad && i != 20)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    if (pad && (b & 0x0f) != 0) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    out[produced++] = static_cast<std::uint8_t>((a << 2) | (b >> 4));
    if (!pad) {
      out[produced++] = static_cast<std::uint8_t>(((b & 0x0f) << 4) | (c >> 2));
      out[produced++] = static_cast<std::uint8_t>(((c & 0x03) << 6) | d);
    }
  }
  if (produced != 16) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
  }
  return out;
}

template <std::size_t N>
[[nodiscard]] inline std::array<char, N> EncodeBase64(std::span<const std::uint8_t> raw) noexcept {
  std::array<char, N> out{};
  std::size_t o = 0;
  std::size_t i = 0;
  while (i + 3 <= raw.size() && o + 4 <= N) {
    const unsigned n =
        (static_cast<unsigned>(raw[i]) << 16) | (static_cast<unsigned>(raw[i + 1]) << 8) | static_cast<unsigned>(raw[i + 2]);
    out[o++] = kBase64[(n >> 18) & 63U];
    out[o++] = kBase64[(n >> 12) & 63U];
    out[o++] = kBase64[(n >> 6) & 63U];
    out[o++] = kBase64[n & 63U];
    i += 3;
  }
  if (i < raw.size() && o + 4 <= N) {
    const unsigned a = raw[i];
    const unsigned b = (i + 1 < raw.size()) ? raw[i + 1] : 0U;
    const unsigned n = (a << 16) | (b << 8);
    out[o++] = kBase64[(n >> 18) & 63U];
    out[o++] = kBase64[(n >> 12) & 63U];
    if (raw.size() - i == 1) {
      out[o++] = '=';
      out[o++] = '=';
    } else {
      out[o++] = kBase64[(n >> 6) & 63U];
      out[o++] = '=';
    }
  }
  return out;
}

[[nodiscard]] inline Result<std::array<std::uint8_t, 20>> Sha1(std::span<const std::uint8_t> data) noexcept {
  std::array<std::uint8_t, 20> md{};
  unsigned int len = 0;
  if (EVP_Digest(data.data(), data.size(), md.data(), &len, EVP_sha1(), nullptr) != 1 || len != 20U) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketHandshakeFailed));
  }
  return md;
}

[[nodiscard]] inline bool OwnedHeader(std::string_view name) noexcept {
  return AsciiEqualsIgnoreCase(name, "host") || AsciiEqualsIgnoreCase(name, "upgrade") ||
         AsciiEqualsIgnoreCase(name, "connection") || AsciiEqualsIgnoreCase(name, "sec-websocket-version") ||
         AsciiEqualsIgnoreCase(name, "sec-websocket-key") || AsciiEqualsIgnoreCase(name, "sec-websocket-accept") ||
         AsciiEqualsIgnoreCase(name, "content-length") || AsciiEqualsIgnoreCase(name, "transfer-encoding");
}

[[nodiscard]] inline bool ValidToken(std::string_view token) noexcept { return IsValidHeaderName(token); }

[[nodiscard]] inline Result<std::string_view> Singleton(const Headers<>& headers, std::string_view name,
                                                        bool missing_is_protocol) noexcept {
  const auto fields = headers.GetAll(name);
  if (fields.empty()) {
    return std::unexpected(Error::FromProto(missing_is_protocol ? ProtoErrorCode::kWebSocketProtocolError
                                                                : ProtoErrorCode::kWebSocketHandshakeFailed));
  }
  if (fields.size() != 1) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
  }
  return TrimAsciiWhitespace(fields[0]);
}

[[nodiscard]] inline Result<void> RequireToken(const Headers<>& headers, std::string_view name,
                                               std::string_view required) noexcept {
  bool present = false;
  bool found = false;
  for (const auto& field : headers) {
    if (!AsciiEqualsIgnoreCase(field.name, name)) {
      continue;
    }
    present = true;
    std::string_view raw(field.value);
    std::size_t start = 0;
    while (start <= raw.size()) {
      const auto comma = raw.find(',', start);
      const auto token =
          TrimAsciiWhitespace((comma == std::string_view::npos) ? raw.substr(start) : raw.substr(start, comma - start));
      bool valid = ValidToken(token);
      if (AsciiEqualsIgnoreCase(name, "upgrade")) {
        const auto slash = token.find('/');
        if (slash == std::string_view::npos) {
          valid = ValidToken(token);
        } else if (token.find('/', slash + 1) != std::string_view::npos) {
          valid = false;
        } else {
          valid = ValidToken(token.substr(0, slash)) && ValidToken(token.substr(slash + 1));
        }
      }
      if (!valid) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
      }
      if (AsciiEqualsIgnoreCase(token, required)) {
        found = true;
      }
      if (comma == std::string_view::npos) {
        break;
      }
      start = comma + 1;
    }
  }
  if (!present) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketHandshakeFailed));
  }
  if (!found) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
  }
  return {};
}

[[nodiscard]] inline bool ValidParameter(std::string_view value) noexcept {
  if (!value.starts_with('"')) {
    return ValidToken(value);
  }
  if (value.size() < 2 || !value.ends_with('"')) {
    return false;
  }
  const auto quoted = value.substr(1, value.size() - 2);
  if (quoted.empty()) {
    return false;
  }
  for (std::size_t i = 0; i < quoted.size(); ++i) {
    char byte = quoted[i];
    if (byte == '\\') {
      if (i + 1 >= quoted.size()) {
        return false;
      }
      byte = quoted[++i];
    }
    if (!detail::kHttpTokenTable[static_cast<unsigned char>(byte)]) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] inline Result<std::string_view> ParseExtensionElement(std::string_view ext) noexcept {
  ext = TrimAsciiWhitespace(ext);
  if (ext.empty()) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
  }
  std::string_view ext_name{};
  std::size_t part_at = 0;
  bool first = true;
  while (part_at <= ext.size()) {
    const auto semi = ext.find(';', part_at);
    const auto part =
        TrimAsciiWhitespace((semi == std::string_view::npos) ? ext.substr(part_at) : ext.substr(part_at, semi - part_at));
    if (first) {
      if (!ValidToken(part)) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
      }
      ext_name = part;
      first = false;
    } else {
      const auto eq = part.find('=');
      const auto pname = TrimAsciiWhitespace((eq == std::string_view::npos) ? part : part.substr(0, eq));
      if (!ValidToken(pname) || (eq != std::string_view::npos && !ValidParameter(TrimAsciiWhitespace(part.substr(eq + 1))))) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
      }
    }
    if (semi == std::string_view::npos) {
      break;
    }
    part_at = semi + 1;
  }
  return ext_name;
}

[[nodiscard]] inline Result<void> ValidateOffers(const Headers<>& headers) noexcept {
  std::array<std::string_view, 64> protocols{};
  std::size_t count = 0;
  for (const auto& field : headers) {
    if (AsciiEqualsIgnoreCase(field.name, "sec-websocket-protocol")) {
      std::string_view raw(field.value);
      std::size_t start = 0;
      while (start <= raw.size()) {
        const auto comma = raw.find(',', start);
        const auto token =
            TrimAsciiWhitespace((comma == std::string_view::npos) ? raw.substr(start) : raw.substr(start, comma - start));
        if (!ValidToken(token) || count >= protocols.size()) {
          return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
        }
        for (std::size_t i = 0; i < count; ++i) {
          if (protocols[i] == token) {
            return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
          }
        }
        protocols[count++] = token;
        if (comma == std::string_view::npos) {
          break;
        }
        start = comma + 1;
      }
    } else if (AsciiEqualsIgnoreCase(field.name, "sec-websocket-extensions")) {
      std::string_view raw(field.value);
      std::size_t start = 0;
      while (start <= raw.size()) {
        const auto comma = raw.find(',', start);
        const auto ext = (comma == std::string_view::npos) ? raw.substr(start) : raw.substr(start, comma - start);
        if (auto parsed = ParseExtensionElement(ext); !parsed) {
          return std::unexpected(parsed.error());
        }
        if (comma == std::string_view::npos) {
          break;
        }
        start = comma + 1;
      }
    }
  }
  return {};
}

[[nodiscard]] inline bool ListedToken(const Headers<>* request, std::string_view header, std::string_view token,
                                      bool extension) noexcept {
  if (request == nullptr || token.empty()) {
    return false;
  }
  for (const auto& field : *request) {
    if (!AsciiEqualsIgnoreCase(field.name, header)) {
      continue;
    }
    const std::string_view raw = field.value;
    std::size_t start = 0;
    while (start <= raw.size()) {
      const auto comma = raw.find(',', start);
      auto part = TrimAsciiWhitespace(comma == std::string_view::npos ? raw.substr(start) : raw.substr(start, comma - start));
      if (extension) {
        const auto semi = part.find(';');
        if (semi != std::string_view::npos) {
          part = TrimAsciiWhitespace(part.substr(0, semi));
        }
      }
      if (part == token) {
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

[[nodiscard]] inline Result<void> AcceptNegotiated(const Headers<>& response, const Headers<>* request) noexcept {
  bool saw_protocol = false;
  for (const auto& field : response) {
    const bool protocol = AsciiEqualsIgnoreCase(field.name, "sec-websocket-protocol");
    const bool extension = AsciiEqualsIgnoreCase(field.name, "sec-websocket-extensions");
    if (!protocol && !extension) {
      continue;
    }
    const std::string_view raw = field.value;
    if (protocol) {
      if (saw_protocol || raw.find(',') != std::string_view::npos) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
      }
      const auto token = TrimAsciiWhitespace(raw);
      if (!ValidToken(token) || !ListedToken(request, "sec-websocket-protocol", token, false)) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
      }
      saw_protocol = true;
      continue;
    }
    std::size_t start = 0;
    bool any = false;
    while (start <= raw.size()) {
      const auto comma = raw.find(',', start);
      const auto ext = (comma == std::string_view::npos) ? raw.substr(start) : raw.substr(start, comma - start);
      auto ext_name = ParseExtensionElement(ext);
      if (!ext_name || !ListedToken(request, "sec-websocket-extensions", *ext_name, true)) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
      }
      any = true;
      if (comma == std::string_view::npos) {
        break;
      }
      start = comma + 1;
    }
    if (!any) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
  }
  return {};
}

[[nodiscard]] inline Result<void> ValidateEmptyBody(const Headers<>& headers, bool body_empty) noexcept {
  if (!body_empty || headers.Contains("transfer-encoding")) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
  }
  auto length = headers.ContentLength();
  if (!length.has_value()) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
  }
  if (length->has_value() && **length != 0) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
  }
  return {};
}

[[nodiscard]] inline Result<void> ValidateHeaderSyntax(const Headers<>& headers) noexcept {
  for (const auto& field : headers) {
    if (!IsValidHeaderName(field.name) || !IsValidHeaderValue(field.value)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
  }
  return {};
}

}  // namespace nexora::ws_detail
