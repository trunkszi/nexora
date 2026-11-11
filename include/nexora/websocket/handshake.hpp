/** @file @brief RFC 6455 WebSocket upgrade request and response handshake codec. */
#pragma once

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <nexora/http/message.hpp>
#include <nexora/websocket/detail/handshake_helpers.hpp>
#include <span>
#include <string_view>

namespace nexora {

struct WebSocketKeyText {
  std::array<char, 24> text{};

  [[nodiscard]] std::string_view View() const noexcept { return {text.data(), text.size()}; }
};

struct WebSocketAcceptText {
  std::array<char, 28> text{};

  [[nodiscard]] std::string_view View() const noexcept { return {text.data(), text.size()}; }
};

class WebSocketHandshake {
 public:
  [[nodiscard]] static Result<WebSocketKeyText> GenerateKey(std::uint64_t seed) noexcept {
    const auto raw = std::bit_cast<std::array<std::uint8_t, 8>>(std::byteswap(seed));
    auto digest = ws_detail::Sha1(raw);
    if (!digest.has_value()) {
      return std::unexpected(digest.error());
    }
    WebSocketKeyText key;
    key.text = ws_detail::EncodeBase64<24>(std::span<const std::uint8_t>(digest->data(), 16));
    return key;
  }

  [[nodiscard]] static Result<WebSocketAcceptText> ComputeAccept(std::string_view client_key) noexcept {
    return ComputeAcceptKey(client_key);
  }

  [[nodiscard]] static Result<WebSocketAcceptText> ComputeAcceptKey(std::string_view client_key) noexcept {
    std::array<std::uint8_t, 256> mixed{};
    if (client_key.size() + ws_detail::kAcceptGuid.size() > mixed.size()) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    std::memcpy(mixed.data(), client_key.data(), client_key.size());
    std::memcpy(mixed.data() + client_key.size(), ws_detail::kAcceptGuid.data(), ws_detail::kAcceptGuid.size());
    auto digest =
        ws_detail::Sha1(std::span<const std::uint8_t>(mixed.data(), client_key.size() + ws_detail::kAcceptGuid.size()));
    if (!digest.has_value()) {
      return std::unexpected(digest.error());
    }
    WebSocketAcceptText accept;
    accept.text = ws_detail::EncodeBase64<28>(*digest);
    return accept;
  }

  [[nodiscard]] static Result<Request> BuildUpgradeRequest(const Uri& uri, std::string_view sec_key,
                                                           const Headers<>& extra = {}) noexcept {
    Request request(Method::kGet, uri, Version::kHttp11);
    for (const auto& field : extra) {
      if (ws_detail::OwnedHeader(field.name)) {
        continue;
      }
      auto added = request.headers.Add(field.name, field.value);
      if (!added.has_value()) {
        return std::unexpected(added.error());
      }
    }
    auto host = request.SetHeader("host", uri.Authority());
    if (!host.has_value()) {
      return std::unexpected(host.error());
    }
    auto upgrade = request.SetHeader("upgrade", "websocket");
    if (!upgrade.has_value()) {
      return std::unexpected(upgrade.error());
    }
    auto connection = request.SetHeader("connection", "Upgrade");
    if (!connection.has_value()) {
      return std::unexpected(connection.error());
    }
    auto version = request.SetHeader("sec-websocket-version", "13");
    if (!version.has_value()) {
      return std::unexpected(version.error());
    }
    auto key = request.SetHeader("sec-websocket-key", sec_key);
    if (!key.has_value()) {
      return std::unexpected(key.error());
    }
    return request;
  }

  [[nodiscard]] static Result<WebSocketKeyText> ValidateUpgradeRequest(const Request& request) noexcept {
    if (request.method != Method::kGet || request.version != Version::kHttp11) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    auto syntax = ws_detail::ValidateHeaderSyntax(request.headers);
    if (!syntax.has_value()) {
      return std::unexpected(syntax.error());
    }
    auto host = ws_detail::Singleton(request.headers, "host", false);
    if (!host.has_value()) {
      return std::unexpected(host.error());
    }
    if (host->find('/') != std::string_view::npos || host->find('?') != std::string_view::npos ||
        host->find('#') != std::string_view::npos) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    std::array<char, 2048> raw{};
    constexpr std::string_view prefix = "http://";
    if (prefix.size() + host->size() + 1 > raw.size()) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    std::memcpy(raw.data(), prefix.data(), prefix.size());
    std::memcpy(raw.data() + prefix.size(), host->data(), host->size());
    raw[prefix.size() + host->size()] = '/';
    auto parsed = Uri::Parse(std::string_view(raw.data(), prefix.size() + host->size() + 1));
    if (!parsed.has_value()) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    auto upgrade = ws_detail::RequireToken(request.headers, "upgrade", "websocket");
    if (!upgrade.has_value()) {
      return std::unexpected(upgrade.error());
    }
    auto connection = ws_detail::RequireToken(request.headers, "connection", "upgrade");
    if (!connection.has_value()) {
      return std::unexpected(connection.error());
    }
    auto ws_version = ws_detail::Singleton(request.headers, "sec-websocket-version", false);
    if (!ws_version.has_value()) {
      return std::unexpected(ws_version.error());
    }
    if (*ws_version != "13") {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    auto key = ws_detail::Singleton(request.headers, "sec-websocket-key", false);
    if (!key.has_value()) {
      return std::unexpected(key.error());
    }
    auto decoded = ws_detail::DecodeKey(*key);
    if (!decoded.has_value()) {
      return std::unexpected(decoded.error());
    }
    auto offers = ws_detail::ValidateOffers(request.headers);
    if (!offers.has_value()) {
      return std::unexpected(offers.error());
    }
    auto body = ws_detail::ValidateEmptyBody(request.headers, request.body.Empty());
    if (!body.has_value()) {
      return std::unexpected(body.error());
    }
    WebSocketKeyText text;
    std::memcpy(text.text.data(), key->data(), text.text.size());
    return text;
  }

  [[nodiscard]] static Result<Response> BuildUpgradeResponse(std::string_view client_key,
                                                             const Headers<>& extra = {}) noexcept {
    auto accept = ComputeAcceptKey(client_key);
    if (!accept.has_value()) {
      return std::unexpected(accept.error());
    }
    Response response(StatusCode{StatusCode::kSwitchingProtocols});
    response.version = Version::kHttp11;
    for (const auto& field : extra) {
      if (ws_detail::OwnedHeader(field.name)) {
        continue;
      }
      auto added = response.headers.Add(field.name, field.value);
      if (!added.has_value()) {
        return std::unexpected(added.error());
      }
    }
    auto upgrade = response.SetHeader("upgrade", "websocket");
    if (!upgrade.has_value()) {
      return std::unexpected(upgrade.error());
    }
    auto connection = response.SetHeader("connection", "Upgrade");
    if (!connection.has_value()) {
      return std::unexpected(connection.error());
    }
    auto key = response.SetHeader("sec-websocket-accept", accept->View());
    if (!key.has_value()) {
      return std::unexpected(key.error());
    }
    return response;
  }

  [[nodiscard]] static Result<void> ValidateUpgradeResponse(const Response& response, std::string_view expected_client_key,
                                                            const Headers<>* request_headers = nullptr) noexcept {
    if (response.status.AsU16() != StatusCode::kSwitchingProtocols || response.version != Version::kHttp11) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    auto syntax = ws_detail::ValidateHeaderSyntax(response.headers);
    if (!syntax.has_value()) {
      return std::unexpected(syntax.error());
    }
    auto key_ok = ws_detail::DecodeKey(expected_client_key);
    if (!key_ok.has_value()) {
      return std::unexpected(key_ok.error());
    }
    auto upgrade = ws_detail::RequireToken(response.headers, "upgrade", "websocket");
    if (!upgrade.has_value()) {
      return std::unexpected(upgrade.error());
    }
    auto connection = ws_detail::RequireToken(response.headers, "connection", "upgrade");
    if (!connection.has_value()) {
      return std::unexpected(connection.error());
    }
    auto accept = ws_detail::Singleton(response.headers, "sec-websocket-accept", false);
    if (!accept.has_value()) {
      return std::unexpected(accept.error());
    }
    auto expected = ComputeAcceptKey(expected_client_key);
    if (!expected.has_value()) {
      return std::unexpected(expected.error());
    }
    if (*accept != expected->View()) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    if (auto negotiated = ws_detail::AcceptNegotiated(response.headers, request_headers); !negotiated.has_value()) {
      return std::unexpected(negotiated.error());
    }
    if (response.headers.Contains("content-length")) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    return ws_detail::ValidateEmptyBody(response.headers, response.body.Empty());
  }
};

}  // namespace nexora
