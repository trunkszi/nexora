#include "support.hpp"

struct Gateway {
  unsigned calls{0};
  [[= nexora::HttpRoute{nexora::Method::kGet, "/health"}]] nexora::Result<void> Health(nexora::RequestContext&,
                                                                                       nexora::Request req,
                                                                                       nexora::Responder responder) noexcept {
    ++calls;
    const auto owned = std::move(req);
    static_cast<void>(owned);
    return responder.Respond(nexora::Response::Ok("healthy"));
  }
  [[= nexora::WebSocketRoute{"/events"}]] nexora::Result<void> Events(nexora::WebSocketServerSession& session,
                                                                      nexora::WebSocketMessage message) noexcept {
    ++calls;
    const auto owned = std::move(message);
    if (!session.IsOpen()) return {};
    return session.Send(owned);
  }
};
int main() {
  Gateway service;
  nexora::ReflectService routes(service);
  const int http1 = example::Loopback(routes, [](std::uint16_t port) noexcept {
    nexora::HttpClient client;
    auto request = nexora::Request::Get("http://localhost:" + std::to_string(port) + "/health");
    if (!request) return 20;
    auto response = client.Execute(*request);
    return response && response->body.AsStringView() == "healthy" ? 0 : 21;
  });
  if (http1 != 0) return http1;
  auto server_tls = nexora::TlsServerConfig::SelfSignedForLocalhost();
  auto client_tls = nexora::TlsClientConfig::CreateInsecureForTest();
  if (!server_tls || !client_tls) return 22;
  constexpr std::array protocols{nexora::AlpnProtocol::kHttp2, nexora::AlpnProtocol::kHttp11};
  if (!server_tls->SetAlpn(protocols)) return 23;
  const int http2 = example::Loopback(
      routes,
      [&client_tls](std::uint16_t port) noexcept {
        nexora::ClientConfig config;
        config.tls_config = &*client_tls;
        nexora::HttpClient client(config);
        auto request = nexora::Request::Get("https://localhost:" + std::to_string(port) + "/health");
        if (!request) return 24;
        auto response = client.Execute(*request);
        return response && response->version == nexora::Version::kHttp2 && response->body.AsStringView() == "healthy" ? 0 : 25;
      },
      &*server_tls);
  if (http2 != 0) return http2;
  const int websocket = example::Loopback(routes, [](std::uint16_t port) noexcept {
    nexora::WebSocketClient client;
    auto uri = nexora::Uri::Parse("ws://localhost:" + std::to_string(port) + "/events");
    if (!uri || !client.Connect(*uri) || !client.SendText("gateway")) return 26;
    auto response = client.Receive();
    if (!response || response->payload.AsStringView() != "gateway" || !client.Close()) return 27;
    response = client.Receive();
    return response && response->kind == nexora::WebSocketMessageKind::kClose ? 0 : 28;
  });
  if (websocket != 0) return websocket;
  const int rejected = example::Loopback(routes, [](std::uint16_t port) noexcept {
    nexora::WebSocketClient client;
    auto uri = nexora::Uri::Parse("ws://localhost:" + std::to_string(port) + "/missing");
    if (!uri) return 29;
    auto accepted = client.Connect(*uri);
    return !accepted && accepted.error() == nexora::Error::FromProto(nexora::ProtoErrorCode::kWebSocketProtocolError) ? 0 : 30;
  });
  if (rejected == 0) std::puts("Reflection gateway: HTTP/1.1, TLS 1.3 + h2, WebSocket routes and upgrade rejection");
  return rejected;
}
