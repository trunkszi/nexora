#include "../../examples/support.hpp"

struct Redirect {
  std::string destination;
  std::uint16_t status{307};
  unsigned calls{0};
  nexora::Result<void> Call(nexora::RequestContext&, nexora::Request request, nexora::Responder responder) noexcept {
    ++calls;
    const auto owned = std::move(request);
    static_cast<void>(owned);
    auto response = nexora::Response::WithStatus(nexora::StatusCode{status});
    if (auto set = response.headers.Set("location", destination); !set) return set;
    return responder.Respond(std::move(response));
  }
};
struct Destination {
  unsigned calls{0};
  nexora::Result<void> Call(nexora::RequestContext&, nexora::Request request, nexora::Responder responder) noexcept {
    ++calls;
    const auto owned = std::move(request);
    const bool stripped =
        !owned.headers.Get("authorization") && !owned.headers.Get("cookie") && !owned.headers.Get("proxy-authorization");
    const bool retained = owned.method == nexora::Method::kPost && owned.body.AsStringView() == "retained body";
    return responder.Respond(
        nexora::Response::WithStatus((stripped && retained ? nexora::StatusCode{200} : nexora::StatusCode{400})));
  }
};
int main() {
  auto destination = nexora::LoopbackListener::Bind();
  if (!destination) return 1;
  const auto child = ::fork();
  if (child < 0) return 2;
  if (child == 0) {
    Destination service;
    std::_Exit(example::Serve(*destination, service, nullptr));
  }
  Redirect redirect{"http://127.0.0.1:" + std::to_string(destination->Port()) + "/target"};
  const auto crossed = example::Loopback(redirect, [](std::uint16_t port) noexcept {
    auto request = nexora::Request::Post("http://localhost:" + std::to_string(port) + "/start",
                                         nexora::Bytes::CopyFromString("retained body"));
    if (!request || !request->headers.Set("authorization", "secret") || !request->headers.Set("cookie", "secret") ||
        !request->headers.Set("proxy-authorization", "secret"))
      return 20;
    nexora::HttpClient client;
    auto response = client.Execute(*request);
    if (!response) std::fprintf(stderr, "cross-origin error: %d\n", response.error().code);
    return response && response->status.AsU16() == 200 ? 0 : 21;
  });
  int status = 0;
  if (::waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0 || crossed != 0) return 3;

  auto tls = nexora::TlsServerConfig::SelfSignedForLocalhost();
  auto client_tls = nexora::TlsClientConfig::CreateInsecureForTest();
  if (!tls || !client_tls) return 4;
  constexpr std::array alpn{nexora::AlpnProtocol::kHttp11};
  if (!tls->SetAlpn(alpn) || !client_tls->SetAlpn(alpn)) return 5;
  for (const std::uint16_t code : {std::uint16_t{307}, std::uint16_t{308}}) {
    Redirect downgrade{"http://127.0.0.1:1/plaintext", code};
    const auto rejected = example::Loopback(
        downgrade,
        [&](std::uint16_t port) noexcept {
          nexora::ClientConfig config;
          config.tls_config = &*client_tls;
          nexora::HttpClient client(config);
          auto request = nexora::Request::Post("https://localhost:" + std::to_string(port) + "/start",
                                               nexora::Bytes::CopyFromString("private body"));
          if (!request || !request->headers.Set("authorization", "secret")) return 22;
          auto response = client.Execute(*request);
          return !response && response.error() == nexora::Error::FromProto(nexora::ProtoErrorCode::kInvalidUri) ? 0 : 23;
        },
        &*tls);
    if (rejected != 0) {
      std::fprintf(stderr, "downgrade %u result: %d\n", code, rejected);
      return rejected;
    }
  }
}
