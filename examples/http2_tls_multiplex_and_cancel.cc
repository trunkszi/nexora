#include "support.hpp"

int main() {
  auto server_tls = nexora::TlsServerConfig::SelfSignedForLocalhost();
  auto client_tls = nexora::TlsClientConfig::CreateInsecureForTest();
  if (!server_tls || !client_tls) return 1;
  constexpr std::array protocols{nexora::AlpnProtocol::kHttp2, nexora::AlpnProtocol::kHttp11};
  if (!server_tls->SetAlpn(protocols)) return 2;
  example::Echo service;
  return example::Loopback(
      service,
      [&client_tls](std::uint16_t port) noexcept {
        auto proactor = uring::Proactor::Create();
        if (!proactor) return 20;
        auto resolver = cares::Resolver<>::FromSystem(*proactor);
        if (!resolver) return 21;
        nexora::ClientConfig config;
        config.tls_config = &*client_tls;
        example::Timer routes(*proactor);
        nexora::HttpClient client(*proactor, *resolver, config, nexora::CompletionRoute::Bind(routes));
        auto request = nexora::Request::Get("https://localhost:" + std::to_string(port) + "/multiplex");
        if (!request || !client.Connect(request->uri) || !client.IsHttp2()) return 22;
        unsigned completed = 0;
        unsigned canceled = 0;
        for (unsigned index = 0; index < 3; ++index) {
          auto id = client.Submit(
              *request, nexora::ResponseCallback([&completed, &canceled](nexora::Result<nexora::Response> response) noexcept {
                if (response && response->body.AsStringView() == "/multiplex")
                  ++completed;
                else if (!response && response.error() == nexora::Error::Cancelled())
                  ++canceled;
              }));
          if (!id) return 23;
          if (index == 1 && !client.Cancel(*id)) return 24;
        }
        for (unsigned step = 0; client.ActiveCount() != 0 && step < 32; ++step)
          if (!client.DriveOnce()) return 25;
        if (completed != 2 || canceled != 1 || !client.Shutdown()) return 26;
        std::puts("TLS 1.3 / ALPN h2: multiplexed responses and exactly one cancellation");
        return 0;
      },
      &*server_tls);
}
