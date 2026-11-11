#include "support.hpp"

int main() {
  example::Echo service;
  return example::Loopback(service, [](std::uint16_t port) noexcept {
    auto proactor = uring::Proactor::Create();
    if (!proactor) return 20;
    auto resolver = cares::Resolver<>::FromSystem(*proactor);
    if (!resolver) return 21;
    example::Timer routes(*proactor);
    nexora::HttpClient client(*proactor, *resolver, {}, nexora::CompletionRoute::Bind(routes));
    auto request = nexora::Request::Get("http://localhost:" + std::to_string(port) + "/keepalive");
    if (!request) return 22;
    for (unsigned index = 0; index < 3; ++index) {
      auto response = client.Execute(*request);
      if (!response || response->body.AsStringView() != "/keepalive") return 23;
    }
    if (!client.Shutdown()) return 24;
    std::puts("HTTP/1.1 keep-alive: three requests, c-ares localhost resolution");
    return 0;
  });
}
