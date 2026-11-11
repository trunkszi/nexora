#include "../../examples/support.hpp"

struct RedirectService {
  std::optional<nexora::Responder> deferred{};
  nexora::Result<void> Call(nexora::RequestContext&, nexora::Request request, nexora::Responder responder) noexcept {
    const auto owned = std::move(request);
    const auto path = owned.uri.PathAndQuery();
    if (path == "/deadline") {
      deferred.emplace(std::move(responder));
      return {};
    }
    if (path == "/start" || path == "/loop") {
      auto response = nexora::Response::WithStatus(nexora::StatusCode{302});
      if (auto header = response.headers.Add("location", path == "/start" ? "/final" : "/loop"); !header) return header;
      return responder.Respond(std::move(response));
    }
    if (path == "/final") {
      if (owned.method != nexora::Method::kGet || !owned.body.Empty() || owned.headers.Get("authorization") != "retained")
        return responder.Respond(nexora::Response::WithStatus(nexora::StatusCode{400}));
      return responder.Respond(nexora::Response::Ok("redirected"));
    }
    return responder.Respond(nexora::Response::WithStatus(nexora::StatusCode{404}));
  }
};
int main() {
  RedirectService service;
  return example::Loopback(service, [](std::uint16_t port) noexcept {
    auto proactor = uring::Proactor::Create();
    if (!proactor) return 20;
    auto resolver = cares::Resolver<>::FromSystem(*proactor);
    if (!resolver) return 21;
    nexora::ClientConfig config;
    config.max_redirects = 1;
    example::Timer routes(*proactor);
    nexora::HttpClient client(*proactor, *resolver, config, nexora::CompletionRoute::Bind(routes));
    const auto origin = "http://localhost:" + std::to_string(port);
    auto request = nexora::Request::Post(origin + "/start", nexora::Bytes::CopyFromString("discarded on 302"));
    if (!request || !request->headers.Add("authorization", "retained")) return 22;
    auto response = client.Execute(*request);
    if (!response || response->body.AsStringView() != "redirected") return 23;
    request = nexora::Request::Get(origin + "/loop");
    if (!request) return 24;
    response = client.Execute(*request);
    if (response || response.error() != nexora::Error::InvalidArgument()) return 25;
    request = nexora::Request::Get(origin + "/deadline");
    if (!request) return 26;
    const auto started = std::chrono::steady_clock::now();
    response = client.Execute(*request, 25);
    if (response || response.error() != nexora::Error::Timeout() || client.ActiveCount() != 0) return 27;
    if (std::chrono::steady_clock::now() - started > std::chrono::seconds(1)) return 28;
    return 0;
  });
}
