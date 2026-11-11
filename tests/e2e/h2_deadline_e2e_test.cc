#include "../../examples/support.hpp"

struct Service {
  std::optional<nexora::Responder> pending{};
  nexora::Result<void> Call(nexora::RequestContext&, nexora::Request request, nexora::Responder responder) noexcept {
    const auto owned = std::move(request);
    if (owned.uri.PathAndQuery() == "/pending") {
      pending.emplace(std::move(responder));
      return {};
    }
    if (owned.uri.PathAndQuery() == "/after" && (!pending || !pending->IsClosed()))
      return responder.Respond(nexora::Response::WithStatus(nexora::StatusCode{500}));
    return responder.Respond(nexora::Response::Ok("live"));
  }
};
int main() {
  Service service;
  return example::Loopback(service, [](std::uint16_t port) noexcept {
    auto proactor = uring::Proactor::Create();
    if (!proactor) return 20;
    auto resolver = cares::Resolver<>::FromSystem(*proactor);
    if (!resolver) return 21;
    nexora::ClientConfig config;
    config.http2_prior_knowledge = true;
    example::Timer routes(*proactor);
    nexora::HttpClient client(*proactor, *resolver, config, nexora::CompletionRoute::Bind(routes));
    const auto origin = "http://localhost:" + std::to_string(port);
    auto pending = nexora::Request::Get(origin + "/pending");
    auto live = nexora::Request::Get(origin + "/live");
    if (!pending || !live || !client.Connect(pending->uri)) return 22;
    unsigned expired = 0;
    unsigned completed = 0;
    auto first =
        client.Submit(*pending, nexora::ResponseCallback([&expired](nexora::Result<nexora::Response> response) noexcept {
          if (!response && response.error() == nexora::Error::Timeout()) ++expired;
        }),
                      std::chrono::steady_clock::now() + std::chrono::milliseconds(50));
    auto second =
        client.Submit(*live, nexora::ResponseCallback([&completed](nexora::Result<nexora::Response> response) noexcept {
          if (response && response->status.AsU16() == 200) ++completed;
        }));
    if (!first || !second) return 23;
    for (unsigned step = 0; client.ActiveCount() != 0 && step < 16; ++step)
      if (!client.DriveOnce()) return 24;
    if (expired != 1 || completed != 1 || client.ActiveCount() != 0) return 25;
    auto after = nexora::Request::Get(origin + "/after");
    if (!after) return 26;
    auto response = client.Execute(*after);
    if (!response || response->status.AsU16() != 200) return 27;
    std::array<nexora::RequestId, 64> ids{};
    unsigned canceled = 0;
    for (auto& id : ids) {
      auto submitted =
          client.Submit(*live, nexora::ResponseCallback([&canceled](nexora::Result<nexora::Response> reply) noexcept {
            if (!reply && reply.error() == nexora::Error::Cancelled()) ++canceled;
          }));
      if (!submitted) return 28;
      id = *submitted;
    }
    auto overflow =
        client.Submit(*live, nexora::ResponseCallback([](nexora::Result<nexora::Response>) noexcept { std::abort(); }));
    if (overflow || overflow.error() != nexora::Error::FromRuntime(nexora::RuntimeErrorCode::kPoolExhausted)) return 29;
    for (const auto id : ids)
      if (!client.Cancel(id)) return 30;
    if (canceled != 64 || client.ActiveCount() != 0 || !client.Shutdown()) return 31;
    return 0;
  });
}
