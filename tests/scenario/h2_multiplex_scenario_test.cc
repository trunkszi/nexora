#include "../integration/support.hpp"

struct Service {
  std::array<std::optional<nexora::Responder>, 3> responders{};
  std::size_t count{0};
  nexora::Result<void> Call(nexora::RequestContext&, nexora::Request req, nexora::Responder responder) noexcept {
    const auto owned = std::move(req);
    static_cast<void>(owned);
    responders[count++].emplace(std::move(responder));
    return {};
  }
};
struct Hooks {
  unsigned headers{0};
  unsigned data{0};
  unsigned trailers{0};
  void Event(nexora::RequestId, const nexora::Http2Event& event) noexcept {
    if (event.kind == nexora::Http2Event::Kind::kHeaders) ++headers;
    if (event.kind == nexora::Http2Event::Kind::kData) ++data;
    if (event.kind == nexora::Http2Event::Kind::kTrailers) ++trailers;
  }
};
int main() {
  Service service;
  Hooks hooks;
  nexora::HttpClient client;
  test::Check(client.UseHttp2().has_value());
  client.SetStreamHook(cares::Delegate<void(nexora::RequestId, const nexora::Http2Event&)>::Bind<&Hooks::Event>(&hooks));
  nexora::HttpServer server(nexora::HttpService::Bind<&Service::Call>(service));
  auto request = nexora::Request::Get("http://localhost/multi");
  test::Check(request.has_value());
  std::vector<unsigned> order;
  for (unsigned index = 0; index < 3; ++index) {
    auto id =
        client.Submit(*request, nexora::ResponseCallback([&order, index](nexora::Result<nexora::Response> response) noexcept {
          test::Check(response.has_value() && response->version == nexora::Version::kHttp2);
          test::Check(response->body.AsStringView() == "streamed");
          test::Check(response->trailers.Get("x-complete") == "yes");
          order.push_back(index);
        }));
    test::Check(id.has_value());
  }
  test::Drive(client, server, 11);
  test::Check(service.count == 3 && order.empty());
  for (unsigned index : {2U, 0U, 1U}) {
    auto response = nexora::Response::Ok("streamed");
    test::Check(response.trailers.Add("x-complete", "yes").has_value());
    test::Check(service.responders[index]->Respond(std::move(response)).has_value());
    test::Drive(client, server, 13);
  }
  test::Check(order == std::vector<unsigned>({2, 0, 1}));
  test::Check(hooks.headers == 3 && hooks.data >= 3 && hooks.trailers == 3);
}
