#include "../integration/support.hpp"

struct Deferred {
  std::optional<nexora::Responder> pending;
  nexora::Result<void> Call(nexora::RequestContext&, nexora::Request req, nexora::Responder responder) noexcept {
    const auto owned = std::move(req);
    static_cast<void>(owned);
    pending.emplace(std::move(responder));
    return {};
  }
};
void DestroyInCallback(bool http2, unsigned mode) {
  test::EchoService service;
  nexora::HttpServer server(nexora::HttpService::Bind<&test::EchoService::Call>(service));
  auto client = std::make_unique<nexora::HttpClient>();
  if (http2) test::Check(client->UseHttp2().has_value());
  auto request = nexora::Request::Get("http://localhost/destroy");
  test::Check(request.has_value());
  unsigned calls = 0;
  auto submitted = client->Submit(*request, nexora::ResponseCallback([&](nexora::Result<nexora::Response> response) noexcept {
    ++calls;
    if (mode == 0)
      test::Check(response.has_value());
    else
      test::Check(!response);
    client.reset();
  }),
                                  mode == 2 ? std::chrono::steady_clock::now() : nexora::detail::After(2000));
  test::Check(submitted.has_value());
  if (mode == 1)
    test::Check(client->Cancel(*submitted));
  else if (mode == 2)
    client->Tick();
  else if (mode == 3)
    client->CloseConnection();
  else {
    for (unsigned step = 0; step < 64 && client; ++step) {
      test::Check(server.Pump().has_value());
      if (client) static_cast<void>(test::Transfer(*client, server));
      if (client) static_cast<void>(test::Transfer(server, *client));
    }
  }
  test::Check(!client && calls == 1);
}
int main() {
  for (const bool http2 : {false, true})
    for (unsigned mode = 0; mode < 4; ++mode) DestroyInCallback(http2, mode);
  Deferred service;
  nexora::HttpServer server(nexora::HttpService::Bind<&Deferred::Call>(service));
  nexora::HttpClient client;
  test::Check(client.UseHttp2().has_value());
  auto request = nexora::Request::Get("http://localhost/defer");
  test::Check(request.has_value());
  unsigned callbacks = 0;
  auto id = client.Submit(*request, nexora::ResponseCallback([&callbacks](nexora::Result<nexora::Response> response) noexcept {
    ++callbacks;
    test::Check(!response && response.error() == nexora::Error::Cancelled());
  }));
  test::Check(id.has_value());
  test::Drive(client, server, 3);
  test::Check(service.pending.has_value());
  test::Check(client.Cancel(*id));
  test::Check(!client.Cancel(*id));
  test::Drive(client, server);
  test::Check(callbacks == 1 && client.ActiveCount() == 0);
  test::Check(!service.pending->Respond(nexora::Response::Ok("late")));
  unsigned timeouts = 0;
  auto timed =
      client.Submit(*request, nexora::ResponseCallback([&timeouts](nexora::Result<nexora::Response> response) noexcept {
        ++timeouts;
        test::Check(!response && response.error() == nexora::Error::Timeout());
      }),
                    std::chrono::steady_clock::now());
  test::Check(timed.has_value());
  client.Tick();
  client.Tick();
  test::Check(timeouts == 1);
}
