#include <chrono>
#include <cstdint>
#include <nexora/http2/detail/event_flow.hpp>
#include <nexora/server/listener.hpp>
#include <string>
#include <thread>

#include "../../integration/support.hpp"

struct Deferred {
  std::array<std::optional<nexora::Responder>, 4> pending{};
  std::size_t count{0};
  nexora::Result<void> Call(nexora::RequestContext&, nexora::Request req, nexora::Responder responder) noexcept {
    const auto owned = std::move(req);
    static_cast<void>(owned);
    pending[count++].emplace(std::move(responder));
    return {};
  }
};

namespace {

struct ByteSpan {
  std::size_t n{0};
  [[nodiscard]] constexpr std::size_t size() const noexcept { return n; }
};

struct FlowCreditEvent {
  int flow_control_bytes{0};
  ByteSpan data{};
};

struct DataOnlyEvent {
  ByteSpan data{};
};

struct PayloadEvent {
  struct PayloadBytes {
    [[nodiscard]] static constexpr std::size_t size() noexcept { return 7; }
  };
  [[nodiscard]] static constexpr PayloadBytes Payload() noexcept { return {}; }
  ByteSpan data{.n = 3};
};

static_assert(nexora::detail::EventFlowControlBytes(FlowCreditEvent{.flow_control_bytes = 11, .data = {.n = 2}}) == 11);
static_assert(nexora::detail::EventFlowControlBytes(FlowCreditEvent{.flow_control_bytes = 0, .data = {.n = 4}}) == 4);
static_assert(nexora::detail::EventFlowControlBytes(DataOnlyEvent{.data = {.n = 5}}) == 5);
static_assert(nexora::detail::EventFlowControlBytes(PayloadEvent{}) == 7);

void QuarantineThenConnect() noexcept {
  std::uint16_t port = 0;
  {
    auto listener = nexora::LoopbackListener::Bind();
    test::Check(listener.has_value());
    port = listener->Port();
  }
  auto ring = uring::Proactor::Create();
  test::Check(ring.has_value());
  auto resolver = cares::Resolver<>::FromSystem(*ring);
  test::Check(resolver.has_value());
  nexora::ClientConfig cfg{
      .pool = {.endpoint_base_cooldown_ns = 10'000'000ULL, .endpoint_max_cooldown_ns = 10'000'000ULL},
      .connect_timeout_ms = 300,
      .prefer_http2 = false,
      .enable_tls = false,
  };
  nexora::HttpClient client(*ring, *resolver, std::move(cfg), nexora::detail::PrivateRingRoute());
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/ready";
  auto uri = nexora::Uri::Parse(url);
  test::Check(uri.has_value());
  auto refused = client.Connect(*uri, 1000);
  test::Check(!refused);
  std::this_thread::sleep_for(std::chrono::milliseconds(30));
  auto restored = nexora::LoopbackListener::Bind(port);
  test::Check(restored.has_value() && restored->Port() == port);
  auto recovered = client.Connect(*uri, 1000);
  test::Check(recovered.has_value());
}

void BadTrailersStayLocal() noexcept {
  Deferred service;
  nexora::HttpServer server(nexora::HttpService::Bind<&Deferred::Call>(service));
  nexora::HttpClient client;
  test::Check(client.UseHttp2().has_value());
  test::Drive(client, server);
  bool sibling_ok = false;
  auto live = nexora::Request::Get("http://localhost/live");
  test::Check(live.has_value());
  test::Check(client
                  .Submit(*live, nexora::ResponseCallback([&](nexora::Result<nexora::Response> res) noexcept {
                    sibling_ok = res.has_value() && res->status.AsU16() == 200 && res->body.AsStringView() == "alive";
                  }))
                  .has_value());
  test::Drive(client, server);
  test::Check(service.count == 1 && client.ActiveCount() == 1);
  const auto reject = [&](nexora::Request req, nexora::Error expected) noexcept {
    const auto before = client.PendingOutput().size();
    const auto active = client.ActiveCount();
    auto submitted = client.Submit(std::move(req), nexora::ResponseCallback([](nexora::Result<nexora::Response>) noexcept {}));
    test::Check(!submitted && submitted.error() == expected);
    test::Check(client.PendingOutput().size() == before && client.ActiveCount() == active);
  };
  auto hop = nexora::Request::Get("http://localhost/hop");
  test::Check(hop.has_value() && hop->trailers.Set("connection", "close").has_value());
  reject(std::move(*hop), nexora::Error::FromProto(nexora::ProtoErrorCode::kHttp2ProtocolError));
  auto te = nexora::Request::Get("http://localhost/te");
  test::Check(te.has_value() && te->trailers.Set("te", "gzip").has_value());
  reject(std::move(*te), nexora::Error::FromProto(nexora::ProtoErrorCode::kHttp2ProtocolError));
  auto edged = nexora::Request::Get("http://localhost/edge");
  test::Check(edged.has_value() && edged->trailers.Set("x-meta", " padded").has_value());
  reject(std::move(*edged), nexora::Error::FromProto(nexora::ProtoErrorCode::kInvalidHeaderValue));
  auto pseudo = nexora::Request::Get("http://localhost/pseudo");
  test::Check(pseudo.has_value() && !pseudo->trailers.Set(":status", "200"));
  test::Check(service.pending[0]->Respond(nexora::Response::Ok("alive")).has_value());
  test::Drive(client, server);
  test::Check(sibling_ok && client.ActiveCount() == 0);
}

}  // namespace

int main() {
  Deferred service;
  nexora::HttpServer server(nexora::HttpService::Bind<&Deferred::Call>(service));
  nexora::HttpClient client;
  auto request = nexora::Request::Get("http://localhost/slow");
  test::Check(request.has_value());
  std::vector<unsigned> order;
  for (unsigned id = 0; id < 3; ++id) {
    test::Check(
        client
            .Submit(*request, nexora::ResponseCallback([&order, id](nexora::Result<nexora::Response> response) noexcept {
              test::Check(response.has_value());
              order.push_back(id);
            }))
            .has_value());
  }
  test::Drive(client, server, 7);
  test::Check(service.count == 3 && order.empty());
  test::Check(service.pending[2]->Respond(nexora::Response::Ok("third")).has_value());
  test::Check(service.pending[1]->Respond(nexora::Response::Ok("second")).has_value());
  test::Drive(client, server);
  test::Check(order.empty());
  test::Check(service.pending[0]->Respond(nexora::Response::Ok("first")).has_value());
  test::Drive(client, server);
  test::Check(order == std::vector<unsigned>({0, 1, 2}) && client.ActiveCount() == 0);

  {
    Deferred h2_service;
    nexora::HttpServer h2_server(nexora::HttpService::Bind<&Deferred::Call>(h2_service));
    nexora::HttpClient h2_client;
    test::Check(h2_client.UseHttp2().has_value());
    test::Drive(h2_client, h2_server);

    bool sibling_ok = false;
    auto live_req = nexora::Request::Get("http://localhost/live");
    test::Check(live_req.has_value());
    test::Check(h2_client
                    .Submit(*live_req, nexora::ResponseCallback([&](nexora::Result<nexora::Response> res) noexcept {
                      sibling_ok = res.has_value() && res->status.AsU16() == 200 && res->body.AsStringView() == "alive";
                    }))
                    .has_value());
    test::Drive(h2_client, h2_server);
    test::Check(h2_service.count == 1);

    // 1. Hop-by-hop header rejected locally before OpenStream().
    auto hop_req = nexora::Request::Get("http://localhost/hop");
    test::Check(hop_req.has_value() && hop_req->headers.Set("connection", "keep-alive").has_value());
    auto hop_sub = h2_client.Submit(*hop_req, nexora::ResponseCallback([](nexora::Result<nexora::Response>) noexcept {}));
    test::Check(!hop_sub && h2_client.PendingOutput().empty());

    // 2. Invalid HTTP/2 `te: gzip` header (only `te: trailers` is legal in HTTP/2) rejected locally before OpenStream().
    auto bad_te = nexora::Request::Get("http://localhost/te");
    test::Check(bad_te.has_value() && bad_te->headers.Set("te", "gzip").has_value());
    auto te_sub = h2_client.Submit(*bad_te, nexora::ResponseCallback([](nexora::Result<nexora::Response>) noexcept {}));
    test::Check(!te_sub && h2_client.PendingOutput().empty());

    // 3. Saturated client output buffer rejected locally with BufferOverflow without emitting RST_STREAM on idle stream.
    nexora::detail::HttpClientConnection raw_conn;
    test::Check(raw_conn.UseHttp2().has_value());
    test::Check(raw_conn.ConsumeOutput(raw_conn.PendingOutput().size()).has_value());
    // Fill output buffer via PING responses until < 64 bytes remain.
    auto peer = std::make_unique<nexora::Http2Connection>(nexora::Http2Role::kServer);
    std::array<std::uint8_t, 17> ping_frame{};
    constexpr std::array<std::uint8_t, 8> ping_payload{1, 2, 3, 4, 5, 6, 7, 8};
    const auto encoded_ping = nexora::EncodeFrame(nexora::Http2FrameType::kPing, 0, 0, ping_payload, ping_frame);
    test::Check(encoded_ping.has_value());
    test::Check(raw_conn.Feed(peer->PendingOutput()).has_value());
    test::Check(raw_conn.ConsumeOutput(raw_conn.PendingOutput().size()).has_value());
    for (int i = 0; i < 3860; ++i) {
      if (!raw_conn.Feed(ping_frame)) break;
    }
    const std::size_t before_overflow = raw_conn.PendingOutput().size();
    const auto far_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    auto full_sub = raw_conn.Submit(nexora::RequestId{99}, *live_req,
                                    nexora::ResponseCallback([](nexora::Result<nexora::Response>) noexcept {}), far_deadline);
    test::Check(!full_sub && raw_conn.PendingOutput().size() == before_overflow);

    // Live sibling stream still completes cleanly on h2_server!
    test::Check(h2_service.pending[0]->Respond(nexora::Response::Ok("alive")).has_value());
    test::Drive(h2_client, h2_server);
    test::Check(sibling_ok && h2_client.ActiveCount() == 0);
  }

  // Leftover bytes after a finished HTTP/1 response make the connection non-reusable.
  {
    nexora::detail::HttpClientConnection h1_conn;
    bool got_ok = false;
    auto req = nexora::Request::Get("http://localhost/item");
    test::Check(req.has_value());
    const auto far_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    test::Check(h1_conn
                    .Submit(nexora::RequestId{1}, *req,
                            nexora::ResponseCallback([&](nexora::Result<nexora::Response> res) noexcept {
                              got_ok = res.has_value() && res->body.AsStringView() == "ok";
                            }),
                            far_deadline)
                    .has_value());
    test::Check(h1_conn.ConsumeOutput(h1_conn.PendingOutput().size()).has_value());
    constexpr std::string_view wire = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokUNSOLICITED";
    test::Check(h1_conn.Feed(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(wire.data()), wire.size()))
                    .has_value());
    auto cbs = h1_conn.TakeCallbacks();
    while (cbs) {
      auto cur = std::move(cbs);
      cbs = std::move(cur->next);
      cur->callback(std::move(cur->response));
    }
    test::Check(got_ok && !h1_conn.Reusable());
  }

  // An over-limit HTTP/2 body resets only that stream.
  {
    Deferred dual_service;
    nexora::HttpServer dual_server(nexora::HttpService::Bind<&Deferred::Call>(dual_service));
    nexora::HttpClient limited_client(nexora::ClientConfig{.max_body_size = 32});
    test::Check(limited_client.UseHttp2().has_value());

    std::optional<nexora::Error> err1{};
    bool ok2 = false;
    auto r1 = nexora::Request::Get("http://localhost/oversized");
    auto r2 = nexora::Request::Get("http://localhost/small");
    test::Check(r1.has_value() && r2.has_value());
    test::Check(limited_client
                    .Submit(*r1, nexora::ResponseCallback([&](nexora::Result<nexora::Response> res) noexcept {
                      if (!res) err1 = res.error();
                    }))
                    .has_value());
    test::Check(limited_client
                    .Submit(*r2, nexora::ResponseCallback([&](nexora::Result<nexora::Response> res) noexcept {
                      ok2 = res.has_value() && res->body.AsStringView() == "tiny";
                    }))
                    .has_value());
    test::Drive(limited_client, dual_server);
    test::Check(dual_service.count == 2);
    test::Check(dual_service.pending[0]->Respond(nexora::Response::Ok(std::string(128, 'X'))).has_value());
    test::Check(dual_service.pending[1]->Respond(nexora::Response::Ok("tiny")).has_value());
    test::Drive(limited_client, dual_server);
    test::Check(err1.has_value() && *err1 == nexora::Error::BufferOverflow() && ok2);
  }

  QuarantineThenConnect();
  BadTrailersStayLocal();
}
