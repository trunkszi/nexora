#include "support.hpp"

namespace {

void TestLargeHttp2WindowReplenishment() noexcept {
  // A body past the 65,535-byte window needs repeated stream and connection WINDOW_UPDATE frames.
  constexpr std::size_t req_bytes = 1'200'000;
  constexpr std::size_t resp_bytes = 1'300'000;

  std::string expected_req(req_bytes, '\0');
  for (std::size_t i = 0; i < req_bytes; ++i) expected_req[i] = static_cast<char>('a' + (i % 26));
  std::string expected_resp(resp_bytes, '\0');
  for (std::size_t i = 0; i < resp_bytes; ++i) expected_resp[i] = static_cast<char>('A' + (i % 26));

  struct LargeHandler {
    const std::string* expected_req{nullptr};
    const std::string* expected_resp{nullptr};
    unsigned calls{0};
    nexora::Result<void> Call(nexora::RequestContext&, nexora::Request req, nexora::Responder responder) noexcept {
      ++calls;
      const auto owned = std::move(req);
      test::Check(owned.body.AsStringView() == *expected_req);
      return responder.Respond(nexora::Response::Ok(*expected_resp));
    }
  } handler{&expected_req, &expected_resp};

  nexora::HttpServer server(nexora::HttpService::Bind<&LargeHandler::Call>(handler),
                            nexora::ServerConfig{.max_body_size = 2 * 1024 * 1024});
  nexora::HttpClient client(nexora::ClientConfig{.max_body_size = 2 * 1024 * 1024, .max_request_body_size = 2 * 1024 * 1024});
  test::Check(client.UseHttp2().has_value());

  auto req = nexora::Request::Post("http://localhost/large", expected_req);
  test::Check(req.has_value());
  bool got_resp = false;
  test::Check(client
                  .Submit(std::move(*req), nexora::ResponseCallback([&](nexora::Result<nexora::Response> res) noexcept {
                            test::Check(res.has_value() && res->status.AsU16() == 200);
                            test::Check(res->body.AsStringView() == expected_resp);
                            got_resp = true;
                          }))
                  .has_value());

  for (unsigned step = 0; step < 8192 && !got_resp; ++step) {
    test::Check(server.Pump().has_value());
    const bool c2s = test::Transfer(client, server, 16384);
    const bool s2c = test::Transfer(server, client, 16384);
    test::Check(c2s || s2c || got_resp);
  }
  test::Check(got_resp && handler.calls == 1 && client.ActiveCount() == 0);
}

void TestSlowReaderConcurrentServerFlushReplies() noexcept {
  // 36 responses exceed the 64 KiB output buffer; FlushReplies must pause and resume.
  constexpr unsigned burst_count = 36;
  const std::string body(4096, 'R');
  struct BatchHandler {
    std::array<std::optional<nexora::Responder>, burst_count> responders{};
    unsigned seen{0};
    nexora::Result<void> Call(nexora::RequestContext&, nexora::Request req, nexora::Responder responder) noexcept {
      const auto owned = std::move(req);
      static_cast<void>(owned);
      responders[seen++].emplace(std::move(responder));
      return {};
    }
  } handler;

  nexora::HttpServer server(nexora::HttpService::Bind<&BatchHandler::Call>(handler));
  nexora::HttpClient client;
  test::Check(client.UseHttp2().has_value());
  test::Drive(client, server);

  unsigned completed = 0;
  auto req = nexora::Request::Get("http://localhost/burst");
  test::Check(req.has_value());
  for (unsigned i = 0; i < burst_count; ++i) {
    test::Check(client
                    .Submit(*req, nexora::ResponseCallback([&](nexora::Result<nexora::Response> res) noexcept {
                      test::Check(res.has_value() && res->status.AsU16() == 200 && res->body.AsStringView() == body);
                      ++completed;
                    }))
                    .has_value());
    test::Drive(client, server);
  }
  test::Check(handler.seen == burst_count);

  // Complete all 36 responses at once before reading a single byte from server!
  for (unsigned i = 0; i < burst_count; ++i) {
    test::Check(handler.responders[i]->Respond(nexora::Response::Ok(body)).has_value());
  }
  test::Check(server.Pump().has_value() && !server.PendingOutput().empty());

  for (unsigned step = 0; step < 4096 && completed < burst_count; ++step) {
    test::Check(server.Pump().has_value());
    const bool s2c = test::Transfer(server, client, 2048);
    const bool c2s = test::Transfer(client, server, 2048);
    test::Check(s2c || c2s || completed == burst_count);
  }
  test::Check(completed == burst_count && client.ActiveCount() == 0);
}

void TestBodyOmissionHttp1CloseAndGoawayFlush() noexcept {
  // HEAD, 204, and 304 responses omit DATA frames even when the handler fills response.body.
  struct SpecialService {
    unsigned calls{0};
    nexora::Result<void> Call(nexora::RequestContext&, nexora::Request req, nexora::Responder responder) noexcept {
      ++calls;
      const auto owned = std::move(req);
      const auto path = owned.uri.Path();
      if (path == "/204") {
        return responder.Respond(nexora::Response::WithStatus(nexora::StatusCode{204}, nexora::Bytes::CopyFromString("drop")));
      }
      if (path == "/304") {
        return responder.Respond(nexora::Response::WithStatus(nexora::StatusCode{304}, nexora::Bytes::CopyFromString("drop")));
      }
      if (path == "/close10") {
        auto resp = nexora::Response::Ok("bye10");
        resp.version = nexora::Version::kHttp10;
        return responder.Respond(std::move(resp));
      }
      if (path == "/close11") {
        auto resp = nexora::Response::Ok("bye11");
        test::Check(resp.headers.Set("connection", "close").has_value());
        return responder.Respond(std::move(resp));
      }
      return responder.Respond(nexora::Response::Ok("head-body"));
    }
  } service;

  nexora::HttpServer server(nexora::HttpService::Bind<&SpecialService::Call>(service));
  nexora::HttpClient client;
  test::Check(client.UseHttp2().has_value());
  test::Drive(client, server);

  unsigned done = 0;
  auto head_req = nexora::Request::Build(nexora::Method::kHead, "http://localhost/head");
  auto r204 = nexora::Request::Get("http://localhost/204");
  auto r304 = nexora::Request::Get("http://localhost/304");
  test::Check(head_req.has_value() && r204.has_value() && r304.has_value());
  for (auto* r : {&*head_req, &*r204, &*r304}) {
    test::Check(client
                    .Submit(*r, nexora::ResponseCallback([&](nexora::Result<nexora::Response> res) noexcept {
                      test::Check(res.has_value() && res->body.Empty());
                      ++done;
                    }))
                    .has_value());
  }
  test::Drive(client, server);
  test::Check(done == 3);

  // HTTP/1 server closes connection after handler responds with Connection: close or HTTP/1.0 without keep-alive.
  for (const auto* path : {"/close11", "/close10"}) {
    nexora::HttpServer h1_srv(nexora::HttpService::Bind<&SpecialService::Call>(service));
    nexora::HttpClient h1_cli;
    auto pipe = nexora::MemoryPipePair::Create();
    auto req = nexora::Request::Get(std::string("http://localhost") + path);
    test::Check(pipe.has_value() && req.has_value());
    auto res = h1_cli.ExchangeOverPipe(*req, pipe->client);
    test::Check(!res && res.error() == nexora::Error::Incomplete());
    auto served = h1_srv.ServeHttp1Once(pipe->server);
    test::Check(!served && served.error() == nexora::Error::FromRuntime(nexora::RuntimeErrorCode::kConnectionClosed));
    res = h1_cli.ExchangeOverPipe(*req, pipe->client);
    test::Check(res.has_value());
    auto after_close = h1_srv.ServeHttp1Once(pipe->server);
    test::Check(!after_close && after_close.error() == nexora::Error::FromRuntime(nexora::RuntimeErrorCode::kConnectionClosed));
  }

  // PeerFail on HTTP/2 flushes GOAWAY frame to the pipe before ServeHttp2Once returns the protocol error.
  {
    nexora::HttpServer goaway_srv(nexora::HttpService::Bind<&SpecialService::Call>(service));
    auto pipe = nexora::MemoryPipePair::Create();
    test::Check(pipe.has_value());
    // Send valid preface + an invalid SETTINGS ACK with non-empty payload to trigger PeerFail + GOAWAY!
    std::vector<std::uint8_t> bad_wire(nexora::kHttp2ClientPreface.begin(), nexora::kHttp2ClientPreface.end());
    std::array<std::uint8_t, 32> frame_buf{};
    constexpr std::array<std::uint8_t, 6> dummy_setting{0, 3, 0, 0, 0, 10};
    auto settings_frame = nexora::EncodeFrame(nexora::Http2FrameType::kSettings, 0, 0, {}, frame_buf);
    test::Check(settings_frame.has_value());
    bad_wire.insert(bad_wire.end(), frame_buf.begin(), frame_buf.begin() + static_cast<std::ptrdiff_t>(*settings_frame));
    auto bad_ack = nexora::EncodeFrame(nexora::Http2FrameType::kSettings, std::to_underlying(nexora::Http2FrameFlags::kAck), 0,
                                       dummy_setting, frame_buf);
    test::Check(bad_ack.has_value());
    bad_wire.insert(bad_wire.end(), frame_buf.begin(), frame_buf.begin() + static_cast<std::ptrdiff_t>(*bad_ack));
    test::Check(pipe->client.Write(bad_wire).has_value());
    auto failed = goaway_srv.ServeHttp2Once(pipe->server);
    test::Check(!failed);
    // Client side of pipe must contain server SETTINGS + GOAWAY frame!
    std::array<std::uint8_t, 512> rx{};
    auto read_n = pipe->client.ReadSome(rx);
    test::Check(read_n.has_value() && *read_n > 0);
    bool saw_goaway = false;
    std::span<const std::uint8_t> cursor{rx.data(), *read_n};
    while (cursor.size() >= nexora::kHttp2FrameHeaderSize) {
      auto decoded = nexora::DecodeFrame(cursor);
      if (!decoded) break;
      if (decoded->header.type == nexora::Http2FrameType::kGoaway) saw_goaway = true;
      cursor = cursor.subspan(nexora::kHttp2FrameHeaderSize + decoded->header.length);
    }
    test::Check(saw_goaway);
  }
}

void TestCoalescedPipelinedBurstExceedingEventRing() noexcept {
  // 50 pipelined HTTP/2 requests emit 100 server events (kHeaders + kMessageComplete) and 150 client events
  // (kHeaders + kData + kMessageComplete) in one coalesced buffer write, plus 100 pipelined DATA frames on a single
  // stream (>80-slot Http2Event ring).
  constexpr unsigned request_burst = 50;
  struct BurstService {
    unsigned calls{0};
    std::size_t last_body_size{0};
    nexora::Result<void> Call(nexora::RequestContext&, nexora::Request req, nexora::Responder responder) noexcept {
      ++calls;
      const auto owned = std::move(req);
      last_body_size = owned.body.Size();
      return responder.Respond(nexora::Response::Ok(owned.uri.PathAndQuery()));
    }
  } service;

  nexora::HttpServer server(nexora::HttpService::Bind<&BurstService::Call>(service));
  nexora::HttpClient client;
  test::Check(client.UseHttp2().has_value());
  test::Drive(client, server);

  unsigned completed = 0;
  for (unsigned i = 0; i < request_burst; ++i) {
    const std::string path = "/burst/" + std::to_string(i);
    auto req = nexora::Request::Get("http://localhost" + path);
    test::Check(req.has_value());
    test::Check(client
                    .Submit(std::move(*req), nexora::ResponseCallback([&, path](nexora::Result<nexora::Response> res) noexcept {
                              test::Check(res.has_value() && res->status.AsU16() == 200);
                              test::Check(res->body.AsStringView() == path);
                              ++completed;
                            }))
                    .has_value());
  }

  // Coalesce all 50 request HEADERS frames into ONE Pipe/Feed write (>80 server Http2Events), then coalesce all 50
  // server responses into ONE client Feed write (>80 client Http2Events).
  auto pipe = nexora::MemoryPipePair::Create();
  test::Check(pipe.has_value());
  const auto req_wire = client.PendingOutput();
  test::Check(!req_wire.empty());
  test::Check(pipe->client.WriteAll(req_wire, 1000).has_value());
  test::Check(client.ConsumeOutput(req_wire.size()).has_value());
  test::Check(server.ServeHttp2Once(pipe->server).has_value());
  test::Check(service.calls == request_burst);

  for (unsigned step = 0; step < 32 && completed < request_burst; ++step) {
    std::array<std::uint8_t, 65536> rx{};
    auto read_n = pipe->client.ReadSome(rx, 0);
    if (read_n && *read_n > 0) {
      test::Check(client.Feed(std::span<const std::uint8_t>(rx.data(), *read_n)).has_value());
    }
    const auto client_out = client.PendingOutput();
    if (!client_out.empty()) {
      test::Check(pipe->client.WriteAll(client_out, 1000).has_value());
      test::Check(client.ConsumeOutput(client_out.size()).has_value());
      if (auto step_res = server.ServeHttp2Once(pipe->server); !step_res)
        test::Check(step_res.error() == nexora::Error::Incomplete());
    }
  }
  test::Check(completed == request_burst && client.ActiveCount() == 0);

  // Also inject 96 pipelined HTTP/2 DATA frames on one stream in a single coalesced Feed chunk (>80 events).
  nexora::Http2Connection raw_client{nexora::Http2Role::kClient};
  nexora::HttpServer frame_server(nexora::HttpService::Bind<&BurstService::Call>(service));
  test::Check(raw_client.InitiateHandshake().has_value());
  {
    const auto hs = raw_client.PendingOutput();
    test::Check(frame_server.Feed(hs).has_value());
    raw_client.ConsumeOutput(hs.size());
    const auto srv_hs = frame_server.PendingOutput();
    test::Check(raw_client.FeedBytes(srv_hs).Ok());
    test::Check(frame_server.ConsumeOutput(srv_hs.size()).has_value());
    while (raw_client.PollEvent().has_value()) {
    }
    const auto ack = raw_client.PendingOutput();
    if (!ack.empty()) {
      test::Check(frame_server.Feed(ack).has_value());
      raw_client.ConsumeOutput(ack.size());
    }
  }
  const auto sid = raw_client.OpenStream();
  test::Check(sid.has_value());
  nexora::Headers<> empty_headers{};
  test::Check(
      raw_client.SubmitRequestHeaders(*sid, nexora::Method::kPost, "http", "localhost", "/frames96", empty_headers, false)
          .has_value());
  std::vector<std::uint8_t> coalesced(raw_client.PendingOutput().begin(), raw_client.PendingOutput().end());
  raw_client.ConsumeOutput(coalesced.size());
  constexpr unsigned data_frames = 96;
  std::array<std::uint8_t, 32> fbuf{};
  constexpr std::array<std::uint8_t, 4> chunk{'d', 'a', 't', 'a'};
  for (unsigned i = 0; i < data_frames; ++i) {
    const std::uint8_t flags = (i + 1 == data_frames) ? std::to_underlying(nexora::Http2FrameFlags::kEndStream) : 0U;
    const auto n = nexora::EncodeFrame(nexora::Http2FrameType::kData, flags, *sid, chunk, fbuf);
    test::Check(n.has_value());
    coalesced.insert(coalesced.end(), fbuf.begin(), fbuf.begin() + static_cast<std::ptrdiff_t>(*n));
  }
  const unsigned before_calls = service.calls;
  test::Check(frame_server.Feed(coalesced).has_value());
  test::Check(service.calls == before_calls + 1 && service.last_body_size == data_frames * chunk.size());
}

void TestPaddedHttp2DataWindowReplenishment() noexcept {
  // 300 padded DATA frames with 8-byte body + 240-byte padding consume 74,700 wire flow-control bytes (>65,535 initial
  // stream and connection windows) while carrying only 2,400 payload bytes (<32,767 half-window). Both HttpServer and
  // HttpClientConnection must replenish exact wire flow_control_bytes on stream 0 and the active stream.
  constexpr unsigned frames = 300;
  constexpr std::uint8_t pad_len = 240;
  constexpr std::size_t body_size = 8;
  constexpr std::array<std::uint8_t, body_size> body{'p', 'a', 'd', 'd', 'e', 'd', '!', '!'};
  constexpr std::size_t wire_per_frame = 1uz + body_size + pad_len;

  auto make_padded_payload = [&]() {
    std::array<std::uint8_t, wire_per_frame> payload{};
    payload[0] = pad_len;
    std::memcpy(payload.data() + 1, body.data(), body.size());
    return payload;
  };
  const auto padded_payload = make_padded_payload();

  // Part 1: Padded request DATA > 64 KiB into HttpServer.
  struct PadCheckService {
    std::size_t expected_size{0};
    unsigned calls{0};
    nexora::Result<void> Call(nexora::RequestContext&, nexora::Request req, nexora::Responder responder) noexcept {
      ++calls;
      const auto owned = std::move(req);
      test::Check(owned.body.Size() == expected_size);
      return responder.Respond(nexora::Response::Ok("padded-ok"));
    }
  } pad_service{frames * body_size};

  nexora::HttpServer server(nexora::HttpService::Bind<&PadCheckService::Call>(pad_service));
  nexora::Http2Connection raw_cli{nexora::Http2Role::kClient};
  test::Check(raw_cli.InitiateHandshake().has_value());
  {
    const auto hs = raw_cli.PendingOutput();
    test::Check(server.Feed(hs).has_value());
    raw_cli.ConsumeOutput(hs.size());
    const auto srv_hs = server.PendingOutput();
    test::Check(raw_cli.FeedBytes(srv_hs).Ok());
    test::Check(server.ConsumeOutput(srv_hs.size()).has_value());
    while (raw_cli.PollEvent().has_value()) {
    }
    const auto ack = raw_cli.PendingOutput();
    if (!ack.empty()) {
      test::Check(server.Feed(ack).has_value());
      raw_cli.ConsumeOutput(ack.size());
    }
  }
  const auto req_sid = raw_cli.OpenStream();
  test::Check(req_sid.has_value());
  nexora::Headers<> empty_headers{};
  test::Check(
      raw_cli.SubmitRequestHeaders(*req_sid, nexora::Method::kPost, "http", "localhost", "/padded", empty_headers, false)
          .has_value());
  {
    const auto hdr = raw_cli.PendingOutput();
    test::Check(server.Feed(hdr).has_value());
    raw_cli.ConsumeOutput(hdr.size());
  }

  std::uint64_t srv_conn_wu = 0;
  std::uint64_t srv_stream_wu = 0;
  for (unsigned i = 0; i < frames; ++i) {
    std::uint8_t flags = std::to_underlying(nexora::Http2FrameFlags::kPadded);
    if (i + 1 == frames) flags = static_cast<std::uint8_t>(flags | std::to_underlying(nexora::Http2FrameFlags::kEndStream));
    std::array<std::uint8_t, nexora::kHttp2FrameHeaderSize + wire_per_frame> wire{};
    const auto n = nexora::EncodeFrame(nexora::Http2FrameType::kData, flags, *req_sid, padded_payload, wire);
    test::Check(n.has_value());
    test::Check(server.Feed(std::span<const std::uint8_t>(wire.data(), *n)).has_value());
    const auto out = server.PendingOutput();
    if (!out.empty()) {
      std::span<const std::uint8_t> cur = out;
      while (cur.size() >= nexora::kHttp2FrameHeaderSize) {
        const auto dec = nexora::DecodeFrame(cur);
        if (!dec) break;
        if (dec->header.type == nexora::Http2FrameType::kWindowUpdate && dec->payload.size() == 4) {
          const auto inc = nexora::ReadU32(dec->payload) & 0x7fffffffU;
          if (dec->header.stream_id == 0)
            srv_conn_wu += inc;
          else if (dec->header.stream_id == *req_sid)
            srv_stream_wu += inc;
        }
        cur = cur.subspan(nexora::kHttp2FrameHeaderSize + dec->header.length);
      }
      test::Check(raw_cli.FeedBytes(out).Ok());
      while (raw_cli.PollEvent().has_value()) {
      }
      test::Check(server.ConsumeOutput(out.size()).has_value());
    }
  }
  test::Check(pad_service.calls == 1 && srv_conn_wu >= 65536 && srv_stream_wu >= 65536);

  // Part 2: Padded response DATA > 64 KiB into HttpClient.
  nexora::HttpClient client;
  test::Check(client.UseHttp2().has_value());
  nexora::Http2Connection raw_srv{nexora::Http2Role::kServer};
  test::Check(raw_srv.InitiateHandshake().has_value());
  auto get_req = nexora::Request::Get("http://localhost/padded-resp");
  test::Check(get_req.has_value());
  bool client_done = false;
  test::Check(client
                  .Submit(std::move(*get_req), nexora::ResponseCallback([&](nexora::Result<nexora::Response> res) noexcept {
                            test::Check(res.has_value() && res->status.AsU16() == 200);
                            test::Check(res->body.Size() == frames * body_size);
                            client_done = true;
                          }))
                  .has_value());
  {
    const auto cli_init = client.PendingOutput();
    test::Check(raw_srv.FeedBytes(cli_init).Ok());
    test::Check(client.ConsumeOutput(cli_init.size()).has_value());
    while (raw_srv.PollEvent().has_value()) {
    }
    const auto srv_init = raw_srv.PendingOutput();
    test::Check(client.Feed(srv_init).has_value());
    raw_srv.ConsumeOutput(srv_init.size());
    const auto cli_ack = client.PendingOutput();
    if (!cli_ack.empty()) {
      test::Check(raw_srv.FeedBytes(cli_ack).Ok());
      test::Check(client.ConsumeOutput(cli_ack.size()).has_value());
    }
  }
  test::Check(raw_srv.SubmitResponseHeaders(1, nexora::StatusCode{200}, empty_headers, false).has_value());
  {
    const auto resp_hdr = raw_srv.PendingOutput();
    test::Check(client.Feed(resp_hdr).has_value());
    raw_srv.ConsumeOutput(resp_hdr.size());
  }
  std::uint64_t cli_conn_wu = 0;
  std::uint64_t cli_stream_wu = 0;
  for (unsigned i = 0; i < frames; ++i) {
    std::uint8_t flags = std::to_underlying(nexora::Http2FrameFlags::kPadded);
    if (i + 1 == frames) flags = static_cast<std::uint8_t>(flags | std::to_underlying(nexora::Http2FrameFlags::kEndStream));
    std::array<std::uint8_t, nexora::kHttp2FrameHeaderSize + wire_per_frame> wire{};
    const auto n = nexora::EncodeFrame(nexora::Http2FrameType::kData, flags, 1, padded_payload, wire);
    test::Check(n.has_value());
    test::Check(client.Feed(std::span<const std::uint8_t>(wire.data(), *n)).has_value());
    const auto out = client.PendingOutput();
    if (!out.empty()) {
      std::span<const std::uint8_t> cur = out;
      while (cur.size() >= nexora::kHttp2FrameHeaderSize) {
        const auto dec = nexora::DecodeFrame(cur);
        if (!dec) break;
        if (dec->header.type == nexora::Http2FrameType::kWindowUpdate && dec->payload.size() == 4) {
          const auto inc = nexora::ReadU32(dec->payload) & 0x7fffffffU;
          if (dec->header.stream_id == 0)
            cli_conn_wu += inc;
          else if (dec->header.stream_id == 1)
            cli_stream_wu += inc;
        }
        cur = cur.subspan(nexora::kHttp2FrameHeaderSize + dec->header.length);
      }
      test::Check(client.ConsumeOutput(out.size()).has_value());
    }
  }
  test::Check(client_done && cli_conn_wu >= 65536 && cli_stream_wu >= 65536);
}

}  // namespace

int main() {
  test::EchoService service;
  nexora::HttpServer server(nexora::HttpService::Bind<&test::EchoService::Call>(service));
  nexora::HttpClient client;
  auto pipe = nexora::MemoryPipePair::Create();
  auto request = nexora::Request::Get("http://localhost/echo");
  test::Check(pipe.has_value() && request.has_value());
  for (unsigned exchange = 0; exchange < 3; ++exchange) {
    auto response = client.ExchangeOverPipe(*request, pipe->client);
    test::Check(!response && response.error() == nexora::Error::Incomplete());
    test::Check(server.ServeHttp1Once(pipe->server).has_value());
    response = client.ExchangeOverPipe(*request, pipe->client);
    test::Check(response.has_value() && response->body.AsStringView() == "hello");
  }
  nexora::HttpServer h2_server(nexora::HttpService::Bind<&test::EchoService::Call>(service));
  nexora::HttpClient h2_client;
  auto h2_pipe = nexora::MemoryPipePair::Create();
  test::Check(h2_pipe.has_value());
  auto response = h2_client.ExchangeH2OverPipe(*request, h2_pipe->client);
  for (unsigned step = 0; !response && response.error() == nexora::Error::Incomplete() && step < 20; ++step) {
    auto served = h2_server.ServeHttp2Once(h2_pipe->server);
    test::Check(served.has_value() || served.error() == nexora::Error::Incomplete());
    response = h2_client.ExchangeH2OverPipe(*request, h2_pipe->client);
  }
  test::Check(response.has_value() && response->version == nexora::Version::kHttp2 && response->body.AsStringView() == "hello");

  TestLargeHttp2WindowReplenishment();
  TestSlowReaderConcurrentServerFlushReplies();
  TestBodyOmissionHttp1CloseAndGoawayFlush();
  TestCoalescedPipelinedBurstExceedingEventRing();
  TestPaddedHttp2DataWindowReplenishment();
}
