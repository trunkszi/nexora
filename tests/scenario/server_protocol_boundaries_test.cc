#include "../integration/support.hpp"

namespace {

struct Service {
  unsigned calls{0};
  std::string target;
  std::string path;
  std::string uri_host;
  nexora::Result<void> Call(nexora::RequestContext& context, nexora::Request request, nexora::Responder responder) noexcept {
    ++calls;
    const auto owned = std::move(request);
    target = context.target;
    path = owned.uri.Path();
    uri_host = owned.uri.Host();
    return responder.Respond(nexora::Response::Ok("ok"));
  }
};

void AppendHpackLiteral(std::vector<std::uint8_t>& block, std::string_view name, std::string_view value) {
  block.push_back(0x00);
  test::Check(name.size() < 127 && value.size() < 127);
  block.push_back(static_cast<std::uint8_t>(name.size()));
  block.insert(block.end(), reinterpret_cast<const std::uint8_t*>(name.data()),
               reinterpret_cast<const std::uint8_t*>(name.data()) + name.size());
  block.push_back(static_cast<std::uint8_t>(value.size()));
  block.insert(block.end(), reinterpret_cast<const std::uint8_t*>(value.data()),
               reinterpret_cast<const std::uint8_t*>(value.data()) + value.size());
}

std::vector<std::uint8_t> BuildRawHeadersFrame(std::uint32_t stream_id,
                                               std::span<const std::pair<std::string_view, std::string_view>> fields,
                                               bool end_stream = true) {
  std::vector<std::uint8_t> hpack{};
  for (const auto& [k, v] : fields) AppendHpackLiteral(hpack, k, v);
  std::vector<std::uint8_t> out(nexora::kHttp2FrameHeaderSize + hpack.size());
  const auto flags = static_cast<std::uint8_t>(std::to_underlying(nexora::Http2FrameFlags::kEndHeaders) |
                                               (end_stream ? std::to_underlying(nexora::Http2FrameFlags::kEndStream) : 0U));
  const auto n = nexora::EncodeFrame(nexora::Http2FrameType::kHeaders, flags, stream_id, hpack, out);
  test::Check(n.has_value() && *n == out.size());
  return out;
}

std::vector<std::uint8_t> ClientPrefaceAndSettings() {
  std::vector<std::uint8_t> wire(nexora::kHttp2ClientPreface.begin(), nexora::kHttp2ClientPreface.end());
  std::array<std::uint8_t, 16> settings{};
  const auto n = nexora::EncodeFrame(nexora::Http2FrameType::kSettings, 0, 0, {}, settings);
  test::Check(n.has_value());
  wire.insert(wire.end(), settings.begin(), settings.begin() + static_cast<std::ptrdiff_t>(*n));
  return wire;
}

bool OutputHasRstStream(std::span<const std::uint8_t> bytes, std::uint32_t expected_stream, nexora::Http2ErrorCode code) {
  while (bytes.size() >= nexora::kHttp2FrameHeaderSize) {
    auto frame = nexora::DecodeFrame(bytes);
    if (!frame) return false;
    if (frame->header.type == nexora::Http2FrameType::kRstStream && frame->header.stream_id == expected_stream &&
        frame->payload.size() == 4 && nexora::Http2ErrorCodeFromU32(nexora::ReadU32(frame->payload)) == code) {
      return true;
    }
    bytes = bytes.subspan(nexora::kHttp2FrameHeaderSize + frame->header.length);
  }
  return false;
}

void RawRequestRejectedPerStream(std::span<const std::pair<std::string_view, std::string_view>> bad_fields) {
  Service service;
  nexora::HttpServer server(nexora::HttpService::Bind<&Service::Call>(service));
  auto wire = ClientPrefaceAndSettings();
  const auto bad_headers = BuildRawHeadersFrame(1, bad_fields, true);
  wire.insert(wire.end(), bad_headers.begin(), bad_headers.end());

  // Malformed pseudo-header/authority on stream 1 is isolated via RST_STREAM(kProtocolError) without calling service
  // AND without killing sibling stream 3 on the same connection!
  const auto fed = server.Feed(wire);
  test::Check(fed.has_value() && service.calls == 0);
  test::Check(OutputHasRstStream(server.PendingOutput(), 1, nexora::Http2ErrorCode::kProtocolError));
  test::Check(server.ConsumeOutput(server.PendingOutput().size()).has_value());

  const std::array<std::pair<std::string_view, std::string_view>, 4> valid_fields{{
      {":method", "GET"},
      {":scheme", "https"},
      {":authority", "localhost"},
      {":path", "/healthy"},
  }};
  const auto good_headers = BuildRawHeadersFrame(3, valid_fields, true);
  test::Check(server.Feed(good_headers).has_value());
  test::Check(service.calls == 1 && service.path == "/healthy");
}

void AuthorityRejected(std::string_view authority) {
  const std::array<std::pair<std::string_view, std::string_view>, 4> fields{{
      {":method", "GET"},
      {":scheme", "https"},
      {":authority", authority},
      {":path", "/admin"},
  }};
  RawRequestRejectedPerStream(fields);
}

void PseudoRejected(std::string_view scheme, std::string_view authority, std::string_view path) {
  const std::array<std::pair<std::string_view, std::string_view>, 4> fields{{
      {":method", "GET"},
      {":scheme", scheme},
      {":authority", authority},
      {":path", path},
  }};
  RawRequestRejectedPerStream(fields);
}

void HostHeaderFallbackAndMismatch() {
  // RFC 9113 §8.3.1: HTTP/2 request with valid `host` and absent `:authority` succeeds!
  {
    Service service;
    nexora::HttpServer server(nexora::HttpService::Bind<&Service::Call>(service));
    auto wire = ClientPrefaceAndSettings();
    const std::array<std::pair<std::string_view, std::string_view>, 4> host_only{{
        {":method", "GET"},
        {":scheme", "https"},
        {":path", "/via-host"},
        {"host", "example.internal:8443"},
    }};
    const auto frame = BuildRawHeadersFrame(1, host_only, true);
    wire.insert(wire.end(), frame.begin(), frame.end());
    test::Check(server.Feed(wire).has_value());
    test::Check(service.calls == 1 && service.uri_host == "example.internal" && service.path == "/via-host");
  }

  // Mismatched `:authority` vs `host` is rejected per-stream with RST_STREAM(kProtocolError).
  {
    const std::array<std::pair<std::string_view, std::string_view>, 5> mismatched{{
        {":method", "GET"},
        {":scheme", "https"},
        {":authority", "a.example"},
        {":path", "/conflict"},
        {"host", "b.example"},
    }};
    RawRequestRejectedPerStream(mismatched);
  }
}

void MaxInflightAndBadHandlerHeaderIsolation() {
  // 1. max_inflight = 1 resets excess concurrent stream 3 with REFUSED_STREAM while stream 1 completes 200 OK.
  {
    struct HoldService {
      std::optional<nexora::Responder> held{};
      unsigned calls{0};
      nexora::Result<void> Call(nexora::RequestContext&, nexora::Request req, nexora::Responder responder) noexcept {
        ++calls;
        const auto owned = std::move(req);
        static_cast<void>(owned);
        held.emplace(std::move(responder));
        return {};
      }
    } hold;
    nexora::HttpServer server(nexora::HttpService::Bind<&HoldService::Call>(hold), nexora::ServerConfig{.max_inflight = 1});
    auto wire = ClientPrefaceAndSettings();
    const std::array<std::pair<std::string_view, std::string_view>, 4> f1{{
        {":method", "POST"},
        {":scheme", "https"},
        {":authority", "localhost"},
        {":path", "/hold"},
    }};
    // Open stream 1 without end_stream so it occupies the single inflight slot.
    const auto s1 = BuildRawHeadersFrame(1, f1, false);
    const auto s3 = BuildRawHeadersFrame(3, f1, true);
    wire.insert(wire.end(), s1.begin(), s1.end());
    wire.insert(wire.end(), s3.begin(), s3.end());
    test::Check(server.Feed(wire).has_value());
    test::Check(OutputHasRstStream(server.PendingOutput(), 3, nexora::Http2ErrorCode::kRefusedStream));
    test::Check(server.ConsumeOutput(server.PendingOutput().size()).has_value());

    // Finish stream 1 with empty DATA(END_STREAM) -> dispatches and responds cleanly!
    std::array<std::uint8_t, 9> end_data{};
    test::Check(nexora::EncodeFrame(nexora::Http2FrameType::kData, std::to_underlying(nexora::Http2FrameFlags::kEndStream), 1,
                                    {}, end_data)
                    .has_value());
    test::Check(server.Feed(end_data).has_value() && hold.calls == 1);
    test::Check(hold.held->Respond(nexora::Response::Ok("done")).has_value());
    test::Check(server.Pump().has_value() && !server.PendingOutput().empty());
  }

  // 2. Handler setting hop-by-hop response header (`connection: close`) on HTTP/2 resets only that stream (kInternalError).
  {
    struct BadHeaderService {
      unsigned calls{0};
      nexora::Result<void> Call(nexora::RequestContext&, nexora::Request req, nexora::Responder responder) noexcept {
        ++calls;
        const auto owned = std::move(req);
        auto resp = nexora::Response::Ok("ok");
        if (owned.uri.Path() == "/bad-resp") {
          test::Check(resp.headers.Set("connection", "close").has_value());
        }
        return responder.Respond(std::move(resp));
      }
    } svc;
    nexora::HttpServer server(nexora::HttpService::Bind<&BadHeaderService::Call>(svc));
    nexora::HttpClient client;
    test::Check(client.UseHttp2().has_value());
    bool failed1 = false;
    bool ok2 = false;
    auto r1 = nexora::Request::Get("http://localhost/bad-resp");
    auto r2 = nexora::Request::Get("http://localhost/good-resp");
    test::Check(r1.has_value() && r2.has_value());
    test::Check(client
                    .Submit(*r1, nexora::ResponseCallback(
                                     [&](nexora::Result<nexora::Response> res) noexcept { failed1 = !res.has_value(); }))
                    .has_value());
    test::Check(client
                    .Submit(*r2, nexora::ResponseCallback([&](nexora::Result<nexora::Response> res) noexcept {
                      ok2 = res.has_value() && res->status.AsU16() == 200;
                    }))
                    .has_value());
    test::Drive(client, server);
    test::Check(failed1 && ok2);
  }
}

void OptionsAsteriskPreserved() {
  Service service;
  nexora::HttpServer server(nexora::HttpService::Bind<&Service::Call>(service));
  auto client = std::make_unique<nexora::Http2Connection>(nexora::Http2Role::kClient);
  test::Check(client->InitiateHandshake().has_value());
  const auto stream = client->OpenStream();
  test::Check(stream.has_value());
  test::Check(client->SubmitRequestHeaders(*stream, nexora::Method::kOptions, "https", "localhost", "*", {}, true).has_value());
  test::Check(server.Feed(client->PendingOutput()).has_value());
  test::Check(service.calls == 1 && service.target == "*" && service.path == "/");
}
void InvalidUpgradeLeavesNoSession() {
  nexora::HttpServer server;
  constexpr std::string_view request =
      "GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
      "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: invalid\r\n\r\n";
  const auto result = server.Feed(std::span(reinterpret_cast<const std::uint8_t*>(request.data()), request.size()));
  test::Check(!result && server.WebSocket() == nullptr);
}
void AlpnPolicy() {
  nexora::HttpServer disabled({}, nexora::ServerConfig{.allow_http2 = false});
  auto selected = disabled.SetNegotiatedAlpn(nexora::AlpnProtocol::kHttp2);
  test::Check(!selected && selected.error() == nexora::Error::FromProto(nexora::ProtoErrorCode::kHttp2ProtocolError));
  Service service;
  nexora::HttpServer http1(nexora::HttpService::Bind<&Service::Call>(service));
  test::Check(http1.SetNegotiatedAlpn(nexora::AlpnProtocol::kHttp11).has_value());
  auto client = std::make_unique<nexora::Http2Connection>(nexora::Http2Role::kClient);
  test::Check(client->InitiateHandshake().has_value());
  test::Check(!http1.Feed(client->PendingOutput()) && service.calls == 0);
}

}  // namespace

int main() {
  AlpnPolicy();
  for (const auto authority : {"a/health?", "a#", "user@host", "a\\b", "a b"}) AuthorityRejected(authority);
  PseudoRejected("ftp", "localhost", "/admin");
  PseudoRejected("https", "", "/admin");
  PseudoRejected("https", "localhost", "admin");
  PseudoRejected("https", "localhost", "/a#b");
  PseudoRejected("https", "localhost", "/a\tb");
  PseudoRejected("https", "localhost", "/a\x01b");
  PseudoRejected("https", "localhost", "/a\x80");
  HostHeaderFallbackAndMismatch();
  MaxInflightAndBadHandlerHeaderIsolation();
  OptionsAsteriskPreserved();
  InvalidUpgradeLeavesNoSession();
}
