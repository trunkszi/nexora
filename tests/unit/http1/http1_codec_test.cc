#include <array>
#include <cstdio>
#include <cstring>
#include <nexora/http1/http1_codec.hpp>
#include <nexora/websocket/handshake.hpp>
#include <string_view>
#include <utility>

namespace {

int g_fails = 0;

void Check(bool ok, const char* message) {
  if (!ok) {
    std::fprintf(stderr, "FAIL %s\n", message);
    ++g_fails;
  }
}

bool Eq(std::span<const std::uint8_t> bytes, std::string_view text) {
  return bytes.size() == text.size() && (text.empty() || std::memcmp(bytes.data(), text.data(), text.size()) == 0);
}

bool Proto(const nexora::Error& err, nexora::ProtoErrorCode code) {
  return err.domain == nexora::ErrorDomain::kProto && err.code == static_cast<std::int32_t>(std::to_underlying(code));
}

void TestRoundTrip() {
  auto built = nexora::Request::Post("http://example.com/v1", "hi");
  Check(built.has_value(), "build post");
  if (!built.has_value()) {
    return;
  }
  nexora::Http1ClientCodec<> client;
  auto wire = client.EncodeRequest(*built);
  Check(wire.has_value(), "encode post");
  if (!wire.has_value()) {
    return;
  }
  nexora::Http1ServerCodec<> server;
  auto request = server.DecodeRequest(wire->ReadableSpan());
  Check(request.has_value() && request->has_value(), "decode post");
  if (!(request.has_value() && request->has_value())) {
    return;
  }
  Check((*request)->message.method == nexora::Method::kPost, "post method");
  Check((*request)->message.uri.Path() == "/v1", "post path");
  Check(Eq((*request)->message.body.Span(), "hi"), "post body");
  Check((*request)->keep_alive == nexora::Http1KeepAlive::kKeepAlive, "post keep");
  auto response = nexora::Response::Ok("ok");
  auto down = server.EncodeResponse(response);
  Check(down.has_value(), "encode ok");
  if (!down.has_value()) {
    return;
  }
  auto decoded = client.DecodeResponse(down->ReadableSpan(), nexora::Method::kPost);
  Check(decoded.has_value() && decoded->has_value(), "decode ok");
  if (decoded.has_value() && decoded->has_value()) {
    Check(Eq((*decoded)->message.body.Span(), "ok"), "ok body");
    Check((*decoded)->keep_alive == nexora::Http1KeepAlive::kKeepAlive, "ok keep");
  }
}

void TestChunkedAndClose() {
  auto built = nexora::Request::Get("http://example.com/");
  Check(built.has_value(), "get");
  if (!built.has_value()) {
    return;
  }
  Check(built->SetHeader("transfer-encoding", "chunked").has_value(), "set chunked");
  Check(built->SetHeader("connection", "close").has_value(), "set close");
  built->body = nexora::Bytes::CopyFromString("xy");
  nexora::Http1ClientCodec<> client;
  auto wire = client.EncodeRequest(*built);
  Check(wire.has_value(), "encode chunked");
  Check(client.EncodeClosed(), "close request closes encode");
  if (!wire.has_value()) {
    return;
  }
  Check(wire->AsStringView().find("2\r\nxy\r\n0\r\n\r\n") != std::string_view::npos, "chunk framing");
  nexora::Http1ServerCodec<> server;
  auto request = server.DecodeRequest(wire->ReadableSpan());
  Check(request.has_value() && request->has_value(), "decode chunked");
  if (request.has_value() && request->has_value()) {
    Check(Eq((*request)->message.body.Span(), "xy"), "chunked body");
    Check((*request)->keep_alive == nexora::Http1KeepAlive::kClose, "request close");
    Check(server.DecodeClosed(), "server decode closed");
  }
  nexora::Response interim(nexora::StatusCode{100});
  auto interim_wire = server.EncodeResponse(interim);
  Check(interim_wire.has_value(), "100 after close request");
  Check(!server.EncodeClosed(), "100 leaves encode open");
  auto final_response = nexora::Response::Ok("");
  Check(final_response.SetHeader("connection", "close").has_value(), "response close");
  auto final_wire = server.EncodeResponse(final_response);
  Check(final_wire.has_value(), "final after 100");
  Check(server.EncodeClosed(), "final closes encode");
  Check(!server.EncodeResponse(final_response).has_value(), "second final rejected");
}

void TestHeadAndEmpty() {
  constexpr std::string_view head = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n";
  nexora::BytesMut<1024> buf;
  Check(buf.AppendString(head).has_value(), "head wire");
  nexora::Http1ClientCodec<> client;
  auto decoded = client.DecodeResponse(buf.ReadableSpan(), nexora::Method::kHead);
  Check(decoded.has_value() && decoded->has_value() && (*decoded)->message.body.Empty(), "head bodyless");
  if (decoded.has_value() && decoded->has_value()) {
    Check((*decoded)->consumed == head.size(), "head consumed headers only");
  }
}

void TestHeadEncode() {
  nexora::Http1ServerCodec<> server;
  auto response = nexora::Response::Ok("abcd");
  auto wire = server.EncodeResponse(response, nexora::Method::kHead);
  Check(wire.has_value(), "encode head");
  if (!wire.has_value()) {
    return;
  }
  const auto text = wire->AsStringView();
  Check(text.find("content-length: 4") != std::string_view::npos, "head keeps length");
  Check(text.find("abcd") == std::string_view::npos, "head suppresses body");
  Check(text.ends_with("\r\n\r\n"), "head ends at header");
}

void TestHtabValue() {
  constexpr std::string_view wire = "HTTP/1.1 200 OK\r\nX-Note: a\tb\r\nContent-Length: 0\r\n\r\n";
  nexora::BytesMut<1024> buf;
  Check(buf.AppendString(wire).has_value(), "htab wire");
  nexora::Http1ClientCodec<> client;
  auto decoded = client.DecodeResponse(buf.ReadableSpan(), nexora::Method::kGet);
  Check(decoded.has_value() && decoded->has_value(), "htab decode");
  if (decoded.has_value() && decoded->has_value()) {
    const auto note = (*decoded)->message.headers.Get("x-note");
    Check(note.has_value() && *note == "a\tb", "htab value");
  }
}

nexora::BytesMut<1024> Wire204() {
  nexora::BytesMut<1024> buf;
  Check(buf.AppendString("HTTP/1.1 204 No Content\r\n\r\n").has_value(), "204 wire");
  return buf;
}

void Test204() {
  auto buf = Wire204();
  nexora::Http1ClientCodec<> client;
  auto decoded = client.DecodeResponse(buf.ReadableSpan(), nexora::Method::kGet);
  Check(decoded.has_value() && decoded->has_value() && (*decoded)->message.body.Empty(), "204 empty");
}

void TestIncompleteAndLimit() {
  nexora::BytesMut<1024> buf;
  Check(buf.AppendString("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHi").has_value(), "short");
  const auto before = buf.Size();
  nexora::Http1ClientCodec<> client;
  auto decoded = client.DecodeResponse(buf.ReadableSpan(), nexora::Method::kGet);
  Check(decoded.has_value() && !decoded->has_value(), "incomplete");
  Check(buf.Size() == before, "incomplete unchanged");
  nexora::BytesMut<16> rest;
  Check(rest.AppendString("!!!").has_value(), "rest");
  auto done = client.DecodeResponse(rest.ReadableSpan(), nexora::Method::kGet);
  Check(done.has_value() && done->has_value() && Eq((*done)->message.body.Span(), "Hi!!!"), "incomplete completes");
  client.Reset();
  nexora::BytesMut<128> huge;
  Check(huge.AppendString("HTTP/1.1 200 OK\r\nContent-Length: 20000\r\n\r\n").has_value(), "huge");
  auto overflow = client.DecodeResponse(huge.ReadableSpan(), nexora::Method::kGet);
  Check(!overflow.has_value() && Proto(overflow.error(), nexora::ProtoErrorCode::kHttp1MessageTooLarge), "body limit");
}

void TestOptionsAndConnect() {
  auto options = nexora::Request::Build(nexora::Method::kOptions, "http://example.com/*");
  Check(options.has_value(), "options");
  if (!options.has_value()) {
    return;
  }
  nexora::Http1ClientCodec<> client;
  auto wire = client.EncodeRequest(*options);
  Check(wire.has_value(), "encode options");
  if (!wire.has_value()) {
    return;
  }
  Check(wire->AsStringView().starts_with("OPTIONS * HTTP/1.1\r\n"), "options star");
  nexora::Http1ServerCodec<> server;
  auto decoded = server.DecodeRequest(wire->ReadableSpan());
  Check(decoded.has_value() && decoded->has_value() && (*decoded)->message.uri.Path() == "/*", "options path");
  auto connect = nexora::Request::Build(nexora::Method::kConnect, "http://example.com:443/");
  Check(connect.has_value(), "connect");
  if (!connect.has_value()) {
    return;
  }
  auto tunnel = client.EncodeRequest(*connect);
  Check(tunnel.has_value(), "encode connect");
  if (tunnel.has_value()) {
    Check(tunnel->AsStringView().starts_with("CONNECT example.com:443 HTTP/1.1\r\n"), "connect target");
  }
}

void TestUpgradeHandoff() {
  constexpr std::string_view key = "dGhlIHNhbXBsZSBub25jZQ==";
  auto uri = nexora::Uri::Parse("http://example.com/chat");
  Check(uri.has_value(), "chat uri");
  if (!uri.has_value()) {
    return;
  }
  auto request = nexora::WebSocketHandshake::BuildUpgradeRequest(*uri, key);
  Check(request.has_value(), "upgrade request");
  if (!request.has_value()) {
    return;
  }
  auto validated = nexora::WebSocketHandshake::ValidateUpgradeRequest(*request);
  Check(validated.has_value() && validated->View() == key, "validate request");
  if (!validated.has_value()) {
    return;
  }
  nexora::Http1ClientCodec<> client;
  auto up = client.EncodeRequest(*request);
  Check(up.has_value(), "encode upgrade");
  if (!up.has_value()) {
    return;
  }
  nexora::Http1ServerCodec<> server;
  auto decoded = server.DecodeRequest(up->ReadableSpan());
  Check(decoded.has_value() && decoded->has_value(), "decode upgrade");
  if (!(decoded.has_value() && decoded->has_value())) {
    return;
  }
  Check((*decoded)->keep_alive == nexora::Http1KeepAlive::kUpgrade, "upgrade keep");
  Check((*decoded)->message.body.Empty(), "upgrade bodyless");
  auto response = nexora::WebSocketHandshake::BuildUpgradeResponse(validated->View());
  Check(response.has_value(), "101 response");
  if (!response.has_value()) {
    return;
  }
  auto down = server.EncodeResponse(*response);
  Check(down.has_value(), "encode 101");
  if (!down.has_value()) {
    return;
  }
  constexpr std::array<std::uint8_t, 7> frame{0x81, 0x05, 'H', 'e', 'l', 'l', 'o'};
  Check(down->Append(frame).has_value(), "append frame");
  auto back = client.DecodeResponse(down->ReadableSpan(), nexora::Method::kGet);
  Check(back.has_value() && back->has_value() && (*back)->keep_alive == nexora::Http1KeepAlive::kUpgrade, "decode 101");
  if (back.has_value() && back->has_value()) {
    Check(Eq(down->ReadableSpan().subspan((*back)->consumed), std::string_view("\x81\x05Hello", 7)), "coalesced frame");
  }
}

}  // namespace

void TestPipelinedClose() {
  auto first = nexora::Request::Get("http://example.com/a");
  auto second = nexora::Request::Get("http://example.com/b");
  Check(first.has_value() && second.has_value(), "pipeline build");
  if (!first.has_value() || !second.has_value()) {
    return;
  }
  Check(second->SetHeader("connection", "close").has_value(), "pipeline close");
  nexora::Http1ClientCodec<> client;
  auto encoded_a = client.EncodeRequest(*first);
  auto encoded_b = client.EncodeRequest(*second);
  Check(encoded_a.has_value() && encoded_b.has_value(), "pipeline encode");
  if (!encoded_a.has_value() || !encoded_b.has_value()) {
    return;
  }
  Check(encoded_a->Append(encoded_b->ReadableSpan()).has_value(), "pipeline join");
  nexora::Http1ServerCodec<> server;
  auto decoded_a = server.DecodeRequest(encoded_a->ReadableSpan());
  Check(decoded_a.has_value() && decoded_a->has_value(), "pipeline request a");
  if (!(decoded_a.has_value() && decoded_a->has_value())) {
    return;
  }
  Check((*decoded_a)->keep_alive == nexora::Http1KeepAlive::kKeepAlive, "request a keep");
  auto decoded_b = server.DecodeRequest(encoded_a->ReadableSpan().subspan((*decoded_a)->consumed));
  Check(decoded_b.has_value() && decoded_b->has_value(), "pipeline request b");
  if (!(decoded_b.has_value() && decoded_b->has_value())) {
    return;
  }
  Check((*decoded_b)->keep_alive == nexora::Http1KeepAlive::kClose, "request b close");
  Check(server.DecodeClosed(), "decode closed after b");
  Check(!server.EncodeClosed(), "encode still open");
  auto response_a = nexora::Response::Ok("A");
  auto wire_a = server.EncodeResponse(response_a);
  Check(wire_a.has_value(), "encode response a");
  Check(!server.EncodeClosed(), "keep-alive response stays open");
  auto response_b = nexora::Response::Ok("B");
  auto wire_b = server.EncodeResponse(response_b);
  Check(wire_b.has_value(), "encode response b");
}

int main() {
  TestRoundTrip();
  TestChunkedAndClose();
  Test204();
  TestIncompleteAndLimit();
  TestOptionsAndConnect();
  TestUpgradeHandoff();
  TestHeadAndEmpty();
  TestHeadEncode();
  TestHtabValue();
  TestPipelinedClose();
  return g_fails == 0 ? 0 : 1;
}
