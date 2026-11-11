// clang-format off
#include <nexora/websocket/utf8.hpp>
// clang-format on
#include <array>
#include <cstdio>
#include <cstring>
#include <nexora/websocket/codec.hpp>
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

void TestUtf8Header() {
  constexpr std::array<std::uint8_t, 2> ascii{'A', 'B'};
  const auto cut = nexora::ws_detail::ClassifyUtf8(ascii);
  Check(cut.ok, "ascii classify");
  const auto fed = nexora::ws_detail::FeedUtf8({}, ascii, true);
  Check(fed.ok && fed.len == 0, "ascii feed");
}

void TestAcceptVector() {
  constexpr std::string_view key = "dGhlIHNhbXBsZSBub25jZQ==";
  auto accept = nexora::WebSocketHandshake::ComputeAcceptKey(key);
  Check(accept.has_value() && accept->View() == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "rfc accept");
  auto alias = nexora::WebSocketHandshake::ComputeAccept(key);
  Check(alias.has_value() && accept.has_value() && alias->View() == accept->View(), "accept alias");
  auto again = nexora::WebSocketHandshake::GenerateKey(0x1122334455667788ULL);
  auto same = nexora::WebSocketHandshake::GenerateKey(0x1122334455667788ULL);
  Check(again.has_value() && same.has_value() && again->View() == same->View(), "stable key");
  Check(again.has_value() && again->View().size() == 24, "key width");
}

void TestHandshake() {
  constexpr std::string_view client_key = "dGhlIHNhbXBsZSBub25jZQ==";
  auto uri = nexora::Uri::Parse("http://example.com/chat");
  Check(uri.has_value(), "uri");
  if (!uri.has_value()) {
    return;
  }
  nexora::Headers<> extra;
  Check(extra.Add("x-trace", "1").has_value(), "extra");
  Check(extra.Add("sec-websocket-protocol", "chat").has_value(), "offer");
  auto request = nexora::WebSocketHandshake::BuildUpgradeRequest(*uri, client_key, extra);
  Check(request.has_value(), "build request");
  if (!request.has_value()) {
    return;
  }
  Check(request->headers.Get("x-trace").has_value(), "kept extra");
  Check(request->headers.Contains("sec-websocket-protocol"), "kept offer");
  auto key = nexora::WebSocketHandshake::ValidateUpgradeRequest(*request);
  Check(key.has_value() && key->View() == client_key, "validate request");
  if (!key.has_value()) {
    return;
  }
  auto response = nexora::WebSocketHandshake::BuildUpgradeResponse(key->View());
  Check(response.has_value(), "build response");
  if (!response.has_value()) {
    return;
  }
  Check(nexora::WebSocketHandshake::ValidateUpgradeResponse(*response, client_key).has_value(), "validate response");
  Check(response->SetHeader("sec-websocket-extensions", "permessage-deflate").has_value(), "ext");
  Check(!nexora::WebSocketHandshake::ValidateUpgradeResponse(*response, client_key).has_value(), "reject extension");
  Check(response->headers.Remove("sec-websocket-extensions").has_value(), "clear ext");
  nexora::Headers<> offer;
  Check(offer.Add("sec-websocket-protocol", "chat, superchat").has_value(), "protocols");
  Check(offer.Add("sec-websocket-extensions", "permessage-deflate; client_max_window_bits").has_value(), "ext offer");
  Check(response->SetHeader("sec-websocket-protocol", "chat").has_value(), "select chat");
  Check(nexora::WebSocketHandshake::ValidateUpgradeResponse(*response, client_key, &offer).has_value(), "offered protocol");
  Check(response->SetHeader("sec-websocket-protocol", "nope").has_value(), "unoffered protocol");
  Check(!nexora::WebSocketHandshake::ValidateUpgradeResponse(*response, client_key, &offer).has_value(), "reject protocol");
  Check(response->headers.Remove("sec-websocket-protocol").has_value(), "clear protocol");
  Check(response->SetHeader("sec-websocket-extensions", "permessage-deflate").has_value(), "select ext");
  Check(nexora::WebSocketHandshake::ValidateUpgradeResponse(*response, client_key, &offer).has_value(), "offered ext");
  Check(response->SetHeader("sec-websocket-extensions", "permessage-deflate; client_max_window_bits=15").has_value(),
        "select ext param");
  Check(nexora::WebSocketHandshake::ValidateUpgradeResponse(*response, client_key, &offer).has_value(),
        "offered ext valid param");
  Check(response->SetHeader("sec-websocket-extensions", "permessage-deflate; client_no_context_takeover").has_value(),
        "select ext bare param");
  Check(nexora::WebSocketHandshake::ValidateUpgradeResponse(*response, client_key, &offer).has_value(),
        "offered ext bare param");
  for (std::string_view bad_ext : std::array<std::string_view, 7>{
           "permessage-deflate; =bad;;",
           "permessage-deflate;",
           "permessage-deflate; ; client_no_context_takeover",
           "permessage-deflate; client_max_window_bits=",
           "permessage-deflate; client_max_window_bits=\"15",
           "permessage-deflate; bad/param=1",
           "permessage-deflate, ",
       }) {
    Check(response->SetHeader("sec-websocket-extensions", bad_ext).has_value(), "set malformed ext");
    auto res = nexora::WebSocketHandshake::ValidateUpgradeResponse(*response, client_key, &offer);
    Check(!res.has_value() && Proto(res.error(), nexora::ProtoErrorCode::kWebSocketProtocolError), "reject malformed ext");
  }
  Check(response->SetHeader("sec-websocket-extensions", "x-private").has_value(), "unoffered ext");
  Check(!nexora::WebSocketHandshake::ValidateUpgradeResponse(*response, client_key, &offer).has_value(), "reject ext");
}

void TestRfcFrameAndPing() {
  constexpr std::array<std::uint8_t, 11> rfc{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58};
  auto server = nexora::WebSocketCodec<>::Server();
  auto message = server.DecodeMessage(rfc);
  Check(message.has_value() && message->message.has_value(), "rfc decode");
  if (message.has_value() && message->message.has_value()) {
    Check(message->message->kind == nexora::WebSocketMessageKind::kText, "rfc text");
    Check(Eq(message->message->payload.Span(), "Hello"), "rfc hello");
  }

  nexora::WebSocketMessage ping;
  ping.kind = nexora::WebSocketMessageKind::kPing;
  ping.payload = nexora::Bytes::CopyFromString("z");
  auto ping_wire = server.EncodeMessage(ping);
  Check(ping_wire.has_value(), "encode ping");
  if (!ping_wire.has_value()) {
    return;
  }
  auto client = nexora::WebSocketCodec<>::Client();
  auto seen = client.DecodeMessage(ping_wire->ReadableSpan());
  Check(seen.has_value() && seen->message.has_value() && seen->message->kind == nexora::WebSocketMessageKind::kPing, "ping");
  if (seen.has_value() && seen->message.has_value()) {
    Check(Eq(seen->message->payload.Span(), "z"), "ping payload");
  }
  auto pong = server.DecodeMessage(client.PendingControl());
  Check(pong.has_value() && pong->message.has_value() && pong->message->kind == nexora::WebSocketMessageKind::kPong,
        "auto pong");
  if (pong.has_value() && pong->message.has_value()) {
    Check(Eq(pong->message->payload.Span(), "z"), "pong payload");
  }
}

void TestFragmentAndUtf8() {
  auto server = nexora::WebSocketCodec<>::Server();
  auto client = nexora::WebSocketCodec<>::Client();
  nexora::WebSocketFrame first;
  first.fin = false;
  first.opcode = nexora::WebSocketOpcode::kText;
  first.payload = nexora::Bytes::CopyFromString("Hel");
  nexora::WebSocketFrame ping;
  ping.fin = true;
  ping.opcode = nexora::WebSocketOpcode::kPing;
  ping.payload = nexora::Bytes::CopyFromString("q");
  nexora::WebSocketFrame rest;
  rest.fin = true;
  rest.opcode = nexora::WebSocketOpcode::kContinuation;
  rest.payload = nexora::Bytes::CopyFromString("lo");
  auto frag1 = server.EncodeFrame(first);
  auto mid = server.EncodeFrame(ping);
  auto frag2 = server.EncodeFrame(rest);
  Check(frag1.has_value() && mid.has_value() && frag2.has_value(), "encode fragments");
  if (!(frag1.has_value() && mid.has_value() && frag2.has_value())) {
    return;
  }
  nexora::BytesMut<512> wire;
  Check(wire.Append(frag1->ReadableSpan()).has_value(), "frag1");
  Check(wire.Append(mid->ReadableSpan()).has_value(), "mid ping");
  Check(wire.Append(frag2->ReadableSpan()).has_value(), "frag2");
  auto control = client.DecodeMessage(wire.ReadableSpan());
  Check(control.has_value() && control->message.has_value() && control->message->kind == nexora::WebSocketMessageKind::kPing,
        "interleaved ping");
  if (!(control.has_value() && control->consumed <= wire.Size())) {
    return;
  }
  auto text = client.DecodeMessage(wire.ReadableSpan().subspan(control->consumed));
  Check(text.has_value() && text->message.has_value(), "reassembled");
  if (text.has_value() && text->message.has_value()) {
    Check(text->message->kind == nexora::WebSocketMessageKind::kText, "reassembled kind");
    Check(Eq(text->message->payload.Span(), "Hello"), "reassembled text");
  }

  constexpr std::array<std::uint8_t, 3> bad{0x81, 0x01, 0xff};
  auto fresh = nexora::WebSocketCodec<>::Client();
  auto rejected = fresh.DecodeMessage(bad);
  Check(!rejected.has_value() && Proto(rejected.error(), nexora::ProtoErrorCode::kWebSocketInvalidUtf8), "utf8 rejected");
  Check(fresh.Failed(), "codec failed");

  auto split = nexora::WebSocketCodec<>::Client();
  constexpr std::array<std::uint8_t, 3> lead{0x01, 0x01, 0xc3};
  constexpr std::array<std::uint8_t, 3> tail{0x80, 0x01, 0xa9};
  auto partial = split.DecodeMessage(lead);
  Check(partial.has_value() && !partial->message.has_value(), "partial fragment");
  auto whole = split.DecodeMessage(tail);
  Check(whole.has_value() && whole->message.has_value() && Eq(whole->message->payload.Span(), "\xc3\xa9"), "split utf8");
}

void ExpectUtf8Fail(std::span<const std::uint8_t> first, std::span<const std::uint8_t> second, const char* name) {
  auto client = nexora::WebSocketCodec<>::Client();
  auto opened = client.DecodeMessage(first);
  if (opened.has_value()) {
    Check(!opened->message.has_value(), name);
    auto closed = client.DecodeMessage(second);
    Check(!closed.has_value() && Proto(closed.error(), nexora::ProtoErrorCode::kWebSocketInvalidUtf8), name);
    return;
  }
  Check(Proto(opened.error(), nexora::ProtoErrorCode::kWebSocketInvalidUtf8), name);
}

void TestUtf8Fragments() {
  constexpr std::array<std::uint8_t, 3> lead{0x01, 0x01, 0xc3};
  constexpr std::array<std::uint8_t, 3> non_cont{0x80, 0x01, 0x20};
  ExpectUtf8Fail(lead, non_cont, "non continuation fragment");
  constexpr std::array<std::uint8_t, 3> truncated{0x81, 0x01, 0xc3};
  auto client = nexora::WebSocketCodec<>::Client();
  auto cut = client.DecodeMessage(truncated);
  Check(!cut.has_value() && Proto(cut.error(), nexora::ProtoErrorCode::kWebSocketInvalidUtf8), "truncated fin");
  constexpr std::array<std::uint8_t, 3> overlong_lead{0x01, 0x01, 0xc0};
  constexpr std::array<std::uint8_t, 3> overlong_tail{0x80, 0x01, 0x80};
  ExpectUtf8Fail(overlong_lead, overlong_tail, "overlong split");
  constexpr std::array<std::uint8_t, 3> surrogate_lead{0x01, 0x01, 0xed};
  constexpr std::array<std::uint8_t, 4> surrogate_tail{0x80, 0x02, 0xa0, 0x80};
  ExpectUtf8Fail(surrogate_lead, surrogate_tail, "surrogate split");
}

void ExpectCloseReject(std::span<const std::uint8_t> frame, nexora::ProtoErrorCode code, const char* name) {
  auto client = nexora::WebSocketCodec<>::Client();
  auto seen = client.DecodeMessage(frame);
  Check(!seen.has_value() && Proto(seen.error(), code), name);
}

void TestCloseCodes() {
  constexpr std::array<std::uint8_t, 4> code0{0x88, 0x02, 0x00, 0x00};
  constexpr std::array<std::uint8_t, 4> code999{0x88, 0x02, 0x03, 0xe7};
  constexpr std::array<std::uint8_t, 4> code1004{0x88, 0x02, 0x03, 0xec};
  constexpr std::array<std::uint8_t, 4> code1005{0x88, 0x02, 0x03, 0xed};
  constexpr std::array<std::uint8_t, 4> code1006{0x88, 0x02, 0x03, 0xee};
  constexpr std::array<std::uint8_t, 4> code1015{0x88, 0x02, 0x03, 0xf7};
  constexpr std::array<std::uint8_t, 4> code5000{0x88, 0x02, 0x13, 0x88};
  constexpr std::array<std::uint8_t, 3> one_byte{0x88, 0x01, 0x00};
  constexpr std::array<std::uint8_t, 5> bad_reason{0x88, 0x03, 0x03, 0xe8, 0xff};
  ExpectCloseReject(code0, nexora::ProtoErrorCode::kWebSocketProtocolError, "close 0");
  ExpectCloseReject(code999, nexora::ProtoErrorCode::kWebSocketProtocolError, "close 999");
  ExpectCloseReject(code1004, nexora::ProtoErrorCode::kWebSocketProtocolError, "close 1004");
  ExpectCloseReject(code1005, nexora::ProtoErrorCode::kWebSocketProtocolError, "close 1005");
  ExpectCloseReject(code1006, nexora::ProtoErrorCode::kWebSocketProtocolError, "close 1006");
  ExpectCloseReject(code1015, nexora::ProtoErrorCode::kWebSocketProtocolError, "close 1015");
  ExpectCloseReject(code5000, nexora::ProtoErrorCode::kWebSocketProtocolError, "close 5000");
  ExpectCloseReject(one_byte, nexora::ProtoErrorCode::kWebSocketProtocolError, "close one byte");
  ExpectCloseReject(bad_reason, nexora::ProtoErrorCode::kWebSocketInvalidUtf8, "close bad utf8");
}

void TestUnmaskedClientFrame() {
  constexpr std::array<std::uint8_t, 7> hello{0x81, 0x05, 'H', 'e', 'l', 'l', 'o'};
  auto server = nexora::WebSocketCodec<>::Server();
  auto seen = server.DecodeMessage(hello);
  Check(!seen.has_value() && Proto(seen.error(), nexora::ProtoErrorCode::kWebSocketProtocolError), "server rejects unmasked");
}

void TestCloseAndMaskDirection() {
  auto client = nexora::WebSocketCodec<>::Client();
  nexora::WebSocketMessage close;
  close.kind = nexora::WebSocketMessageKind::kClose;
  close.close_code = 1005;
  Check(!client.EncodeMessage(close).has_value(), "local close rejected");
  close.close_code = 1000;
  close.payload = nexora::Bytes::CopyFromString("bye");
  auto wire = client.EncodeMessage(close);
  Check(wire.has_value(), "close encoded");
  if (!wire.has_value()) {
    return;
  }
  auto server = nexora::WebSocketCodec<>::Server();
  auto seen = server.DecodeMessage(wire->ReadableSpan());
  Check(seen.has_value() && seen->message.has_value() && seen->message->close_code == 1000, "close code");
  if (seen.has_value() && seen->message.has_value()) {
    Check(Eq(seen->message->payload.Span(), "bye"), "close reason");
  }
  constexpr std::array<std::uint8_t, 3> text{0x81, 0x01, 'A'};
  auto after = client.DecodeMessage(text);
  Check(after.has_value() && after->message.has_value() && Eq(after->message->payload.Span(), "A"), "data after close sent");
  constexpr std::array<std::uint8_t, 6> masked_to_client{0x81, 0x80, 0, 0, 0, 0};
  auto fresh = nexora::WebSocketCodec<>::Client();
  Check(!fresh.DecodeMessage(masked_to_client).has_value(), "client rejects masked");
}

}  // namespace

int main() {
  TestUtf8Header();
  TestAcceptVector();
  TestHandshake();
  TestRfcFrameAndPing();
  TestFragmentAndUtf8();
  TestUtf8Fragments();
  TestCloseCodes();
  TestUnmaskedClientFrame();
  TestCloseAndMaskDirection();
  return g_fails == 0 ? 0 : 1;
}
