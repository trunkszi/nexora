// clang-format off
#include <nexora/http1/http1_body.hpp>
// clang-format on
#include <array>
#include <cstdio>
#include <cstring>
#include <nexora/http1/http1_codec.hpp>
#include <nexora/websocket/codec.hpp>
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

bool Proto(const nexora::Error& err, nexora::ProtoErrorCode code) {
  return err.domain == nexora::ErrorDomain::kProto && err.code == static_cast<std::int32_t>(std::to_underlying(code));
}

bool Eq(std::span<const std::uint8_t> bytes, std::string_view text) {
  return bytes.size() == text.size() && (text.empty() || std::memcmp(bytes.data(), text.data(), text.size()) == 0);
}

nexora::BytesMut<4096> Wire(std::string_view text) {
  nexora::BytesMut<4096> buf;
  Check(buf.AppendString(text).has_value(), "append wire");
  return buf;
}

void TestBodyHeader() {
  Check(nexora::http1_detail::ForbiddenTrailer("content-length"), "forbidden trailer name");
  Check(!nexora::http1_detail::ForbiddenTrailer("x-trace"), "ordinary trailer");
}

void TestConflict() {
  auto buf = Wire("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n");
  const auto before = buf.Size();
  nexora::Http1ClientCodec<> client;
  auto decoded = client.DecodeResponse(buf.ReadableSpan(), nexora::Method::kGet);
  Check(!decoded.has_value() && Proto(decoded.error(), nexora::ProtoErrorCode::kHttp1ConflictingFraming), "conflict code");
  Check(buf.Size() == before, "conflict leaves buffer");
}

void TestDistinctLengths() {
  auto buf = Wire("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nAB");
  const auto before = buf.Size();
  nexora::Http1ClientCodec<> client;
  auto decoded = client.DecodeResponse(buf.ReadableSpan(), nexora::Method::kGet);
  Check(!decoded.has_value() && Proto(decoded.error(), nexora::ProtoErrorCode::kHttp1ConflictingFraming), "distinct lengths");
  Check(buf.Size() == before, "distinct lengths leave buffer");
}

void TestSameLengths() {
  auto buf = Wire("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nZ");
  nexora::Http1ClientCodec<> client;
  auto decoded = client.DecodeResponse(buf.ReadableSpan(), nexora::Method::kGet);
  Check(decoded.has_value() && decoded->has_value(), "same lengths decode");
  if (decoded.has_value() && decoded->has_value()) {
    Check(Eq((*decoded)->message.body.Span(), "Z"), "same lengths body");
  }
}

void TestChunkedTrailer() {
  auto buf = Wire(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
      "5;ext=token\r\nhello\r\n0\r\nX-Trace: abc\r\n\r\n");
  nexora::Http1ClientCodec<> client;
  auto decoded = client.DecodeResponse(buf.ReadableSpan(), nexora::Method::kGet);
  Check(decoded.has_value() && decoded->has_value(), "chunked decode");
  if (decoded.has_value() && decoded->has_value()) {
    Check(Eq((*decoded)->message.body.Span(), "hello"), "chunked body");
    const auto trace = (*decoded)->message.trailers.Get("x-trace");
    Check(trace.has_value() && *trace == "abc", "chunked trailer");
    Check((*decoded)->consumed == buf.Size(), "chunked consumed");
  }
}

void TestForbiddenTrailer() {
  auto buf = Wire("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 1\r\n\r\n");
  const auto before = buf.Size();
  nexora::Http1ClientCodec<> client;
  auto decoded = client.DecodeResponse(buf.ReadableSpan(), nexora::Method::kGet);
  Check(!decoded.has_value() && Proto(decoded.error(), nexora::ProtoErrorCode::kHttp1ParseError), "forbidden trailer");
  Check(buf.Size() == before, "forbidden trailer leaves buffer");
}

void TestSwitchingRemainder() {
  constexpr std::string_view head = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
  nexora::BytesMut<4096> buf;
  Check(buf.AppendString(head).has_value(), "101 head");
  constexpr std::array<std::uint8_t, 7> frame{0x81, 0x05, 'H', 'e', 'l', 'l', 'o'};
  Check(buf.Append(frame).has_value(), "101 frame");
  nexora::Http1ClientCodec<> client;
  auto decoded = client.DecodeResponse(buf.ReadableSpan(), nexora::Method::kGet);
  Check(decoded.has_value() && decoded->has_value(), "101 decode");
  if (!(decoded.has_value() && decoded->has_value())) {
    return;
  }
  Check((*decoded)->message.status.AsU16() == 101, "101 status");
  Check((*decoded)->keep_alive == nexora::Http1KeepAlive::kUpgrade, "101 upgrade");
  Check((*decoded)->message.body.Empty(), "101 has no http body");
  Check((*decoded)->consumed == head.size(), "101 consumed headers");
  const auto rest = buf.ReadableSpan().subspan((*decoded)->consumed);
  Check(Eq(rest, std::string_view("\x81\x05Hello", 7)), "101 remainder");
  nexora::WebSocketCodec<> ws = nexora::WebSocketCodec<>::Client();
  auto message = ws.DecodeMessage(rest);
  Check(message.has_value() && message->message.has_value(), "101 frame decodes");
  if (message.has_value() && message->message.has_value()) {
    Check(message->message->kind == nexora::WebSocketMessageKind::kText, "101 text");
    Check(Eq(message->message->payload.Span(), "Hello"), "101 hello");
  }
}

void TestChunkMetadataCap() {
  nexora::Http1ClientCodec<256, 4096> client;
  nexora::BytesMut<1024> first;
  Check(first.AppendString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;").has_value(), "meta head");
  std::array<std::uint8_t, 180> ext{};
  for (auto& byte : ext) {
    byte = static_cast<std::uint8_t>('a');
  }
  Check(first.Append(ext).has_value(), "meta ext");
  Check(first.AppendString("\r\nA\r\n").has_value(), "meta data");
  auto opened = client.DecodeResponse(first.ReadableSpan(), nexora::Method::kGet);
  Check(opened.has_value() && !opened->has_value(), "chunk meta still open");
  nexora::BytesMut<512> second;
  Check(second.AppendString("1;").has_value(), "second size");
  Check(second.Append(ext).has_value(), "second ext");
  Check(second.AppendString("\r\nB\r\n").has_value(), "second data");
  auto overflow = client.DecodeResponse(second.ReadableSpan(), nexora::Method::kGet);
  Check(!overflow.has_value() && Proto(overflow.error(), nexora::ProtoErrorCode::kHttp1MessageTooLarge), "chunk meta cap");
}

void TestIncrementalChunks() {
  nexora::Http1ClientCodec<> client;
  auto first = Wire("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n");
  auto opened = client.DecodeResponse(first.ReadableSpan(), nexora::Method::kGet);
  Check(opened.has_value() && !opened->has_value(), "first chunk held");
  auto second = Wire("1\r\nB\r\n");
  auto mid = client.DecodeResponse(second.ReadableSpan(), nexora::Method::kGet);
  Check(mid.has_value() && !mid->has_value(), "second chunk held");
  auto last = Wire("0\r\n\r\n");
  auto done = client.DecodeResponse(last.ReadableSpan(), nexora::Method::kGet);
  Check(done.has_value() && done->has_value() && Eq((*done)->message.body.Span(), "AB"), "incremental chunks");

  constexpr std::string_view wire = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\n0\r\n\r\n";
  nexora::Http1ClientCodec<> bytewise;
  bool finished = false;
  for (std::size_t i = 0; i < wire.size(); ++i) {
    const auto byte = static_cast<std::uint8_t>(wire[i]);
    auto step = bytewise.DecodeResponse(std::span<const std::uint8_t>(&byte, 1), nexora::Method::kGet);
    Check(step.has_value(), "bytewise step");
    if (!step.has_value()) {
      return;
    }
    if (step->has_value()) {
      Check(Eq((*step)->message.body.Span(), "Z"), "bytewise body");
      Check(i + 1 == wire.size(), "bytewise finishes on last byte");
      finished = true;
    }
  }
  Check(finished, "bytewise completed");
}

}  // namespace

int main() {
  TestBodyHeader();
  TestConflict();
  TestDistinctLengths();
  TestSameLengths();
  TestChunkedTrailer();
  TestForbiddenTrailer();
  TestSwitchingRemainder();
  TestChunkMetadataCap();
  TestIncrementalChunks();
  return g_fails == 0 ? 0 : 1;
}
