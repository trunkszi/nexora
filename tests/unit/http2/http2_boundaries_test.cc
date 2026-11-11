#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "link.hpp"

namespace {

std::vector<std::uint8_t> Frame(nexora::Http2FrameType type, std::uint8_t flags, std::uint32_t stream,
                                std::span<const std::uint8_t> payload) {
  std::vector<std::uint8_t> out(nexora::kHttp2FrameHeaderSize + payload.size());
  auto size = nexora::EncodeFrame(type, flags, stream, payload, out);
  if (!size)
    out.clear();
  else
    out.resize(*size);
  return out;
}

int ExpectGoaway(std::span<const std::uint8_t> wire, std::uint32_t code) {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  if (link.server.FeedBytes(wire)) return nexora::test::Fail(__LINE__);
  const auto got = nexora::test::PayloadCode(link.server, nexora::Http2FrameType::kGoaway);
  if (got != code) return nexora::test::Fail(__LINE__);
  return 0;
}

int NegativeWindowAndPartial() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  auto stream = link.client.OpenStream();
  if (!stream) return nexora::test::Fail(__LINE__);
  if (!link.client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", "ex", "/w", {}, false)) {
    return nexora::test::Fail(__LINE__);
  }
  std::vector<std::uint8_t> chunk(20000, 0x11);
  auto first = link.client.SubmitData(*stream, chunk, false);
  if (!first || *first != 16384) return nexora::test::Fail(__LINE__);
  auto rest = link.client.SubmitData(*stream, std::span<const std::uint8_t>(chunk).subspan(*first), false);
  if (!rest || *rest != chunk.size() - *first) return nexora::test::Fail(__LINE__);
  if (link.client.StreamSendWindow(*stream) != 65535 - static_cast<std::int64_t>(chunk.size())) {
    return nexora::test::Fail(__LINE__);
  }
  if (const int line = link.Pump()) return line;
  nexora::Http2Settings shrink{};
  shrink.enable_push = 0;
  shrink.initial_window_size = 0;
  std::array<std::uint8_t, 36> payload{};
  auto payload_size = nexora::EncodeSettingsPayload(shrink, payload);
  std::array<std::uint8_t, 64> frame{};
  auto frame_size = nexora::EncodeFrame(nexora::Http2FrameType::kSettings, 0, 0,
                                        std::span<const std::uint8_t>(payload.data(), *payload_size), frame);
  if (!payload_size || !frame_size) return nexora::test::Fail(__LINE__);
  if (!link.client.FeedBytes(std::span<const std::uint8_t>(frame.data(), *frame_size))) return nexora::test::Fail(__LINE__);
  if (link.client.StreamSendWindow(*stream) >= 0) return nexora::test::Fail(__LINE__);
  constexpr std::array<std::uint8_t, 4> extra{1, 2, 3, 4};
  auto blocked = link.client.SubmitData(*stream, extra, false);
  if (!blocked || *blocked != 0) return nexora::test::Fail(__LINE__);
  const auto debt = -link.client.StreamSendWindow(*stream);
  if (!link.server.SubmitWindowUpdate(*stream, static_cast<std::uint32_t>(debt + 4))) return nexora::test::Fail(__LINE__);
  if (const int line = link.Pump()) return line;
  if (link.client.StreamSendWindow(*stream) != 4) return nexora::test::Fail(__LINE__);
  auto resumed = link.client.SubmitData(*stream, extra, true);
  if (!resumed || *resumed != 4) return nexora::test::Fail(__LINE__);
  return 0;
}

int GrpcTrailers() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  auto stream = link.client.OpenStream();
  if (!stream) return nexora::test::Fail(__LINE__);
  nexora::Headers<> headers;
  if (!headers.Add("content-type", "application/grpc")) return nexora::test::Fail(__LINE__);
  if (!link.client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "http", "localhost", "/svc/M", headers, false)) {
    return nexora::test::Fail(__LINE__);
  }
  constexpr std::array<std::uint8_t, 6> message{0, 0, 0, 0, 1, 0x2a};
  auto wrote = link.client.SubmitData(*stream, message, false);
  if (!wrote || *wrote != message.size()) return nexora::test::Fail(__LINE__);
  nexora::Headers<> trailers;
  if (!trailers.Add("grpc-status", "0")) return nexora::test::Fail(__LINE__);
  if (!link.client.SubmitTrailers(*stream, trailers)) return nexora::test::Fail(__LINE__);
  link.server_events.clear();
  if (const int line = link.Pump()) return line;
  bool saw_headers = false;
  bool saw_data = false;
  bool saw_trailers = false;
  bool saw_complete = false;
  for (const auto& event : link.server_events) {
    if (event.stream_id != *stream) continue;
    if (event.kind == nexora::Http2Event::Kind::kHeaders) {
      saw_headers = event.headers.Get("content-type") == std::optional<std::string_view>{"application/grpc"} &&
                    event.path == "/svc/M" && !event.end_stream;
    }
    if (event.kind == nexora::Http2Event::Kind::kData) saw_data = event.data.size() == message.size();
    if (event.kind == nexora::Http2Event::Kind::kTrailers) {
      saw_trailers = event.headers.Get("grpc-status") == std::optional<std::string_view>{"0"};
    }
    if (event.kind == nexora::Http2Event::Kind::kMessageComplete) {
      saw_complete = event.data.size() == message.size() && event.data.Back() == 0x2a;
    }
  }
  if (!saw_headers || !saw_data || !saw_trailers || !saw_complete) return nexora::test::Fail(__LINE__);
  return 0;
}

int PingGoawayRst() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  if (!link.client.SubmitPing(0x1122334455667788ULL, false)) return nexora::test::Fail(__LINE__);
  link.client_events.clear();
  if (const int line = link.Pump()) return line;
  bool ping = false;
  for (const auto& event : link.client_events) {
    if (event.kind == nexora::Http2Event::Kind::kPingAck) ping = true;
  }
  if (!ping) return nexora::test::Fail(__LINE__);
  auto stream = link.client.OpenStream();
  if (!stream || !link.client.SubmitRequestHeaders(*stream, nexora::Method::kGet, "https", "ex", "/", {}, false)) {
    return nexora::test::Fail(__LINE__);
  }
  if (const int line = link.Pump()) return line;
  if (!link.client.SubmitRstStream(*stream, nexora::Http2ErrorCode::kCancel)) return nexora::test::Fail(__LINE__);
  link.server_events.clear();
  if (const int line = link.Pump()) return line;
  bool reset = false;
  for (const auto& event : link.server_events) {
    if (event.kind == nexora::Http2Event::Kind::kStreamReset && event.stream_id == *stream &&
        event.error_code == nexora::Http2ErrorCode::kCancel) {
      reset = true;
    }
  }
  if (!reset) return nexora::test::Fail(__LINE__);
  if (!link.server.SubmitGoaway(1, nexora::Http2ErrorCode::kNoError)) return nexora::test::Fail(__LINE__);
  link.client_events.clear();
  if (const int line = link.Pump()) return line;
  bool goaway = false;
  for (const auto& event : link.client_events) {
    if (event.kind == nexora::Http2Event::Kind::kGoaway && event.last_stream_id == 1) goaway = true;
  }
  if (!goaway) return nexora::test::Fail(__LINE__);
  return 0;
}

int SplitPreface() {
  nexora::Http2Connection client(nexora::Http2Role::kClient);
  nexora::Http2Connection server(nexora::Http2Role::kServer);
  if (!client.InitiateHandshake() || !server.InitiateHandshake()) return nexora::test::Fail(__LINE__);
  const auto settings = server.PendingOutput();
  if (settings.size() < 21 || settings[17] != 0 || settings[18] != 0 || settings[19] != 0 || settings[20] != 0) {
    return nexora::test::Fail(__LINE__);
  }
  const auto bytes = client.PendingOutput();
  if (bytes.size() < 24 || !server.FeedBytes(bytes.first(10))) return nexora::test::Fail(__LINE__);
  if (!server.FeedBytes(bytes.subspan(10))) return nexora::test::Fail(__LINE__);
  client.ConsumeOutput(bytes.size());
  constexpr std::array<std::uint8_t, 24> garbage{};
  nexora::Http2Connection other(nexora::Http2Role::kServer);
  if (other.FeedBytes(garbage)) return nexora::test::Fail(__LINE__);
  return 0;
}

int MalformedFrames() {
  constexpr std::array<std::uint8_t, 1> one{0};
  constexpr std::array<std::uint8_t, 8> eight{};
  constexpr std::array<std::uint8_t, 4> rst{0, 0, 0, 8};
  if (const int line = ExpectGoaway(Frame(nexora::Http2FrameType::kPing, 0, 0, one), 0x6)) return line;
  if (const int line = ExpectGoaway(Frame(nexora::Http2FrameType::kSettings, 0, 0, one), 0x6)) return line;
  if (const int line = ExpectGoaway(Frame(nexora::Http2FrameType::kSettings, 0x1, 0, eight), 0x6)) return line;
  if (const int line = ExpectGoaway(Frame(nexora::Http2FrameType::kRstStream, 0, 1, one), 0x6)) return line;
  if (const int line = ExpectGoaway(Frame(nexora::Http2FrameType::kData, 0, 0, one), 0x1)) return line;
  constexpr std::array<std::uint8_t, 9> huge{0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  if (const int line = ExpectGoaway(huge, 0x6)) return line;
  nexora::HeaderField status;
  if (!status.name.TryAssign(":status") || !status.value.TryAssign("200")) return nexora::test::Fail(__LINE__);
  std::array<std::uint8_t, 32> block{};
  auto encoded = nexora::HpackEncoder{}.Encode(std::span<const nexora::HeaderField>(&status, 1), block);
  if (!encoded) return nexora::test::Fail(__LINE__);
  const auto headers = Frame(nexora::Http2FrameType::kHeaders, 0x4, 1, std::span<const std::uint8_t>(block.data(), *encoded));
  if (const int line = ExpectGoaway(headers, 0x1)) return line;
  auto first = Frame(nexora::Http2FrameType::kHeaders, 0, 1, std::span<const std::uint8_t>(rst.data(), 1));
  auto empty = Frame(nexora::Http2FrameType::kContinuation, 0, 1, {});
  std::vector<std::uint8_t> burst = first;
  burst.insert(burst.end(), empty.begin(), empty.end());
  burst.insert(burst.end(), empty.begin(), empty.end());
  if (const int line = ExpectGoaway(burst, 0xb)) return line;
  return 0;
}

int RapidReset() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  auto stream = link.client.OpenStream();
  if (!stream || !link.client.SubmitRequestHeaders(*stream, nexora::Method::kGet, "https", "ex", "/r", {}, false)) {
    return nexora::test::Fail(__LINE__);
  }
  if (const int line = link.Pump()) return line;
  constexpr std::array<std::uint8_t, 4> code{0, 0, 0, 0x8};
  const auto rst = Frame(nexora::Http2FrameType::kRstStream, 0, *stream, code);
  for (int i = 0; i < 128; ++i) {
    if (!link.server.FeedBytes(rst)) return nexora::test::Fail(__LINE__);
    while (link.server.PollEvent()) {
    }
  }
  if (link.server.FeedBytes(rst)) return nexora::test::Fail(__LINE__);
  const auto calm = nexora::test::PayloadCode(link.server, nexora::Http2FrameType::kGoaway);
  if (calm != 0xb) return nexora::test::Fail(__LINE__);
  return 0;
}

int HeaderFaults() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  auto stream = link.client.OpenStream();
  nexora::Headers<> headers;
  if (!headers.Add("content-length", "1")) return nexora::test::Fail(__LINE__);
  if (!stream || !link.client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", "ex", "/c", headers, false)) {
    return nexora::test::Fail(__LINE__);
  }
  constexpr std::array<std::uint8_t, 2> extra{1, 2};
  if (!link.client.SubmitData(*stream, extra, false)) return nexora::test::Fail(__LINE__);
  const auto wire = std::vector<std::uint8_t>(link.client.PendingOutput().begin(), link.client.PendingOutput().end());
  if (link.server.FeedBytes(wire)) return nexora::test::Fail(__LINE__);
  const auto length_code = nexora::test::PayloadCode(link.server, nexora::Http2FrameType::kGoaway);
  if (length_code != 0x1) return nexora::test::Fail(__LINE__);
  nexora::test::Link closed;
  if (const int line = closed.Handshake()) return line;
  auto done = closed.client.OpenStream();
  if (!done || !closed.client.SubmitRequestHeaders(*done, nexora::Method::kGet, "https", "ex", "/", {}, true)) {
    return nexora::test::Fail(__LINE__);
  }
  if (const int line = closed.Pump()) return line;
  constexpr std::array<std::uint8_t, 1> indexed{0x82};
  auto again = Frame(nexora::Http2FrameType::kHeaders, 0x4, *done, indexed);
  if (closed.server.FeedBytes(again)) return nexora::test::Fail(__LINE__);
  const auto closed_code = nexora::test::PayloadCode(closed.server, nexora::Http2FrameType::kGoaway);
  if (closed_code != 0x5) return nexora::test::Fail(__LINE__);
  return 0;
}

int ContinuationSplit() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  auto stream = link.client.OpenStream();
  nexora::Headers<> headers;
  const auto bulky = std::string(8192, '~');
  if (!headers.Add("x-b", bulky) || !headers.Add("x-c", bulky)) return nexora::test::Fail(__LINE__);
  if (!stream || !link.client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", "ex", "/big", headers, true)) {
    return nexora::test::Fail(__LINE__);
  }
  const auto pending = link.client.PendingOutput();
  bool saw_open = false;
  bool saw_end = false;
  std::size_t cursor = 0;
  while (cursor + 9 <= pending.size()) {
    const auto len = (std::uint32_t{pending[cursor]} << 16) | (std::uint32_t{pending[cursor + 1]} << 8) | pending[cursor + 2];
    const auto type = pending[cursor + 3];
    const auto flags = pending[cursor + 4];
    if (type == 0x1 && (flags & 0x4) == 0) saw_open = true;
    if (type == 0x9 && (flags & 0x4) != 0) saw_end = true;
    cursor += 9 + len;
  }
  if (!saw_open || !saw_end || cursor != pending.size()) return nexora::test::Fail(__LINE__);
  if (const int line = link.Pump()) return line;
  bool saw_value = false;
  for (const auto& event : link.server_events) {
    if (event.kind == nexora::Http2Event::Kind::kHeaders &&
        event.headers.Get("x-b") == std::optional<std::string_view>{bulky}) {
      saw_value = true;
    }
  }
  if (!saw_value) return nexora::test::Fail(__LINE__);
  nexora::Headers<> response;
  if (!response.Add("x-b", bulky) || !response.Add("x-c", bulky)) return nexora::test::Fail(__LINE__);
  if (!link.server.SubmitResponseHeaders(*stream, nexora::StatusCode{200}, response, false))
    return nexora::test::Fail(__LINE__);
  const auto outbound = std::vector<std::uint8_t>(link.server.PendingOutput().begin(), link.server.PendingOutput().end());
  link.server.ConsumeOutput(outbound.size());
  if (outbound.size() < 9) return nexora::test::Fail(__LINE__);
  const auto first_len = (std::uint32_t{outbound[0]} << 16) | (std::uint32_t{outbound[1]} << 8) | outbound[2];
  const auto first = std::size_t{9} + first_len;
  if (first >= outbound.size() || (outbound[4] & 0x4) != 0) return nexora::test::Fail(__LINE__);
  if (!link.client.FeedBytes(std::span<const std::uint8_t>(outbound.data(), first))) return nexora::test::Fail(__LINE__);
  auto other = link.client.OpenStream();
  if (!other || !link.client.SubmitRequestHeaders(*other, nexora::Method::kGet, "https", "ex", "/next", {}, true)) {
    return nexora::test::Fail(__LINE__);
  }
  if (!link.client.FeedBytes(std::span<const std::uint8_t>(outbound.data() + first, outbound.size() - first))) {
    return nexora::test::Fail(__LINE__);
  }
  bool saw_response = false;
  while (auto event = link.client.PollEvent()) {
    if (event->kind == nexora::Http2Event::Kind::kHeaders &&
        event->headers.Get("x-b") == std::optional<std::string_view>{bulky}) {
      saw_response = true;
    }
  }
  if (!saw_response) return nexora::test::Fail(__LINE__);
  link.server_events.clear();
  if (const int line = link.Pump()) return line;
  bool saw_next = false;
  for (const auto& event : link.server_events) {
    if (event.kind == nexora::Http2Event::Kind::kHeaders && event.path == "/next") saw_next = true;
  }
  if (!saw_next) return nexora::test::Fail(__LINE__);
  return 0;
}

int HeadKeepsLength() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  auto stream = link.client.OpenStream();
  if (!stream || !link.client.SubmitRequestHeaders(*stream, nexora::Method::kHead, "https", "ex", "/h", {}, true)) {
    return nexora::test::Fail(__LINE__);
  }
  if (const int line = link.Pump()) return line;
  nexora::Headers<> headers;
  if (!headers.Add("content-length", "1024")) return nexora::test::Fail(__LINE__);
  if (!link.server.SubmitResponseHeaders(*stream, nexora::StatusCode{200}, headers, true)) {
    return nexora::test::Fail(__LINE__);
  }
  link.client_events.clear();
  if (const int line = link.Pump()) return line;
  bool saw = false;
  for (const auto& event : link.client_events) {
    if (event.kind == nexora::Http2Event::Kind::kHeaders && event.status.AsU16() == 200 &&
        event.headers.Get("content-length") == std::optional<std::string_view>{"1024"}) {
      saw = true;
    }
  }
  if (!saw) return nexora::test::Fail(__LINE__);
  return 0;
}

int NotModifiedKeepsLength() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  auto stream = link.client.OpenStream();
  if (!stream || !link.client.SubmitRequestHeaders(*stream, nexora::Method::kGet, "https", "ex", "/n", {}, true)) {
    return nexora::test::Fail(__LINE__);
  }
  if (const int line = link.Pump()) return line;
  nexora::Headers<> headers;
  if (!headers.Add("content-length", "500")) return nexora::test::Fail(__LINE__);
  if (!link.server.SubmitResponseHeaders(*stream, nexora::StatusCode{304}, headers, true)) {
    return nexora::test::Fail(__LINE__);
  }
  if (const int line = link.Pump()) return line;
  bool saw = false;
  for (const auto& event : link.client_events) {
    if (event.kind == nexora::Http2Event::Kind::kHeaders && event.status.AsU16() == 304) saw = true;
  }
  if (!saw) return nexora::test::Fail(__LINE__);
  return 0;
}

int ContinueThenFinal() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  auto stream = link.client.OpenStream();
  if (!stream || !link.client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", "ex", "/c", {}, false)) {
    return nexora::test::Fail(__LINE__);
  }
  if (const int line = link.Pump()) return line;
  if (!link.server.SubmitResponseHeaders(*stream, nexora::StatusCode{100}, {}, false)) return nexora::test::Fail(__LINE__);
  if (!link.server.SubmitResponseHeaders(*stream, nexora::StatusCode{200}, {}, false)) return nexora::test::Fail(__LINE__);
  constexpr std::array<std::uint8_t, 3> body{1, 2, 3};
  auto wrote = link.server.SubmitData(*stream, body, true);
  if (!wrote || *wrote != body.size()) return nexora::test::Fail(__LINE__);
  link.client_events.clear();
  if (const int line = link.Pump()) return line;
  constexpr std::array<nexora::Http2Event::Kind, 4> expect{nexora::Http2Event::Kind::kHeaders,
                                                           nexora::Http2Event::Kind::kHeaders, nexora::Http2Event::Kind::kData,
                                                           nexora::Http2Event::Kind::kMessageComplete};
  std::size_t index = 0;
  bool saw_100 = false;
  bool saw_200 = false;
  for (const auto& event : link.client_events) {
    if (event.stream_id != *stream) continue;
    if (index >= 4 || event.kind != expect[index]) return nexora::test::Fail(__LINE__);
    if (index == 0 && event.status.AsU16() == 100) saw_100 = true;
    if (index == 1 && event.kind == nexora::Http2Event::Kind::kHeaders && event.status.AsU16() == 200) saw_200 = true;
    ++index;
  }
  if (index != 4 || !saw_100 || !saw_200) return nexora::test::Fail(__LINE__);
  return 0;
}

int ShortBodyThenTrailers() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  auto stream = link.client.OpenStream();
  if (!stream || !link.client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", "ex", "/t", {}, false)) {
    return nexora::test::Fail(__LINE__);
  }
  if (const int line = link.Pump()) return line;
  nexora::Headers<> headers;
  if (!headers.Add("content-length", "10")) return nexora::test::Fail(__LINE__);
  if (!link.server.SubmitResponseHeaders(*stream, nexora::StatusCode{200}, headers, false)) {
    return nexora::test::Fail(__LINE__);
  }
  constexpr std::array<std::uint8_t, 5> body{1, 2, 3, 4, 5};
  if (!link.server.SubmitData(*stream, body, false)) return nexora::test::Fail(__LINE__);
  nexora::Headers<> trailers;
  if (!trailers.Add("x-t", "1") || !link.server.SubmitTrailers(*stream, trailers)) return nexora::test::Fail(__LINE__);
  const auto wire = std::vector<std::uint8_t>(link.server.PendingOutput().begin(), link.server.PendingOutput().end());
  if (link.client.FeedBytes(wire)) return nexora::test::Fail(__LINE__);
  const auto code = nexora::test::PayloadCode(link.client, nexora::Http2FrameType::kGoaway);
  if (code != 0x1) return nexora::test::Fail(__LINE__);
  return 0;
}

int ResetDebtRecovers() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  for (int i = 0; i < 200; ++i) {
    auto ok = link.client.OpenStream();
    auto drop = link.client.OpenStream();
    if (!ok || !drop) return nexora::test::Fail(__LINE__);
    if (!link.client.SubmitRequestHeaders(*ok, nexora::Method::kGet, "https", "ex", "/ok", {}, true)) {
      return nexora::test::Fail(__LINE__);
    }
    if (!link.client.SubmitRequestHeaders(*drop, nexora::Method::kGet, "https", "ex", "/x", {}, false)) {
      return nexora::test::Fail(__LINE__);
    }
    if (const int line = link.Pump()) return line;
    if (!link.server.SubmitResponseHeaders(*ok, nexora::StatusCode{200}, {}, true)) return nexora::test::Fail(__LINE__);
    if (!link.client.SubmitRstStream(*drop, nexora::Http2ErrorCode::kCancel)) return nexora::test::Fail(__LINE__);
    if (const int line = link.Pump()) return line;
    link.client_events.clear();
    link.server_events.clear();
  }
  auto again = link.client.OpenStream();
  if (!again || !link.client.SubmitRequestHeaders(*again, nexora::Method::kGet, "https", "ex", "/alive", {}, true)) {
    return nexora::test::Fail(__LINE__);
  }
  link.server_events.clear();
  if (const int line = link.Pump()) return line;
  bool saw = false;
  for (const auto& event : link.server_events) {
    if (event.kind == nexora::Http2Event::Kind::kHeaders && event.path == "/alive") saw = true;
  }
  if (!saw) return nexora::test::Fail(__LINE__);
  return 0;
}

int ContinueStillChecksLength() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  auto stream = link.client.OpenStream();
  nexora::Headers<> headers;
  if (!headers.Add("content-length", "10")) return nexora::test::Fail(__LINE__);
  if (!stream || !link.client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", "ex", "/c", headers, false)) {
    return nexora::test::Fail(__LINE__);
  }
  if (const int line = link.Pump()) return line;
  if (!link.server.SubmitResponseHeaders(*stream, nexora::StatusCode{100}, {}, false)) {
    return nexora::test::Fail(__LINE__);
  }
  constexpr std::array<std::uint8_t, 5> body{1, 2, 3, 4, 5};
  if (!link.client.SubmitData(*stream, body, true)) return nexora::test::Fail(__LINE__);
  const auto wire = std::vector<std::uint8_t>(link.client.PendingOutput().begin(), link.client.PendingOutput().end());
  if (link.server.FeedBytes(wire)) return nexora::test::Fail(__LINE__);
  const auto code = nexora::test::PayloadCode(link.server, nexora::Http2FrameType::kGoaway);
  if (code != 0x1) return nexora::test::Fail(__LINE__);
  return 0;
}

int EarlyNoContentKeepsBody() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  auto stream = link.client.OpenStream();
  nexora::Headers<> headers;
  if (!headers.Add("content-length", "4")) return nexora::test::Fail(__LINE__);
  if (!stream || !link.client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", "ex", "/n", headers, false)) {
    return nexora::test::Fail(__LINE__);
  }
  if (const int line = link.Pump()) return line;
  if (!link.server.SubmitResponseHeaders(*stream, nexora::StatusCode{204}, {}, true)) {
    return nexora::test::Fail(__LINE__);
  }
  constexpr std::array<std::uint8_t, 4> body{1, 2, 3, 4};
  if (!link.client.SubmitData(*stream, body, true)) return nexora::test::Fail(__LINE__);
  if (const int line = link.Pump()) return line;
  bool saw = false;
  for (const auto& event : link.server_events) {
    if (event.kind == nexora::Http2Event::Kind::kMessageComplete && event.stream_id == *stream) saw = true;
  }
  if (!saw) return nexora::test::Fail(__LINE__);
  return 0;
}

int RapidResetWithEndStreamOnHeaders() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  for (int i = 0; i < 128; ++i) {
    auto stream = link.client.OpenStream();
    if (!stream || !link.client.SubmitRequestHeaders(*stream, nexora::Method::kGet, "https", "ex", "/r", {}, true)) {
      return nexora::test::Fail(__LINE__);
    }
    if (!link.client.SubmitRstStream(*stream, nexora::Http2ErrorCode::kCancel)) return nexora::test::Fail(__LINE__);
    if (const int line = link.Pump()) return line;
    link.client_events.clear();
    link.server_events.clear();
  }
  auto last = link.client.OpenStream();
  if (!last || !link.client.SubmitRequestHeaders(*last, nexora::Method::kGet, "https", "ex", "/z", {}, true)) {
    return nexora::test::Fail(__LINE__);
  }
  if (!link.client.SubmitRstStream(*last, nexora::Http2ErrorCode::kCancel)) return nexora::test::Fail(__LINE__);
  const auto wire = std::vector<std::uint8_t>(link.client.PendingOutput().begin(), link.client.PendingOutput().end());
  if (link.server.FeedBytes(wire)) return nexora::test::Fail(__LINE__);
  const auto calm = nexora::test::PayloadCode(link.server, nexora::Http2FrameType::kGoaway);
  if (calm != 0xb) return nexora::test::Fail(__LINE__);
  return 0;
}

int ClientSurvivesInterleavedServerResets() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  for (int i = 0; i < 200; ++i) {
    auto ok = link.client.OpenStream();
    auto drop = link.client.OpenStream();
    if (!ok || !drop) return nexora::test::Fail(__LINE__);
    if (!link.client.SubmitRequestHeaders(*ok, nexora::Method::kGet, "https", "ex", "/ok", {}, true)) {
      return nexora::test::Fail(__LINE__);
    }
    if (!link.client.SubmitRequestHeaders(*drop, nexora::Method::kGet, "https", "ex", "/x", {}, false)) {
      return nexora::test::Fail(__LINE__);
    }
    if (const int line = link.Pump()) return line;
    if (!link.server.SubmitResponseHeaders(*ok, nexora::StatusCode{200}, {}, true)) {
      return nexora::test::Fail(__LINE__);
    }
    if (!link.server.SubmitRstStream(*drop, nexora::Http2ErrorCode::kCancel)) return nexora::test::Fail(__LINE__);
    if (const int line = link.Pump()) return line;
    if (nexora::test::PayloadCode(link.client, nexora::Http2FrameType::kGoaway) == 0xb) {
      return nexora::test::Fail(__LINE__);
    }
    link.client_events.clear();
    link.server_events.clear();
  }
  return 0;
}

}  // namespace

int main() {
  if (const int line = NegativeWindowAndPartial()) return line;
  if (const int line = GrpcTrailers()) return line;
  if (const int line = PingGoawayRst()) return line;
  if (const int line = SplitPreface()) return line;
  if (const int line = MalformedFrames()) return line;
  if (const int line = RapidReset()) return line;
  if (const int line = HeaderFaults()) return line;
  if (const int line = ContinuationSplit()) return line;
  if (const int line = HeadKeepsLength()) return line;
  if (const int line = NotModifiedKeepsLength()) return line;
  if (const int line = ContinueThenFinal()) return line;
  if (const int line = ShortBodyThenTrailers()) return line;
  if (const int line = ResetDebtRecovers()) return line;
  if (const int line = ContinueStillChecksLength()) return line;
  if (const int line = EarlyNoContentKeepsBody()) return line;
  if (const int line = RapidResetWithEndStreamOnHeaders()) return line;
  if (const int line = ClientSurvivesInterleavedServerResets()) return line;
  return 0;
}
