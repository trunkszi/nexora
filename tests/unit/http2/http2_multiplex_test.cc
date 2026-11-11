#include <array>
#include <charconv>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "link.hpp"

namespace {

int MultiplexTwoStreams() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  auto left = link.client.OpenStream();
  auto right = link.client.OpenStream();
  if (!left || !right || *right != *left + 2U) return nexora::test::Fail(__LINE__);
  nexora::Headers<> left_headers;
  if (!left_headers.Add("x-stream", "left")) return nexora::test::Fail(__LINE__);
  nexora::Headers<> right_headers;
  if (!right_headers.Add("x-stream", "right")) return nexora::test::Fail(__LINE__);
  if (!link.client.SubmitRequestHeaders(*left, nexora::Method::kGet, "https", "ex", "/left", left_headers, true)) {
    return nexora::test::Fail(__LINE__);
  }
  if (!link.client.SubmitRequestHeaders(*right, nexora::Method::kPost, "https", "ex", "/right", right_headers, true)) {
    return nexora::test::Fail(__LINE__);
  }
  link.client_events.clear();
  link.server_events.clear();
  if (const int line = link.Pump()) return line;
  const nexora::Http2Event* left_headers_ev = nullptr;
  const nexora::Http2Event* right_headers_ev = nullptr;
  for (const auto& event : link.server_events) {
    if (event.kind != nexora::Http2Event::Kind::kHeaders) continue;
    if (event.stream_id == *left) left_headers_ev = &event;
    if (event.stream_id == *right) right_headers_ev = &event;
  }
  if (left_headers_ev == nullptr || right_headers_ev == nullptr) return nexora::test::Fail(__LINE__);
  if (left_headers_ev->path != "/left" || left_headers_ev->method != nexora::Method::kGet) return nexora::test::Fail(__LINE__);
  if (right_headers_ev->path != "/right" || right_headers_ev->method != nexora::Method::kPost) {
    return nexora::test::Fail(__LINE__);
  }
  if (left_headers_ev->headers.Get("x-stream") != std::optional<std::string_view>{"left"}) return nexora::test::Fail(__LINE__);
  nexora::Headers<> ok_headers;
  if (!ok_headers.Add("content-type", "text/plain")) return nexora::test::Fail(__LINE__);
  if (!link.server.SubmitResponseHeaders(*right, nexora::StatusCode{404}, {}, true)) return nexora::test::Fail(__LINE__);
  if (!link.server.SubmitResponseHeaders(*left, nexora::StatusCode{200}, ok_headers, false))
    return nexora::test::Fail(__LINE__);
  constexpr std::array<std::uint8_t, 4> body{'p', 'i', 'n', 'g'};
  auto wrote = link.server.SubmitData(*left, body, true);
  if (!wrote || *wrote != body.size()) return nexora::test::Fail(__LINE__);
  link.client_events.clear();
  if (const int line = link.Pump()) return line;
  bool saw_404 = false;
  bool saw_200 = false;
  bool saw_body = false;
  for (const auto& event : link.client_events) {
    if (event.kind == nexora::Http2Event::Kind::kHeaders && event.stream_id == *right && event.status.AsU16() == 404) {
      saw_404 = true;
    }
    if (event.kind == nexora::Http2Event::Kind::kHeaders && event.stream_id == *left && event.status.AsU16() == 200) {
      saw_200 = event.headers.Get("content-type") == std::optional<std::string_view>{"text/plain"};
    }
    if (event.kind == nexora::Http2Event::Kind::kMessageComplete && event.stream_id == *left) {
      saw_body = event.data.size() == body.size() && event.data[0] == 'p';
    }
  }
  if (!saw_404 || !saw_200 || !saw_body) return nexora::test::Fail(__LINE__);
  return 0;
}

int GoawayDrain() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  auto keep = link.client.OpenStream();
  auto drop = link.client.OpenStream();
  if (!keep || !drop) return nexora::test::Fail(__LINE__);
  if (!link.client.SubmitRequestHeaders(*keep, nexora::Method::kGet, "https", "ex", "/keep", {}, false)) {
    return nexora::test::Fail(__LINE__);
  }
  if (!link.client.SubmitRequestHeaders(*drop, nexora::Method::kGet, "https", "ex", "/drop", {}, false)) {
    return nexora::test::Fail(__LINE__);
  }
  if (const int line = link.Pump()) return line;
  if (!link.server.SubmitResponseHeaders(*keep, nexora::StatusCode{200}, {}, true)) return nexora::test::Fail(__LINE__);
  if (!link.server.SubmitGoaway(*keep, nexora::Http2ErrorCode::kNoError)) return nexora::test::Fail(__LINE__);
  link.client_events.clear();
  if (const int line = link.Pump()) return line;
  bool kept = false;
  bool refused = false;
  bool goaway = false;
  for (const auto& event : link.client_events) {
    if (event.kind == nexora::Http2Event::Kind::kHeaders && event.stream_id == *keep && event.status.AsU16() == 200)
      kept = true;
    if (event.kind == nexora::Http2Event::Kind::kStreamReset && event.stream_id == *drop &&
        event.error_code == nexora::Http2ErrorCode::kRefusedStream) {
      refused = true;
    }
    if (event.kind == nexora::Http2Event::Kind::kGoaway && event.last_stream_id == *keep) goaway = true;
  }
  if (!kept || !refused || !goaway || link.client.OpenStream()) return nexora::test::Fail(__LINE__);
  constexpr std::array<std::uint8_t, 3> block{0x82, 0x86, 0x84};
  std::array<std::uint8_t, 32> frame{};
  auto size = nexora::EncodeFrame(nexora::Http2FrameType::kHeaders, 0x5, *drop + 2U, block, frame);
  if (!size || !link.server.FeedBytes(std::span<const std::uint8_t>(frame.data(), *size))) return nexora::test::Fail(__LINE__);
  const auto code = nexora::test::PayloadCode(link.server, nexora::Http2FrameType::kRstStream);
  if (code != std::to_underlying(nexora::Http2ErrorCode::kRefusedStream)) return nexora::test::Fail(__LINE__);
  return 0;
}

int ChunkedTrailers() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  auto stream = link.client.OpenStream();
  if (!stream || !link.client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", "ex", "/s", {}, false)) {
    return nexora::test::Fail(__LINE__);
  }
  constexpr std::array<std::uint8_t, 3> chunk{9, 8, 7};
  for (int i = 0; i < 3; ++i) {
    auto wrote = link.client.SubmitData(*stream, chunk, false);
    if (!wrote || *wrote != chunk.size()) return nexora::test::Fail(__LINE__);
  }
  nexora::Headers<> trailers;
  if (!trailers.Add("x-done", "1") || !link.client.SubmitTrailers(*stream, trailers)) return nexora::test::Fail(__LINE__);
  link.server_events.clear();
  if (const int line = link.Pump()) return line;
  constexpr std::array<nexora::Http2Event::Kind, 6> expect{
      nexora::Http2Event::Kind::kHeaders, nexora::Http2Event::Kind::kData,     nexora::Http2Event::Kind::kData,
      nexora::Http2Event::Kind::kData,    nexora::Http2Event::Kind::kTrailers, nexora::Http2Event::Kind::kMessageComplete};
  std::size_t index = 0;
  for (const auto& event : link.server_events) {
    if (event.stream_id != *stream) continue;
    if (index >= 6 || event.kind != expect[index]) return nexora::test::Fail(__LINE__);
    ++index;
  }
  if (index != 6 || link.server_events.back().data.size() != 9) return nexora::test::Fail(__LINE__);
  return 0;
}

int FlowControlBounds() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  auto stream = link.client.OpenStream();
  if (!stream || !link.client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", "ex", "/f", {}, false)) {
    return nexora::test::Fail(__LINE__);
  }
  nexora::Http2Settings wide{};
  wide.enable_push = 0;
  wide.initial_window_size = 1000000;
  std::array<std::uint8_t, 36> settings_payload{};
  auto settings_size = nexora::EncodeSettingsPayload(wide, settings_payload);
  std::array<std::uint8_t, 64> settings_frame{};
  auto settings_frame_size =
      settings_size
          ? nexora::EncodeFrame(nexora::Http2FrameType::kSettings, 0, 0,
                                std::span<const std::uint8_t>(settings_payload.data(), *settings_size), settings_frame)
          : settings_size;
  if (!settings_frame_size ||
      !link.client.FeedBytes(std::span<const std::uint8_t>(settings_frame.data(), *settings_frame_size))) {
    return nexora::test::Fail(__LINE__);
  }
  std::vector<std::uint8_t> chunk(16384, 0x2a);
  int writes = 0;
  for (; writes < 8; ++writes) {
    auto wrote = link.client.SubmitData(*stream, chunk, false);
    if (!wrote) return nexora::test::Fail(__LINE__);
    if (*wrote == 0) break;
    link.client.ConsumeOutput(link.client.PendingOutput().size());
  }
  if (writes < 2 || link.client.ConnectionSendWindow() != 0) return nexora::test::Fail(__LINE__);
  if (!link.server.SubmitWindowUpdate(0, 1000)) return nexora::test::Fail(__LINE__);
  if (const int line = link.Pump()) return line;
  auto resumed = link.client.SubmitData(*stream, chunk, false);
  if (!resumed || *resumed != 1000) return nexora::test::Fail(__LINE__);
  nexora::test::Link overflow_link;
  if (const int line = overflow_link.Handshake()) return line;
  std::array<std::uint8_t, 4> increment{0x7f, 0xff, 0xff, 0xff};
  std::array<std::uint8_t, 16> update{};
  auto update_size = nexora::EncodeFrame(nexora::Http2FrameType::kWindowUpdate, 0, 0, increment, update);
  if (!update_size || overflow_link.client.FeedBytes(std::span<const std::uint8_t>(update.data(), *update_size))) {
    return nexora::test::Fail(__LINE__);
  }
  const auto overflow = nexora::test::PayloadCode(overflow_link.client, nexora::Http2FrameType::kGoaway);
  if (overflow != std::to_underlying(nexora::Http2ErrorCode::kFlowControlError)) return nexora::test::Fail(__LINE__);
  nexora::test::Link recv;
  if (const int line = recv.Handshake()) return line;
  auto inbound = recv.client.OpenStream();
  if (!inbound || !recv.client.SubmitRequestHeaders(*inbound, nexora::Method::kPost, "https", "ex", "/r", {}, false)) {
    return nexora::test::Fail(__LINE__);
  }
  if (const int line = recv.Pump()) return line;
  std::vector<std::uint8_t> data(16384, 0x7);
  std::vector<std::uint8_t> frame(16400);
  for (int i = 0; i < 4; ++i) {
    auto size = nexora::EncodeFrame(nexora::Http2FrameType::kData, 0, *inbound, data, frame);
    if (!size) return nexora::test::Fail(__LINE__);
    auto fed = recv.server.FeedBytes(std::span<const std::uint8_t>(frame.data(), *size));
    if (i < 3) {
      if (!fed) return nexora::test::Fail(__LINE__);
    } else if (fed) {
      return nexora::test::Fail(__LINE__);
    }
  }
  const auto flow = nexora::test::PayloadCode(recv.server, nexora::Http2FrameType::kGoaway);
  if (flow != std::to_underlying(nexora::Http2ErrorCode::kFlowControlError)) return nexora::test::Fail(__LINE__);
  return 0;
}

int Exchange(nexora::Http2Connection& client, nexora::Http2Connection& server, std::vector<std::uint8_t>& got, bool& saw_end) {
  for (int turn = 0; turn < 16; ++turn) {
    bool moved = false;
    const auto from_client = client.PendingOutput();
    if (!from_client.empty() || server.IsIngressPaused()) {
      const auto fed = server.FeedBytes(from_client);
      if (!fed.Ok()) {
        std::printf("server feed: %s\n", fed.ErrorValue().Message().data());
        return nexora::test::Fail(__LINE__);
      }
      if (fed.Consumed() > 0) {
        client.ConsumeOutput(fed.Consumed());
        moved = true;
      }
    }
    const auto from_server = server.PendingOutput();
    if (!from_server.empty() || client.IsIngressPaused()) {
      const auto fed = client.FeedBytes(from_server);
      if (!fed.Ok()) {
        std::printf("client feed: %s\n", fed.ErrorValue().Message().data());
        return nexora::test::Fail(__LINE__);
      }
      if (fed.Consumed() > 0) {
        server.ConsumeOutput(fed.Consumed());
        moved = true;
      }
    }
    while (const auto view = server.PeekEventView()) {
      if (view->kind == nexora::Http2Event::Kind::kData) {
        got.insert(got.end(), view->data.begin(), view->data.end());
        saw_end = saw_end || view->end_stream;
      }
      if (view->kind == nexora::Http2Event::Kind::kMessageComplete) {
        saw_end = saw_end || view->end_stream;
      }
      server.ConsumeEvent();
      moved = true;
    }
    while (client.PeekEventView()) {
      client.ConsumeEvent();
      moved = true;
    }
    if (!moved && !client.IsIngressPaused() && !server.IsIngressPaused()) {
      return 0;
    }
  }
  return nexora::test::Fail(__LINE__);
}

int StreamFourMebibytes() {
  constexpr std::size_t total = 4U * 1024U * 1024U;
  nexora::Http2Settings settings{};
  settings.initial_window_size = 0x7fffffffu;
  settings.max_frame_size = 131072;
  const nexora::Http2Limits limits{.io_buffer_bytes = 262144, .header_block_bytes = 65536, .coalesce_message_body = false};
  nexora::Http2Connection client(nexora::Http2Role::kClient, settings, limits);
  nexora::Http2Connection server(nexora::Http2Role::kServer, settings, limits);
  if (!client.InitiateHandshake() || !server.InitiateHandshake()) return nexora::test::Fail(__LINE__);
  std::vector<std::uint8_t> got;
  bool saw_end = false;
  if (const int line = Exchange(client, server, got, saw_end)) return line;
  if (!server.SubmitWindowUpdate(0, 0x1000000u)) return nexora::test::Fail(__LINE__);
  if (const int line = Exchange(client, server, got, saw_end)) return line;
  auto stream = client.OpenStream();
  if (!stream) return nexora::test::Fail(__LINE__);
  std::array<char, 16> digits{};
  const auto printed = std::to_chars(digits.data(), digits.data() + digits.size(), total);
  if (printed.ec != std::errc{}) return nexora::test::Fail(__LINE__);
  nexora::Headers<> headers;
  if (!headers.Add("content-length", std::string_view(digits.data(), printed.ptr))) return nexora::test::Fail(__LINE__);
  if (!client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", "ex", "/blob", headers, false)) {
    return nexora::test::Fail(__LINE__);
  }
  if (const int line = Exchange(client, server, got, saw_end)) return line;
  std::vector<std::uint8_t> payload(total);
  for (std::size_t i = 0; i < payload.size(); ++i) {
    payload[i] = static_cast<std::uint8_t>(i);
  }
  std::size_t off = 0;
  while (off < payload.size()) {
    auto wrote = client.SubmitData(*stream, std::span<const std::uint8_t>(payload.data() + off, payload.size() - off), true);
    if (!wrote || *wrote == 0) return nexora::test::Fail(__LINE__);
    off += *wrote;
    if (const int line = Exchange(client, server, got, saw_end)) return line;
  }
  if (!saw_end || got.size() != total) return nexora::test::Fail(__LINE__);
  for (std::size_t i = 0; i < total; ++i) {
    if (got[i] != static_cast<std::uint8_t>(i)) return nexora::test::Fail(__LINE__);
  }
  return 0;
}

int MismatchedBufferAndFrameLimits() {
  nexora::Http2Settings client_settings{};
  client_settings.max_frame_size = 131072;
  const nexora::Http2Limits client_limits{
      .io_buffer_bytes = 65536, .header_block_bytes = 65536, .coalesce_message_body = false};
  nexora::Http2Connection client(nexora::Http2Role::kClient, client_settings, client_limits);
  if (!client.InitiateHandshake()) return nexora::test::Fail(__LINE__);

  const auto init_wire = client.PendingOutput();
  if (init_wire.size() < nexora::kHttp2ClientPreface.size() + nexora::kHttp2FrameHeaderSize) {
    return nexora::test::Fail(__LINE__);
  }
  const auto frame_span = init_wire.subspan(nexora::kHttp2ClientPreface.size());
  auto hdr = nexora::DecodeFrameHeader(frame_span.first(nexora::kHttp2FrameHeaderSize));
  if (!hdr || hdr->type != nexora::Http2FrameType::kSettings ||
      frame_span.size() < nexora::kHttp2FrameHeaderSize + hdr->length) {
    return nexora::test::Fail(__LINE__);
  }
  auto advertised =
      nexora::ApplySettingsPayload(nexora::Http2Settings{}, frame_span.subspan(nexora::kHttp2FrameHeaderSize, hdr->length));
  if (!advertised || advertised->max_frame_size != 65527U) return nexora::test::Fail(__LINE__);

  nexora::Http2Settings server_settings{};
  server_settings.initial_window_size = 0x7fffffffU;
  server_settings.max_frame_size = 16777215U;
  const nexora::Http2Limits server_limits{
      .io_buffer_bytes = 16777224, .header_block_bytes = 65536, .coalesce_message_body = false};
  nexora::Http2Connection server(nexora::Http2Role::kServer, server_settings, server_limits);
  if (!server.InitiateHandshake()) return nexora::test::Fail(__LINE__);

  std::vector<std::uint8_t> got;
  bool saw_end = false;
  if (const int line = Exchange(client, server, got, saw_end)) return line;
  if (!server.SubmitWindowUpdate(0, 0x1000000U)) return nexora::test::Fail(__LINE__);
  if (const int line = Exchange(client, server, got, saw_end)) return line;

  auto stream = client.OpenStream();
  if (!stream || !client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", "ex", "/cap", {}, false)) {
    return nexora::test::Fail(__LINE__);
  }
  if (const int line = Exchange(client, server, got, saw_end)) return line;

  constexpr std::size_t total = 200U * 1024U;
  std::vector<std::uint8_t> payload(total);
  for (std::size_t i = 0; i < payload.size(); ++i) {
    payload[i] = static_cast<std::uint8_t>((i * 7U) & 0xffU);
  }
  std::size_t off = 0;
  std::size_t chunks = 0;
  while (off < payload.size()) {
    auto wrote = client.SubmitData(*stream, std::span<const std::uint8_t>(payload.data() + off, payload.size() - off), true);
    if (!wrote || *wrote == 0 || *wrote > 65527U) return nexora::test::Fail(__LINE__);
    off += *wrote;
    ++chunks;
    if (off < payload.size()) {
      auto blocked =
          client.SubmitData(*stream, std::span<const std::uint8_t>(payload.data() + off, payload.size() - off), true);
      if (!blocked || *blocked != 0) return nexora::test::Fail(__LINE__);
    }
    if (const int line = Exchange(client, server, got, saw_end)) return line;
  }
  if (chunks < 4 || !saw_end || got != payload) return nexora::test::Fail(__LINE__);
  return 0;
}

int WideHeaderBlock() {
  const nexora::Http2Limits limits{.io_buffer_bytes = 131072, .header_block_bytes = 131072};
  nexora::Http2Connection client(nexora::Http2Role::kClient, {}, limits);
  nexora::Http2Connection server(nexora::Http2Role::kServer, {}, limits);
  if (!client.InitiateHandshake() || !server.InitiateHandshake()) return nexora::test::Fail(__LINE__);
  std::vector<std::uint8_t> ignored;
  bool saw_end = false;
  if (const int line = Exchange(client, server, ignored, saw_end)) return line;
  const std::string bulky(8192, '~');
  nexora::Headers<> headers;
  for (int i = 0; i < 9; ++i) {
    const std::array<char, 4> name{'x', '-', 'm', static_cast<char>('0' + i)};
    if (!headers.Add(std::string_view(name.data(), name.size()), bulky)) return nexora::test::Fail(__LINE__);
  }
  auto stream = client.OpenStream();
  if (!stream || !client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", "ex", "/meta", headers, true)) {
    return nexora::test::Fail(__LINE__);
  }
  bool saw = false;
  for (int turn = 0; turn < 8; ++turn) {
    bool moved = false;
    const auto from_client = client.PendingOutput();
    if (!from_client.empty()) {
      if (!server.FeedBytes(from_client)) return nexora::test::Fail(__LINE__);
      client.ConsumeOutput(from_client.size());
      moved = true;
    }
    const auto from_server = server.PendingOutput();
    if (!from_server.empty()) {
      if (!client.FeedBytes(from_server)) return nexora::test::Fail(__LINE__);
      server.ConsumeOutput(from_server.size());
      moved = true;
    }
    while (const auto view = server.PeekEventView()) {
      if (view->kind == nexora::Http2Event::Kind::kHeaders && view->headers != nullptr) {
        saw = true;
        for (int i = 0; i < 9; ++i) {
          const std::array<char, 4> name{'x', '-', 'm', static_cast<char>('0' + i)};
          if (view->headers->Get(std::string_view(name.data(), name.size())) != std::optional<std::string_view>{bulky}) {
            return nexora::test::Fail(__LINE__);
          }
        }
      }
      server.ConsumeEvent();
    }
    while (client.PeekEventView()) client.ConsumeEvent();
    if (!moved) break;
  }
  if (!saw) return nexora::test::Fail(__LINE__);
  return 0;
}

int DiagnosticCounts() {
  nexora::test::Link link;
  if (const int line = link.Handshake()) return line;
  if (link.client.ActiveStreamCount() != 0 || link.client.WindowUpdateCount() != 0 || link.client.ResetStreamCount() != 0) {
    return nexora::test::Fail(__LINE__);
  }
  auto stream = link.client.OpenStream();
  auto extra = link.client.OpenStream();
  if (!stream || !extra || link.client.ActiveStreamCount() != 2) return nexora::test::Fail(__LINE__);
  if (!link.server.SubmitWindowUpdate(0, 1024)) return nexora::test::Fail(__LINE__);
  if (link.server.WindowUpdateCount() != 1) return nexora::test::Fail(__LINE__);
  if (const int line = link.Pump()) return line;
  if (link.client.WindowUpdateCount() != 1) return nexora::test::Fail(__LINE__);
  if (!link.client.SubmitRequestHeaders(*stream, nexora::Method::kGet, "https", "ex", "/c", {}, false)) {
    return nexora::test::Fail(__LINE__);
  }
  if (const int line = link.Pump()) return line;
  if (link.server.ActiveStreamCount() != 1 || link.server.ResetStreamCount() != 0) return nexora::test::Fail(__LINE__);
  if (!link.server.SubmitRstStream(*stream, nexora::Http2ErrorCode::kCancel)) return nexora::test::Fail(__LINE__);
  if (link.server.ResetStreamCount() != 1) return nexora::test::Fail(__LINE__);
  if (const int line = link.Pump()) return line;
  if (link.client.ResetStreamCount() != 1) return nexora::test::Fail(__LINE__);
  return 0;
}

}  // namespace

int main() {
  if (const int line = MultiplexTwoStreams()) return line;
  if (const int line = GoawayDrain()) return line;
  if (const int line = ChunkedTrailers()) return line;
  if (const int line = FlowControlBounds()) return line;
  if (const int line = StreamFourMebibytes()) return line;
  if (const int line = MismatchedBufferAndFrameLimits()) return line;
  if (const int line = WideHeaderBlock()) return line;
  if (const int line = DiagnosticCounts()) return line;
  return 0;
}
