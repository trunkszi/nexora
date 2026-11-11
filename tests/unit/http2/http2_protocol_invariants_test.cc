#include "link.hpp"

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wmismatched-new-delete"
#endif

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <span>
#include <string_view>
#include <vector>

std::atomic<std::size_t> g_allocs{0};
std::atomic<bool> g_arm{false};

void* operator new(std::size_t sz) {
  if (g_arm.load(std::memory_order_relaxed)) g_allocs.fetch_add(1, std::memory_order_relaxed);
  if (sz == 0) sz = 1;
  if (void* memory = std::malloc(sz)) return memory;
  std::abort();
}

void* operator new(std::size_t sz, std::align_val_t al) {
  if (g_arm.load(std::memory_order_relaxed)) g_allocs.fetch_add(1, std::memory_order_relaxed);
  if (sz == 0) sz = 1;
  auto align = static_cast<std::size_t>(al);
  if (align < sizeof(void*)) align = sizeof(void*);
  void* memory = nullptr;
  if (posix_memalign(&memory, align, sz) != 0) std::abort();
  return memory;
}

void* operator new[](std::size_t sz) { return ::operator new(sz); }
void* operator new[](std::size_t sz, std::align_val_t al) { return ::operator new(sz, al); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }

namespace {

int Fail(int line) {
  g_arm.store(false, std::memory_order_relaxed);
  std::fprintf(stderr, "fail %d allocs %zu\n", line, g_allocs.load(std::memory_order_relaxed));
  return line;
}

bool Proto(const nexora::Error& err, nexora::ProtoErrorCode code) {
  return err.domain == nexora::ErrorDomain::kProto && err.code == static_cast<std::int32_t>(std::to_underlying(code));
}

bool Proto(const nexora::Http2Read& read, nexora::ProtoErrorCode code) { return !read && Proto(read.ErrorValue(), code); }

void Drain(nexora::Http2Connection& connection) {
  while (connection.PollEvent()) {
  }
}

int PumpDir(nexora::Http2Connection& src, nexora::Http2Connection& dst, bool& moved) {
  const auto out = src.PendingOutput();
  if (out.empty() && !dst.IsIngressPaused()) return 0;
  const auto fed = dst.FeedBytes(out);
  if (!fed.Ok()) return Fail(__LINE__);
  if (fed.Consumed() > 0) {
    src.ConsumeOutput(fed.Consumed());
    moved = true;
  }
  return 0;
}

int Exchange(nexora::Http2Connection& left, nexora::Http2Connection& right) {
  for (int turn = 0; turn < 16; ++turn) {
    bool moved = false;
    if (const int line = PumpDir(left, right, moved)) return line;
    if (const int line = PumpDir(right, left, moved)) return line;
    if (!moved && !left.IsIngressPaused() && !right.IsIngressPaused()) return 0;
  }
  return Fail(__LINE__);
}

int Handshake(nexora::Http2Connection& client, nexora::Http2Connection& server) {
  if (!client.InitiateHandshake() || !server.InitiateHandshake()) return Fail(__LINE__);
  if (const int line = Exchange(client, server)) return line;
  Drain(client);
  Drain(server);
  return 0;
}

std::vector<std::uint8_t> Frame(nexora::Http2FrameType type, std::uint8_t flags, std::uint32_t stream,
                                std::span<const std::uint8_t> payload) {
  std::vector<std::uint8_t> out(nexora::kHttp2FrameHeaderSize + payload.size());
  auto wrote = nexora::EncodeFrame(type, flags, stream, payload, out);
  out.resize(wrote ? *wrote : 0uz);
  return out;
}

std::size_t FillPings(nexora::Http2Connection& connection) {
  while (connection.SubmitPing(1)) {
  }
  return connection.PendingOutput().size();
}

int ZeroAllocWholeRpc() {
  nexora::Http2Settings settings{};
  settings.initial_window_size = 0x7fffffffU;
  nexora::Http2Limits limits{};
  limits.coalesce_message_body = false;
  nexora::Http2Connection client(nexora::Http2Role::kClient, settings, limits);
  nexora::Http2Connection server(nexora::Http2Role::kServer, settings, limits);
  if (const int line = Handshake(client, server)) return line;
  if (!client.SubmitWindowUpdate(0, 0x1000000U) || !server.SubmitWindowUpdate(0, 0x1000000U)) return Fail(__LINE__);
  if (const int line = Exchange(client, server)) return line;
  Drain(client);
  Drain(server);

  constexpr std::string_view rpc_path = "/greptime.v1.GreptimeDatabase/HandleRequests";
  constexpr std::string_view rpc_authority = "ingest-node-01.internal.local:4001";
  nexora::Headers<> req_headers;
  nexora::Headers<> resp_headers;
  nexora::Headers<> trailers;
  if (!req_headers.Add("content-type", "application/grpc+proto") || !req_headers.Add("te", "trailers") ||
      !resp_headers.Add("content-type", "application/grpc+proto") || !trailers.Add("grpc-status", "0") ||
      !trailers.Add("grpc-message", "ok")) {
    return Fail(__LINE__);
  }

  std::array<nexora::Http2Event, 8> held{};
  const auto capacity = server.DataArenaCapacity();
  g_allocs.store(0, std::memory_order_relaxed);
  g_arm.store(true, std::memory_order_relaxed);

  for (int iter = 0; iter < 70; ++iter) {
    auto stream = client.OpenStream();
    if (!stream) return Fail(__LINE__);
    if (!client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", rpc_authority, rpc_path, req_headers, false)) {
      return Fail(__LINE__);
    }
    const std::array<std::uint8_t, 8> chunk_a{static_cast<std::uint8_t>(iter), 1, 2, 3, 4, 5, 6, 7};
    const std::array<std::uint8_t, 8> chunk_b{static_cast<std::uint8_t>(iter + 1), 8, 9, 10, 11, 12, 13, 14};
    if (client.SubmitData(*stream, chunk_a, false) != chunk_a.size()) return Fail(__LINE__);
    if (client.SubmitData(*stream, chunk_b, false) != chunk_b.size()) return Fail(__LINE__);
    if (!client.SubmitTrailers(*stream, trailers)) return Fail(__LINE__);

    const auto up = client.PendingOutput();
    const auto server_fed = server.FeedBytes(up);
    client.ConsumeOutput(up.size());
    if (!server_fed || *server_fed != up.size()) return Fail(__LINE__);

    std::size_t n = 0;
    while (auto ev = server.PollEvent()) {
      if (n >= held.size()) return Fail(__LINE__);
      held[n++] = std::move(*ev);
    }
    if (n != 5 || held[0].path != rpc_path || held[0].authority != rpc_authority || held[1].Payload()[0] != chunk_a[0] ||
        held[1].flow_control_bytes != chunk_a.size() || held[2].Payload()[0] != chunk_b[0] ||
        held[2].flow_control_bytes != chunk_b.size() || std::to_integer<std::uint8_t>(held[2].PayloadBytes()[1]) != 8U ||
        held[3].headers.Get("grpc-status") != std::optional<std::string_view>{"0"}) {
      return Fail(__LINE__);
    }

    if (!server.SubmitResponseHeaders(*stream, nexora::StatusCode{200}, resp_headers, false)) return Fail(__LINE__);
    if (server.SubmitData(*stream, chunk_b, false) != chunk_b.size()) return Fail(__LINE__);
    if (server.SubmitData(*stream, chunk_a, false) != chunk_a.size()) return Fail(__LINE__);
    if (!server.SubmitTrailers(*stream, trailers)) return Fail(__LINE__);

    const auto down = server.PendingOutput();
    const auto client_fed = client.FeedBytes(down);
    server.ConsumeOutput(down.size());
    if (!client_fed || *client_fed != down.size()) return Fail(__LINE__);

    n = 0;
    while (auto ev = client.PollEvent()) {
      if (n >= held.size()) return Fail(__LINE__);
      held[n++] = std::move(*ev);
    }
    if (n != 5 || held[0].status.Code() != 200 || held[1].Payload()[0] != chunk_b[0] || held[2].Payload()[0] != chunk_a[0] ||
        held[4].kind != nexora::Http2Event::Kind::kMessageComplete) {
      return Fail(__LINE__);
    }
  }

  auto ps = client.OpenStream();
  if (!ps || !client.SubmitRequestHeaders(*ps, nexora::Method::kPost, "https", rpc_authority, rpc_path, req_headers, false))
    return Fail(__LINE__);
  constexpr std::array<std::uint8_t, 9> padded_payload{5, 0xaa, 0xbb, 0xcc, 0, 0, 0, 0, 0};
  std::array<std::uint8_t, 18> padded_wire{};
  if (nexora::EncodeFrame(nexora::Http2FrameType::kData, std::to_underlying(nexora::Http2FrameFlags::kPadded), *ps,
                          padded_payload, padded_wire) != padded_wire.size() ||
      !server.FeedBytes(client.PendingOutput()) || (client.ConsumeOutput(client.PendingOutput().size()), false) ||
      !server.FeedBytes(padded_wire) || !server.PollEvent())
    return Fail(__LINE__);
  const auto peeked = server.PeekEventView();
  auto padded_ev = server.PollEvent();
  if (!peeked || peeked->flow_control_bytes != padded_payload.size() || !padded_ev || padded_ev->Payload().size() != 3U ||
      padded_ev->Payload()[0] != 0xaaU || padded_ev->flow_control_bytes != padded_payload.size() || padded_ev->end_stream)
    return Fail(__LINE__);
  constexpr std::array<std::uint8_t, 6> fin_body{1, 2, 3, 4, 5, 6};
  if (client.SubmitData(*ps, fin_body, true) != fin_body.size() || !server.FeedBytes(client.PendingOutput()))
    return Fail(__LINE__);
  client.ConsumeOutput(client.PendingOutput().size());
  auto fin_ev = server.PollEvent();
  auto done_ev = server.PollEvent();
  if (!fin_ev || !fin_ev->end_stream || fin_ev->flow_control_bytes != fin_body.size() || !done_ev ||
      done_ev->kind != nexora::Http2Event::Kind::kMessageComplete || done_ev->flow_control_bytes != 0U)
    return Fail(__LINE__);
  if (!server.SubmitResponseHeaders(*ps, nexora::StatusCode{200}, resp_headers, false) ||
      server.SubmitData(*ps, fin_body, true) != fin_body.size() || !client.FeedBytes(server.PendingOutput()))
    return Fail(__LINE__);
  server.ConsumeOutput(server.PendingOutput().size());
  if (!client.PollEvent()) return Fail(__LINE__);
  auto c_fin = client.PollEvent();
  auto c_done = client.PollEvent();
  if (!c_fin || !c_fin->end_stream || c_fin->flow_control_bytes != fin_body.size() || !c_done ||
      c_done->kind != nexora::Http2Event::Kind::kMessageComplete)
    return Fail(__LINE__);

  const auto allocs = g_allocs.load(std::memory_order_relaxed);
  g_arm.store(false, std::memory_order_relaxed);
  if (allocs != 0 || server.DataArenaCapacity() != capacity || server.DataArenaUsed() != fin_body.size()) return Fail(__LINE__);
  return 0;
}

int BoundaryPing() {
  nexora::Http2Connection client(nexora::Http2Role::kClient);
  nexora::Http2Connection server(nexora::Http2Role::kServer);
  if (const int line = Handshake(client, server)) return line;
  const auto full = FillPings(client);
  auto failed = client.SubmitPing(2);
  if (failed || client.PendingOutput().size() != full || !Proto(failed.error(), nexora::ProtoErrorCode::kBufferOverflow)) {
    return Fail(__LINE__);
  }
  int spins = 0;
  while (!client.SubmitPing(3)) {
    client.ConsumeOutput(1);
    if (++spins > 20) return Fail(__LINE__);
  }
  if (client.PendingOutput().size() != full - static_cast<std::size_t>(spins) + 17) return Fail(__LINE__);
  return 0;
}

int BoundaryControl(bool reset) {
  nexora::Http2Connection client(nexora::Http2Role::kClient);
  nexora::Http2Connection server(nexora::Http2Role::kServer);
  if (const int line = Handshake(client, server)) return line;
  auto stream = client.OpenStream();
  if (!stream || !client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", "ex", "/", {}, false)) {
    return Fail(__LINE__);
  }
  client.ConsumeOutput(client.PendingOutput().size());
  const auto full = FillPings(client);
  nexora::Result<void> failed =
      reset ? client.SubmitRstStream(*stream, nexora::Http2ErrorCode::kCancel) : client.SubmitWindowUpdate(*stream, 1);
  if (failed || client.PendingOutput().size() != full || !Proto(failed.error(), nexora::ProtoErrorCode::kBufferOverflow)) {
    return Fail(__LINE__);
  }
  int spins = 0;
  while (true) {
    client.ConsumeOutput(1);
    ++spins;
    failed = reset ? client.SubmitRstStream(*stream, nexora::Http2ErrorCode::kCancel) : client.SubmitWindowUpdate(*stream, 1);
    if (failed) break;
    if (spins > 20 || client.PendingOutput().size() != full - static_cast<std::size_t>(spins)) return Fail(__LINE__);
  }
  if (client.PendingOutput().size() != full - static_cast<std::size_t>(spins) + 13) return Fail(__LINE__);
  return 0;
}

int BoundaryInboundAck(bool ping_frame) {
  nexora::Http2Connection client(nexora::Http2Role::kClient);
  nexora::Http2Connection server(nexora::Http2Role::kServer);
  if (const int line = Handshake(client, server)) return line;
  const auto full = FillPings(client);
  constexpr std::array<std::uint8_t, 8> opaque{1, 2, 3, 4, 5, 6, 7, 8};
  const auto wire =
      ping_frame ? Frame(nexora::Http2FrameType::kPing, 0, 0, opaque) : Frame(nexora::Http2FrameType::kSettings, 0, 0, {});
  const std::size_t ack_bytes = ping_frame ? 17uz : nexora::kHttp2FrameHeaderSize;
  auto fed = client.FeedBytes(wire);
  if (!fed.Ok() || *fed != wire.size() || !client.IsIngressPaused() || static_cast<bool>(fed) ||
      !Proto(fed, nexora::ProtoErrorCode::kBufferOverflow) || client.PendingOutput().size() != full) {
    return Fail(__LINE__);
  }
  int spins = 0;
  while (true) {
    client.ConsumeOutput(1);
    ++spins;
    auto resumed = client.FeedBytes({});
    if (!resumed.Ok()) return Fail(__LINE__);
    if (!client.IsIngressPaused()) {
      if (!resumed) return Fail(__LINE__);
      break;
    }
    if (spins > 25 || client.PendingOutput().size() != full - static_cast<std::size_t>(spins)) return Fail(__LINE__);
  }
  if (client.PendingOutput().size() != full - static_cast<std::size_t>(spins) + ack_bytes) return Fail(__LINE__);
  return 0;
}

int FirstSettings(nexora::Http2Role role) {
  const auto ping = Frame(nexora::Http2FrameType::kPing, 0, 0, std::array<std::uint8_t, 8>{});
  const auto ack = Frame(nexora::Http2FrameType::kSettings, std::to_underlying(nexora::Http2FrameFlags::kAck), 0, {});
  const std::vector<std::uint8_t> preface(nexora::kHttp2ClientPreface.begin(), nexora::kHttp2ClientPreface.end());
  for (const auto& frame : {ping, ack}) {
    nexora::Http2Connection connection(role);
    if (!connection.InitiateHandshake()) return Fail(__LINE__);
    connection.ConsumeOutput(connection.PendingOutput().size());
    if (role == nexora::Http2Role::kServer && !connection.FeedBytes(preface)) return Fail(__LINE__);
    auto fed = connection.FeedBytes(frame);
    if (!Proto(fed, nexora::ProtoErrorCode::kHttp2ProtocolError)) return Fail(__LINE__);
  }
  nexora::Http2Connection server(nexora::Http2Role::kServer);
  if (!server.InitiateHandshake()) return Fail(__LINE__);
  server.ConsumeOutput(server.PendingOutput().size());
  if (!server.FeedBytes(preface)) return Fail(__LINE__);
  const auto settings = Frame(nexora::Http2FrameType::kSettings, 0, 0, {});
  if (!server.FeedBytes(settings) || server.PendingOutput().size() < nexora::kHttp2FrameHeaderSize) return Fail(__LINE__);
  return 0;
}

int FragmentedPreface() {
  nexora::Http2Connection client(nexora::Http2Role::kClient);
  nexora::Http2Connection server(nexora::Http2Role::kServer);
  if (!client.InitiateHandshake() || !server.InitiateHandshake()) return Fail(__LINE__);
  std::vector<std::uint8_t> bytes(client.PendingOutput().begin(), client.PendingOutput().end());
  client.ConsumeOutput(bytes.size());
  for (std::uint8_t byte : bytes) {
    if (!server.FeedBytes(std::span<const std::uint8_t>(&byte, 1))) return Fail(__LINE__);
  }
  bytes.assign(server.PendingOutput().begin(), server.PendingOutput().end());
  server.ConsumeOutput(bytes.size());
  for (std::uint8_t byte : bytes) {
    if (!client.FeedBytes(std::span<const std::uint8_t>(&byte, 1))) return Fail(__LINE__);
  }
  Drain(client);
  Drain(server);
  if (!client.SubmitPing(9) || !server.SubmitPing(9)) return Fail(__LINE__);
  return Exchange(client, server);
}

int Whitespace() {
  nexora::test::Link link;
  if (link.Handshake()) return Fail(__LINE__);
  auto stream = link.client.OpenStream();
  if (!stream) return Fail(__LINE__);
  constexpr std::array<std::string_view, 4> bad{" a", "a ", "\ta", "a\t"};
  for (const auto value : bad) {
    nexora::Headers<> headers;
    if (!headers.Add("x-b", value)) return Fail(__LINE__);
    auto sent = link.client.SubmitRequestHeaders(*stream, nexora::Method::kGet, "https", "ex", "/", headers, false);
    if (sent || !Proto(sent.error(), nexora::ProtoErrorCode::kHttp2ProtocolError)) return Fail(__LINE__);
  }
  nexora::Headers<> spaced;
  if (!spaced.Add("x-b", "a b") ||
      !link.client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", "ex", "/", spaced, false)) {
    return Fail(__LINE__);
  }
  nexora::Headers<> trailers;
  if (!trailers.Add("x-t", " z")) return Fail(__LINE__);
  auto trailed = link.client.SubmitTrailers(*stream, trailers);
  if (trailed || !Proto(trailed.error(), nexora::ProtoErrorCode::kHttp2ProtocolError)) return Fail(__LINE__);
  if (const int line = link.Pump()) return Fail(line);
  bool saw = false;
  for (const auto& event : link.server_events) {
    if (event.kind == nexora::Http2Event::Kind::kHeaders &&
        event.headers.Get("x-b") == std::optional<std::string_view>{"a b"}) {
      saw = true;
    }
  }
  if (!saw) return Fail(__LINE__);

  auto encoded_for = [](std::uint32_t id, std::string_view value) {
    nexora::HpackEncoder encoder;
    std::array<nexora::HeaderField, 1> fields{};
    if (!fields[0].name.TryAssign("x-t") || !fields[0].value.TryAssign(value)) return std::vector<std::uint8_t>{};
    std::array<std::uint8_t, 64> block{};
    auto size = encoder.Encode(fields, block);
    if (!size) return std::vector<std::uint8_t>{};
    const auto flags = static_cast<std::uint8_t>(std::to_underlying(nexora::Http2FrameFlags::kEndHeaders) |
                                                 std::to_underlying(nexora::Http2FrameFlags::kEndStream));
    return Frame(nexora::Http2FrameType::kHeaders, flags, id, std::span<const std::uint8_t>(block.data(), *size));
  };
  auto bad_fed = link.server.FeedBytes(encoded_for(*stream, " a"));
  if (!Proto(bad_fed, nexora::ProtoErrorCode::kHttp2ProtocolError)) return Fail(__LINE__);
  nexora::test::Link good;
  if (good.Handshake()) return Fail(__LINE__);
  auto other = good.client.OpenStream();
  if (!other || !good.client.SubmitRequestHeaders(*other, nexora::Method::kPost, "https", "ex", "/", {}, false) ||
      good.Pump()) {
    return Fail(__LINE__);
  }
  if (!good.server.FeedBytes(encoded_for(*other, "a b"))) return Fail(__LINE__);
  bool trailer_ok = false;
  while (auto event = good.server.PollEvent()) {
    if (event->kind == nexora::Http2Event::Kind::kTrailers &&
        event->headers.Get("x-t") == std::optional<std::string_view>{"a b"}) {
      trailer_ok = true;
    }
  }
  if (!trailer_ok) return Fail(__LINE__);
  return 0;
}

int BackpressureAndSlabBatchLifetime() {
  nexora::Http2Limits limits{};
  limits.io_buffer_bytes = nexora::kHttp2DefaultMaxFrameSize + nexora::kHttp2FrameHeaderSize;
  limits.coalesce_message_body = false;
  nexora::Http2Connection client(nexora::Http2Role::kClient, {}, limits);
  nexora::Http2Connection server(nexora::Http2Role::kServer, {}, limits);
  if (const int line = Handshake(client, server)) return line;

  auto stream = client.OpenStream();
  if (!stream || !client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", "ex", "/stream", {}, false)) {
    return Fail(__LINE__);
  }
  if (const int line = Exchange(client, server)) return line;
  Drain(client);
  Drain(server);

  std::vector<std::uint8_t> burst;
  for (std::size_t i = 0; i < 85; ++i) {
    std::array<std::uint8_t, 16> chunk{};
    chunk.fill(static_cast<std::uint8_t>(0x20U + i));
    auto f = Frame(nexora::Http2FrameType::kData, 0, *stream, chunk);
    burst.insert(burst.end(), f.begin(), f.end());
  }

  auto fed = server.FeedBytes(burst);
  if (!fed.Ok() || !server.IsIngressPaused() || static_cast<bool>(fed) ||
      !Proto(fed, nexora::ProtoErrorCode::kBufferOverflow)) {
    return Fail(__LINE__);
  }

  std::vector<nexora::Http2Event> batch;
  while (auto ev = server.PollEvent()) {
    batch.push_back(std::move(*ev));
  }
  if (batch.size() != 80 || server.DataArenaUsed() != 80U * 16U) return Fail(__LINE__);
  for (std::size_t i = 0; i < batch.size(); ++i) {
    const auto expected = static_cast<std::uint8_t>(0x20U + i);
    if (batch[i].Payload().size() != 16 || batch[i].Payload()[0] != expected || batch[i].Payload()[15] != expected) {
      return Fail(__LINE__);
    }
  }
  batch.clear();

  std::span<const std::uint8_t> rem(burst.data() + fed.Consumed(), burst.size() - fed.Consumed());
  std::size_t tail_seen = 0;
  while (!rem.empty() || server.IsIngressPaused()) {
    auto next = server.FeedBytes(rem);
    if (!next.Ok()) return Fail(__LINE__);
    rem = rem.subspan(next.Consumed());
    while (auto ev = server.PollEvent()) {
      const auto expected = static_cast<std::uint8_t>(0x20U + 80U + tail_seen);
      if (ev->Payload().size() != 16 || ev->Payload()[0] != expected) return Fail(__LINE__);
      ++tail_seen;
    }
  }
  if (tail_seen != 5) return Fail(__LINE__);
  return 0;
}

int ResetFlow() {
  nexora::test::Link link;
  if (link.Handshake()) return Fail(__LINE__);
  auto stream = link.client.OpenStream();
  if (!stream || !link.client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", "ex", "/w", {}, false)) {
    return Fail(__LINE__);
  }
  std::vector<std::uint8_t> chunk(16384, 0x11);
  auto wrote = link.client.SubmitData(*stream, chunk, false);
  if (!wrote || *wrote != chunk.size() || link.Pump()) return Fail(__LINE__);
  if (link.server.ConnectionRecvWindow() != 65535 - 16384) return Fail(__LINE__);
  if (!link.server.SubmitRstStream(*stream, nexora::Http2ErrorCode::kCancel)) return Fail(__LINE__);
  for (int i = 0; i < 2; ++i) {
    auto more = link.client.SubmitData(*stream, chunk, false);
    if (!more || *more != chunk.size()) return Fail(__LINE__);
    auto fed = link.server.FeedBytes(link.client.PendingOutput());
    link.client.ConsumeOutput(link.client.PendingOutput().size());
    if (!fed) return Fail(__LINE__);
  }
  if (link.server.ConnectionRecvWindow() != 65535 - 3 * 16384) return Fail(__LINE__);
  auto overflow = Frame(nexora::Http2FrameType::kData, 0, *stream, chunk);
  auto denied = link.server.FeedBytes(overflow);
  if (!Proto(denied, nexora::ProtoErrorCode::kHttp2FlowControlError)) return Fail(__LINE__);
  return 0;
}

int EvictedResetStreamSafety() {
  nexora::Http2Connection client(nexora::Http2Role::kClient);
  nexora::Http2Connection server(nexora::Http2Role::kServer);
  if (const int line = Handshake(client, server)) return line;

  std::uint32_t active_stream = 0;
  for (int i = 0; i < 66; ++i) {
    auto stream = client.OpenStream();
    if (!stream || !client.SubmitRequestHeaders(*stream, nexora::Method::kGet, "https", "ex", "/", {}, true)) {
      return Fail(__LINE__);
    }
    if (i < 65) {
      if (!client.SubmitRstStream(*stream, nexora::Http2ErrorCode::kCancel)) return Fail(__LINE__);
    } else {
      active_stream = *stream;
    }
    client.ConsumeOutput(client.PendingOutput().size());
  }

  nexora::HpackEncoder peer_hpack;
  std::array<nexora::HeaderField, 2> resp_fields{};
  if (!resp_fields[0].name.TryAssign(":status") || !resp_fields[0].value.TryAssign("200") ||
      !resp_fields[1].name.TryAssign("x-shared-trace") || !resp_fields[1].value.TryAssign("trace-from-evicted-stream-0001")) {
    return Fail(__LINE__);
  }
  std::array<std::uint8_t, 128> block1{};
  auto len1 = peer_hpack.Encode(resp_fields, block1);
  std::array<nexora::HeaderField, 1> trailer_fields{};
  if (!trailer_fields[0].name.TryAssign("grpc-status") || !trailer_fields[0].value.TryAssign("0")) return Fail(__LINE__);
  std::array<std::uint8_t, 64> tblock{};
  auto tlen = peer_hpack.Encode(trailer_fields, tblock);
  std::array<std::uint8_t, 64> block_active{};
  auto len_active = peer_hpack.Encode(resp_fields, block_active);
  if (!len1 || !tlen || !len_active || *len_active >= *len1) return Fail(__LINE__);

  const auto end_hdr = std::to_underlying(nexora::Http2FrameFlags::kEndHeaders);
  const auto end_both = static_cast<std::uint8_t>(end_hdr | std::to_underlying(nexora::Http2FrameFlags::kEndStream));
  std::vector<std::uint8_t> body(1024, 0x42);

  if (!client.FeedBytes(Frame(nexora::Http2FrameType::kHeaders, end_hdr, 1, std::span(block1.data(), *len1))) ||
      !client.FeedBytes(Frame(nexora::Http2FrameType::kData, 0, 1, body)) ||
      !client.FeedBytes(Frame(nexora::Http2FrameType::kHeaders, end_both, 1, std::span(tblock.data(), *tlen))) ||
      !client.FeedBytes(Frame(nexora::Http2FrameType::kWindowUpdate, 0, 1, std::array<std::uint8_t, 4>{0, 0, 0, 1})) ||
      !client.FeedBytes(Frame(nexora::Http2FrameType::kRstStream, 0, 1, std::array<std::uint8_t, 4>{}))) {
    return Fail(__LINE__);
  }
  if (client.ConnectionRecvWindow() != 65535 - 1024 || client.PollEvent().has_value()) return Fail(__LINE__);

  if (!client.FeedBytes(
          Frame(nexora::Http2FrameType::kHeaders, end_both, active_stream, std::span(block_active.data(), *len_active)))) {
    return Fail(__LINE__);
  }
  auto ev = client.PollEvent();
  if (!ev || ev->stream_id != active_stream ||
      ev->headers.Get("x-shared-trace") != std::optional<std::string_view>{"trace-from-evicted-stream-0001"}) {
    return Fail(__LINE__);
  }
  Drain(client);

  const auto idle = Frame(nexora::Http2FrameType::kWindowUpdate, 0, 1000001, std::array<std::uint8_t, 4>{0, 0, 0, 1});
  if (!Proto(client.FeedBytes(idle), nexora::ProtoErrorCode::kHttp2ProtocolError)) return Fail(__LINE__);
  return 0;
}

int SkipClosedWindow() {
  nexora::test::Link link;
  if (link.Handshake()) return Fail(__LINE__);
  auto stream = link.client.OpenStream();
  if (!stream || !link.client.SubmitRequestHeaders(*stream, nexora::Method::kPost, "https", "ex", "/w", {}, false) ||
      link.Pump()) {
    return Fail(__LINE__);
  }
  if (!link.server.SubmitWindowUpdate(*stream, 0x7fffffffU - 65535U) || link.Pump()) return Fail(__LINE__);
  if (link.client.StreamSendWindow(*stream) != 0x7fffffff) return Fail(__LINE__);
  if (!link.client.SubmitRstStream(*stream, nexora::Http2ErrorCode::kCancel)) return Fail(__LINE__);
  nexora::Http2Settings settings{};
  settings.enable_push = 0;
  settings.initial_window_size = 65536;
  std::array<std::uint8_t, 36> payload{};
  auto payload_size = nexora::EncodeSettingsPayload(settings, payload);
  if (!payload_size) return Fail(__LINE__);
  auto frame = Frame(nexora::Http2FrameType::kSettings, 0, 0, std::span<const std::uint8_t>(payload.data(), *payload_size));
  if (!link.client.FeedBytes(frame)) return Fail(__LINE__);
  return 0;
}

}  // namespace

int main() {
  for (int (*fn)() : {ZeroAllocWholeRpc, BoundaryPing, FragmentedPreface, Whitespace, BackpressureAndSlabBatchLifetime,
                      ResetFlow, EvictedResetStreamSafety, SkipClosedWindow}) {
    if (const int line = fn()) return line;
  }
  for (const bool flag : {false, true}) {
    if (const int line = BoundaryControl(flag)) return line;
    if (const int line = BoundaryInboundAck(flag)) return line;
    if (const int line = FirstSettings(flag ? nexora::Http2Role::kServer : nexora::Http2Role::kClient)) return line;
  }
  return 0;
}
