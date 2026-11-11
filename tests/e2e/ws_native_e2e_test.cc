#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <nexora/client/ws_client.hpp>
#include <nexora/server/listener.hpp>
#include <nexora/server/ws_server.hpp>
#include <source_location>

namespace {
void Check(bool value, std::source_location location = std::source_location::current()) noexcept {
  if (!value) {
    std::fprintf(stderr, "ws_native:%u failed\n", location.line());
    std::abort();
  }
}
struct ForeignCounter {
  unsigned count{0};
  [[nodiscard]] static bool CanRoute(std::uint8_t id) noexcept { return id == 7; }
  uring::Result<void> DispatchBatch(std::span<const uring::Delivery> deliveries) noexcept {
    count += static_cast<unsigned>(deliveries.size());
    return {};
  }
};
int Serve(nexora::LoopbackListener& listener, int pong_ack_fd) noexcept {
  auto ring = uring::Proactor::Create();
  if (!ring) return 1;
  nexora::detail::UringTransport stream(*ring);
  if (!stream.Accept(listener.RawFd(), 2000)) return 2;
  nexora::Http1ServerCodec<> codec;
  nexora::WebSocketServerSession websocket;
  nexora::BytesMut<16384> input;
  nexora::BytesMut<16384> output;
  std::array<std::uint8_t, 4096> bytes{};
  for (;;) {
    auto request = codec.DecodeRequest(input.ReadableSpan());
    if (!request) return 3;
    if (*request) {
      auto response = websocket.AcceptUpgrade((**request).message);
      if (!response) return 4;
      auto encoded = codec.EncodeResponse(*response);
      if (!encoded || !output.Append(encoded->ReadableSpan())) return 4;
      break;
    }
    input.Clear();
    auto read = stream.ReadSome(bytes, 2000);
    if (!read || *read == 0 || !input.Append(std::span(bytes).first(*read))) return 5;
  }
  if (!websocket.Send(nexora::WebSocketMessage{.kind = nexora::WebSocketMessageKind::kText,
                                               .payload = nexora::Bytes::CopyFromString("welcome")}))
    return 6;
  if (!websocket.Send(nexora::WebSocketMessage{.kind = nexora::WebSocketMessageKind::kPing,
                                               .payload = nexora::Bytes::CopyFromString("hb-1")}))
    return 6;
  if (!output.Append(websocket.PendingOutput()) || !websocket.ConsumeOutput(websocket.PendingOutput().size()) ||
      !stream.WriteAll(output.ReadableSpan(), 2000))
    return 7;

  bool saw_pong = false;
  while (!saw_pong) {
    auto read = stream.ReadSome(bytes, 2000);
    if (!read || *read == 0 || !websocket.Feed(std::span(bytes).first(*read))) return 14;
    for (;;) {
      auto message = websocket.PollMessage();
      if (!message) return 15;
      if (!*message) break;
      if ((**message).kind == nexora::WebSocketMessageKind::kPong && (**message).payload.AsStringView() == "hb-1") {
        saw_pong = true;
      } else {
        return 16;
      }
    }
  }
  const char ack = 'K';
  if (::write(pong_ack_fd, &ack, 1) != 1) return 17;

  for (unsigned step = 0; step < 16; ++step) {
    auto read = stream.ReadSome(bytes, 2000);
    if (!read || *read == 0 || !websocket.Feed(std::span(bytes).first(*read))) return 8;
    bool closing = false;
    for (;;) {
      auto message = websocket.PollMessage();
      if (!message) return 9;
      if (!*message) break;
      if ((**message).kind == nexora::WebSocketMessageKind::kClose)
        closing = true;
      else {
        if (!websocket.Send(**message)) return 10;
        if ((**message).kind == nexora::WebSocketMessageKind::kBinary &&
            !websocket.Send(nexora::WebSocketMessage{.kind = nexora::WebSocketMessageKind::kClose, .close_code = 1000}))
          return 13;
      }
    }
    if (!stream.WriteAll(websocket.PendingOutput(), 2000) || !websocket.ConsumeOutput(websocket.PendingOutput().size()))
      return 11;
    if (closing) return 0;
  }
  return 12;
}
[[nodiscard]] bool UnsupportedSocketOption(int err) noexcept {
  return err == EOPNOTSUPP || err == ENOPROTOOPT || err == EINVAL;
}
int PeerFd(std::uint16_t port) noexcept {
  for (int fd = 3; fd < 256; ++fd) {
    sockaddr_storage storage{};
    socklen_t len = sizeof(storage);
    if (::getpeername(fd, static_cast<sockaddr*>(static_cast<void*>(&storage)), &len) != 0 || storage.ss_family != AF_INET)
      continue;
    const auto* peer = static_cast<const sockaddr_in*>(static_cast<const void*>(&storage));
    if (peer->sin_port == htons(port)) return fd;
  }
  return -1;
}
int ServeRetain(nexora::LoopbackListener& listener, int ctrl) noexcept {
  auto ring = uring::Proactor::Create();
  if (!ring) return 1;
  nexora::detail::UringTransport stream(*ring);
  if (!stream.Accept(listener.RawFd(), 2000)) return 2;
  nexora::Http1ServerCodec<> codec;
  nexora::WebSocketServerSession websocket;
  nexora::BytesMut<16384> input;
  std::array<std::uint8_t, 4096> bytes{};
  for (;;) {
    auto request = codec.DecodeRequest(input.ReadableSpan());
    if (!request) return 3;
    if (*request) {
      auto response = websocket.AcceptUpgrade((**request).message);
      if (!response) return 4;
      auto encoded = codec.EncodeResponse(*response);
      if (!encoded || !stream.WriteAll(encoded->ReadableSpan(), 2000)) return 4;
      break;
    }
    input.Clear();
    auto read = stream.ReadSome(bytes, 2000);
    if (!read || *read == 0 || !input.Append(std::span(bytes).first(*read))) return 5;
  }
  const int small_rcv = 1024;
  if (::setsockopt(stream.RawFd(), SOL_SOCKET, SO_RCVBUF, &small_rcv, sizeof(small_rcv)) != 0) return 6;
  char step = 'R';
  if (::write(ctrl, &step, 1) != 1 || ::read(ctrl, &step, 1) != 1 || step != 'F') return 6;
  if (!websocket.Send(nexora::WebSocketMessage{.kind = nexora::WebSocketMessageKind::kText,
                                               .payload = nexora::Bytes::CopyFromString("retain-me")}) ||
      !websocket.Send(nexora::WebSocketMessage{.kind = nexora::WebSocketMessageKind::kPing,
                                               .payload = nexora::Bytes::CopyFromString("hb")}) ||
      !stream.WriteAll(websocket.PendingOutput(), 2000))
    return 7;
  step = 'S';
  if (::write(ctrl, &step, 1) != 1 || ::read(ctrl, &step, 1) != 1 || step != 'D') return 8;
  constexpr int restored_rcv = 262144;
  if (::setsockopt(stream.RawFd(), SOL_SOCKET, SO_RCVBUF, &restored_rcv, sizeof(restored_rcv)) != 0) return 8;
  // Loopback MTU 65536 (MSS 65484) leaves the clamp below one segment, so RFC 1122 suppresses window updates.
  // Option 73 plus a clamp shrink raises rcv_ssthresh. Without it the zero-window probe fits in the 8 s drain.
  // 2048*4096 covers the 1 MiB fill.
  constexpr int reserved = 262144;
  constexpr int open_clamp = 1073741824;
  constexpr int reserve_mem = 73;
  const int reserve_rc = ::setsockopt(stream.RawFd(), SOL_SOCKET, reserve_mem, &reserved, sizeof(reserved));
  const int reserve_err = errno;
  if (reserve_rc == 0) {
    const int open_rc = ::setsockopt(stream.RawFd(), IPPROTO_TCP, TCP_WINDOW_CLAMP, &open_clamp, sizeof(open_clamp));
    const int open_err = errno;
    if (open_rc != 0 && !UnsupportedSocketOption(open_err)) return 9;
    const int shrink_rc = ::setsockopt(stream.RawFd(), IPPROTO_TCP, TCP_WINDOW_CLAMP, &restored_rcv, sizeof(restored_rcv));
    const int shrink_err = errno;
    if (shrink_rc != 0 && !UnsupportedSocketOption(shrink_err)) return 9;
  } else if (!UnsupportedSocketOption(reserve_err)) {
    return 10;
  } else {
    const int clamp_rc = ::setsockopt(stream.RawFd(), IPPROTO_TCP, TCP_WINDOW_CLAMP, &restored_rcv, sizeof(restored_rcv));
    const int clamp_err = errno;
    if (clamp_rc != 0 && !UnsupportedSocketOption(clamp_err)) return 10;
  }
  bool saw_pong = false;
  const auto drain_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(8000);
  for (unsigned attempt = 0; attempt < 2048 && !saw_pong && std::chrono::steady_clock::now() < drain_deadline; ++attempt) {
    auto read = stream.ReadSome(bytes, 100);
    if (!read) continue;
    if (*read == 0) return 12;
    for (std::size_t i = 0; i < *read; ++i) {
      if (bytes[i] == 0x8A) saw_pong = true;
    }
  }
  if (!saw_pong) return 13;
  step = 'P';
  return ::write(ctrl, &step, 1) == 1 ? 0 : 11;
}
void RetainTextAcrossPongTimeout() noexcept {
  auto listener = nexora::LoopbackListener::Bind();
  Check(listener.has_value());
  std::array<int, 2> ctrl{-1, -1};
  Check(::socketpair(AF_UNIX, SOCK_STREAM, 0, ctrl.data()) == 0);
  const auto child = ::fork();
  Check(child >= 0);
  if (child == 0) {
    static_cast<void>(::close(ctrl[0]));
    const int rc = ServeRetain(*listener, ctrl[1]);
    static_cast<void>(::close(ctrl[1]));
    std::_Exit(rc);
  }
  static_cast<void>(::close(ctrl[1]));
  {
    auto ring = uring::Proactor::Create();
    Check(ring.has_value());
    auto resolver = cares::Resolver<>::FromSystem(*ring);
    Check(resolver.has_value());
    ForeignCounter foreign;
    nexora::CompletionRoutes<> routes;
    Check(routes.Register(nexora::CompletionRoute::Bind(foreign)).has_value());
    nexora::WebSocketClient client(*ring, *resolver, routes);
    auto uri = nexora::Uri::Parse("ws://localhost:" + std::to_string(listener->Port()) + "/echo");
    Check(uri.has_value() && client.Connect(*uri).has_value());
    const int fd = PeerFd(listener->Port());
    Check(fd >= 0);
    char step = '\0';
    Check(::read(ctrl[0], &step, 1) == 1 && step == 'R');
    const int small_snd = 4096;
    Check(::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &small_snd, sizeof(small_snd)) == 0);
    std::array<std::uint8_t, 1024> zeros{};
    std::size_t filled = 0;
    ssize_t sent = 0;
    while (filled < 1024uz * 1024uz) {
      sent = ::send(fd, zeros.data(), zeros.size(), MSG_NOSIGNAL);
      if (sent > 0) {
        filled += static_cast<std::size_t>(sent);
        continue;
      }
      if (sent < 0 && errno == EINTR) continue;
      Check(sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
      ::usleep(1000);
      sent = ::send(fd, zeros.data(), zeros.size(), MSG_NOSIGNAL);
      if (sent > 0) {
        filled += static_cast<std::size_t>(sent);
        continue;
      }
      if (sent < 0 && errno == EINTR) continue;
      Check(sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
      break;
    }
    Check(filled > 0);
    const int flags = ::fcntl(fd, F_GETFL);
    Check(flags >= 0 && (flags & O_NONBLOCK) != 0);
    // Text is queued ahead of Ping, so a flush timeout returns with that message still queued.
    step = 'F';
    Check(::write(ctrl[0], &step, 1) == 1 && ::read(ctrl[0], &step, 1) == 1 && step == 'S');
    auto stalled = client.Receive(10);
    Check(!stalled && stalled.error() == nexora::Error::Timeout());
    constexpr int restored_buf = 262144;
    Check(::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &restored_buf, sizeof(restored_buf)) == 0);
    step = 'D';
    Check(::write(ctrl[0], &step, 1) == 1);
    // 6 s covers zero-window probe backoff on a 250 Hz kernel when option 73 is rejected.
    auto message = client.Receive(6000);
    Check(message.has_value() && message->kind == nexora::WebSocketMessageKind::kText &&
          message->payload.AsStringView() == "retain-me");
    Check(::read(ctrl[0], &step, 1) == 1 && step == 'P');
    auto ping = client.Receive(6000);
    Check(ping.has_value() && ping->kind == nexora::WebSocketMessageKind::kPing && ping->payload.AsStringView() == "hb");
  }
  static_cast<void>(::close(ctrl[0]));
  int status = 0;
  Check(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
}  // namespace
int main() {
  auto listener = nexora::LoopbackListener::Bind();
  Check(listener.has_value());
  std::array<int, 2> pong_pipe{-1, -1};
  Check(::pipe(pong_pipe.data()) == 0);
  const auto child = ::fork();
  Check(child >= 0);
  if (child == 0) {
    static_cast<void>(::close(pong_pipe[0]));
    const int rc = Serve(*listener, pong_pipe[1]);
    static_cast<void>(::close(pong_pipe[1]));
    std::_Exit(rc);
  }
  static_cast<void>(::close(pong_pipe[1]));
  {
    auto ring = uring::Proactor::Create();
    Check(ring.has_value());
    auto resolver = cares::Resolver<>::FromSystem(*ring);
    Check(resolver.has_value());
    ForeignCounter foreign;
    nexora::CompletionRoutes<> routes;
    Check(routes.Register(nexora::CompletionRoute::Bind(foreign)).has_value());
    nexora::WebSocketClient client(*ring, *resolver, routes);
    Check(ring->Arm(7, uring::ops::PrepareNop()).has_value());
    auto uri = nexora::Uri::Parse("ws://localhost:" + std::to_string(listener->Port()) + "/echo");
    Check(uri.has_value() && client.Connect(*uri).has_value());
    Check(foreign.count == 1);
    auto message = client.Receive();
    Check(message.has_value() && message->payload.AsStringView() == "welcome");
    auto ping = client.Receive();
    Check(ping.has_value() && ping->kind == nexora::WebSocketMessageKind::kPing && ping->payload.AsStringView() == "hb-1");
    char ack = '\0';
    Check(::read(pong_pipe[0], &ack, 1) == 1 && ack == 'K');
    Check(client.SendText("hello").has_value());
    Check(ring->Arm(7, uring::ops::PrepareNop()).has_value());
    message = client.Receive();
    Check(foreign.count == 2);
    Check(message.has_value() && message->kind == nexora::WebSocketMessageKind::kText &&
          message->payload.AsStringView() == "hello");
    constexpr std::array<std::uint8_t, 3> bytes{1, 2, 3};
    Check(client.SendBinary(nexora::Bytes::CopyFromSlice(bytes)).has_value());
    message = client.Receive();
    Check(message.has_value() && message->kind == nexora::WebSocketMessageKind::kBinary &&
          std::equal(message->payload.Span().begin(), message->payload.Span().end(), bytes.begin(), bytes.end()));
    message = client.Receive();
    Check(message.has_value() && message->kind == nexora::WebSocketMessageKind::kClose && message->close_code == 1000);
  }
  static_cast<void>(::close(pong_pipe[0]));
  int status = 0;
  Check(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  RetainTextAcrossPongTimeout();
}
