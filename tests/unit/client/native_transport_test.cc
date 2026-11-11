#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <cerrno>
#include <cstdlib>
#include <nexora/client/http_client.hpp>
#include <nexora/client/ws_client.hpp>
#include <nexora/server/listener.hpp>
#include <nexora/socket/tcp_transport.hpp>

namespace {
void Check(bool value) noexcept {
  if (!value) std::abort();
}
struct PreviousRouter {
  unsigned count{0};
  void OnForeignDeliveries(std::span<const uring::Delivery> deliveries) noexcept {
    count += static_cast<unsigned>(deliveries.size());
  }
};
struct InstalledObserver {
  cares::ForeignBatchObserver observer{};
  [[nodiscard]] static bool CanRoute(std::uint8_t id) noexcept { return id == 1; }
  [[nodiscard]] uring::Result<void> DispatchBatch(std::span<const uring::Delivery> deliveries) const noexcept {
    observer(deliveries);
    return {};
  }
};
struct ForeignRoute {
  unsigned count{0};
  [[nodiscard]] static bool CanRoute(std::uint8_t id) noexcept { return id == 7; }
  [[nodiscard]] uring::Result<void> DispatchBatch(std::span<const uring::Delivery> deliveries) noexcept {
    count += static_cast<unsigned>(deliveries.size());
    return std::unexpected(uring::UringErrorCode::kInvalid);
  }
};
struct ReentrantClient {
  uring::Proactor& proactor;
  cares::Resolver<>& resolver;
  std::uint16_t port{0};
  unsigned calls{0};
  [[nodiscard]] static bool CanRoute(std::uint8_t id) noexcept { return id == 8 || id == 1; }
  [[nodiscard]] uring::Result<void> DispatchBatch(std::span<const uring::Delivery> deliveries) noexcept {
    if (uring::Subsystem(deliveries.front().completion.token) != 8) return {};
    ++calls;
    nexora::CompletionRoutes<> routes;
    Check(routes.Register(nexora::CompletionRoute::Bind(*this)).has_value());
    nexora::HttpClient client(proactor, resolver, routes);
    auto uri = nexora::Uri::Parse("http://127.0.0.1:" + std::to_string(port) + "/");
    Check(uri.has_value());
    const auto before = std::chrono::steady_clock::now();
    auto connected = client.Connect(*uri, 20);
    Check(!connected && std::chrono::steady_clock::now() - before < std::chrono::seconds(1));
    return {};
  }
};
void SharedClientsRequireRoutes() {
  auto ring = uring::Proactor::Create();
  Check(ring.has_value());
  auto resolver = cares::Resolver<>::FromSystem(*ring);
  Check(resolver.has_value());
  nexora::HttpClient http(*ring, *resolver, {}, {});
  nexora::WebSocketClient websocket(*ring, *resolver, {}, {});
  auto http_uri = nexora::Uri::Parse("http://127.0.0.1:1/");
  auto ws_uri = nexora::Uri::Parse("ws://127.0.0.1:1/");
  Check(http_uri.has_value() && ws_uri.has_value());
  auto connected = http.Connect(*http_uri);
  Check(!connected && connected.error() == nexora::Error::InvalidArgument());
  connected = websocket.Connect(*ws_uri);
  Check(!connected && connected.error() == nexora::Error::InvalidArgument());
  Check(ring->InFlight() == 0);
}
void ClosedProactorReturns() {
  auto ring = uring::Proactor::Create();
  Check(ring.has_value());
  std::array<int, 2> sockets{};
  Check(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets.data()) == 0);
  ForeignRoute route;
  nexora::detail::UringTransport transport(*ring, nullptr, 1, nexora::CompletionRoute::Bind(route));
  Check(transport.Adopt(sockets[0]).has_value());
  Check(ring->DrainBlocking(route).has_value());
  std::array<std::uint8_t, 1> bytes{};
  auto read = transport.ReadSome(bytes, 10);
  Check(!read && ring->Stage() == uring::DrainStage::kClosed);
  Check(::close(sockets[1]) == 0);
}
enum class LateRoute : std::uint8_t { kShared, kPrivate };
void LateCqeRetiresParkedFd(LateRoute kind) {
  auto ring = uring::Proactor::Create();
  Check(ring.has_value());
  std::array<int, 2> sockets{};
  Check(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets.data()) == 0);
  nexora::detail::UringTransport transport(*ring);
  Check(transport.Adopt(sockets[0]).has_value());
  struct Hook {
    nexora::detail::UringTransport* transport{nullptr};
    int parked_fd{-1};
    int probe_fd{-1};
    [[nodiscard]] static bool CanRoute(std::uint8_t id) noexcept { return id == 9; }
    [[nodiscard]] uring::Result<void> DispatchBatch(std::span<const uring::Delivery> deliveries) noexcept {
      if (deliveries.empty() || uring::Subsystem(deliveries.front().completion.token) != 9) return {};
      std::array<std::uint8_t, 1> bytes{};
      Check(!transport->ReadSome(bytes, 20));
      probe_fd = ::socket(AF_INET, SOCK_STREAM, 0);
      Check(probe_fd >= 0 && probe_fd != parked_fd);
      Check(transport->ParkedCount() == 1);
      return {};
    }
  } hook{&transport, sockets[0]};
  Check(ring->Arm(9, uring::ops::PrepareNop()).has_value());
  Check(ring->WaitCompletions(1, std::chrono::seconds(1), hook).has_value());
  Check(hook.probe_fd >= 0 && transport.ParkedCount() == 1);
  if (kind == LateRoute::kShared) {
    nexora::CompletionRoutes<> routes;
    nexora::detail::ForeignObserverScope<nexora::CompletionRoutes<>> scope(nullptr, routes);
    for (int step = 0; transport.ParkedCount() != 0 && step < 4; ++step)
      Check(ring->Drive(uring::DriveMode::kPoll, scope).has_value());
    Check(!scope.Error());
  } else {
    auto route = nexora::detail::PrivateRingRoute();
    for (int step = 0; transport.ParkedCount() != 0 && step < 4; ++step)
      Check(ring->Drive(uring::DriveMode::kPoll, route).has_value());
  }
  Check(transport.ParkedCount() == 0);
  Check(::fcntl(sockets[0], F_GETFD) < 0);
  Check(::close(hook.probe_fd) == 0);
  Check(::close(sockets[1]) == 0);
}
void ReentrantConnectReturns() {
  auto ring = uring::Proactor::Create();
  Check(ring.has_value());
  auto resolver = cares::Resolver<>::FromSystem(*ring);
  auto listener = nexora::LoopbackListener::Bind();
  Check(resolver.has_value() && listener.has_value());
  ReentrantClient route{*ring, *resolver, listener->Port()};
  Check(ring->Arm(8, uring::ops::PrepareNop()).has_value());
  Check(ring->WaitCompletions(1, std::chrono::seconds(1), route).has_value());
  Check(route.calls == 1);
  for (unsigned step = 0; ring->InFlight() != 0 && step < 8; ++step)
    Check(ring->WaitCompletions(1, std::chrono::seconds(1), route).has_value());
  Check(ring->InFlight() == 0);
}
// A full SOCK_NONBLOCK send buffer must time out inside io_uring and stay open.
void SaturatedWriteRecovers() {
  auto ring = uring::Proactor::Create();
  Check(ring.has_value());
  std::array<int, 2> sockets{};
  Check(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets.data()) == 0);
  const int small = 4096;
  Check(::setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) == 0);
  Check(::setsockopt(sockets[1], SOL_SOCKET, SO_RCVBUF, &small, sizeof(small)) == 0);
  nexora::detail::UringTransport transport(*ring);
  Check(transport.Adopt(sockets[0]).has_value());
  std::array<std::uint8_t, 1024> chunk{};
  bool saturated = false;
  for (int step = 0; step < 4096; ++step) {
    const ssize_t sent = ::send(sockets[0], chunk.data(), chunk.size(), MSG_NOSIGNAL);
    if (sent > 0) continue;
    Check(sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    saturated = true;
    break;
  }
  Check(saturated);
  std::array<std::uint8_t, 64> payload{};
  for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::uint8_t>(i + 1);
  auto timed = transport.WriteAll(payload, 20);
  Check(!timed && timed.error() == nexora::Error::Timeout());
  Check(transport.IsOpen() && transport.ParkedCount() == 0);
  std::array<std::uint8_t, 1024> sink{};
  bool drained = false;
  for (int step = 0; step < 4096; ++step) {
    const ssize_t got = ::recv(sockets[1], sink.data(), sink.size(), 0);
    if (got > 0) continue;
    Check(got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    drained = true;
    break;
  }
  Check(drained);
  Check(transport.WriteAll(payload, 2000).has_value());
  std::array<std::uint8_t, 64> received{};
  std::size_t total = 0;
  while (total < payload.size()) {
    const ssize_t got = ::recv(sockets[1], received.data() + total, payload.size() - total, 0);
    Check(got > 0);
    total += static_cast<std::size_t>(got);
  }
  Check(total == payload.size());
  for (std::size_t i = 0; i < payload.size(); ++i) Check(received[i] == payload[i]);
  Check(::close(sockets[1]) == 0);
}
}  // namespace
int main() {
  SaturatedWriteRecovers();
  LateCqeRetiresParkedFd(LateRoute::kShared);
  LateCqeRetiresParkedFd(LateRoute::kPrivate);
  ClosedProactorReturns();
  SharedClientsRequireRoutes();
  ReentrantConnectReturns();
  auto proactor = uring::Proactor::Create();
  Check(proactor.has_value());
  std::array<int, 2> sockets{};
  Check(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets.data()) == 0);
  {
    auto resolver = cares::Resolver<>::FromSystem(*proactor);
    Check(resolver.has_value());
    ForeignRoute foreign;
    nexora::detail::UringTransport transport(*proactor, &*resolver, 1, nexora::CompletionRoute::Bind(foreign));
    Check(transport.Adopt(sockets[0]).has_value());
    auto nop = proactor->Arm(7, uring::ops::PrepareNop());
    Check(nop.has_value());
    constexpr std::array<std::uint8_t, 1> byte{42};
    auto wrote = transport.WriteAll(byte, 2000);
    Check(wrote.has_value() && foreign.count == 1 && proactor->InFlight() == 0);
    std::array<std::uint8_t, 1> received{};
    Check(::recv(sockets[1], received.data(), received.size(), MSG_DONTWAIT) == 1 && received[0] == 42);
    auto read = transport.ReadSome(received, 10);
    Check(!read && read.error() == nexora::Error::Timeout());
    Check(transport.IsOpen() && proactor->InFlight() == 0);
    Check(::send(sockets[1], byte.data(), byte.size(), MSG_NOSIGNAL) == 1);
    read = transport.ReadSome(received, 2000);
    Check(read.has_value() && *read == 1 && received[0] == 42);
  }
  Check(::close(sockets[1]) == 0);
  Check(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets.data()) == 0);
  {
    auto resolver = cares::Resolver<>::FromSystem(*proactor);
    Check(resolver.has_value());
    PreviousRouter previous;
    resolver->BindForeignRouter(&previous);
    nexora::detail::UringTransport transport(*proactor, &*resolver);
    Check(transport.Adopt(sockets[0]).has_value());
    Check(proactor->Arm(1, uring::ops::PrepareNop()).has_value());
    constexpr std::array<std::uint8_t, 1> byte{7};
    Check(transport.WriteAll(byte, 2000).has_value());
    Check(previous.count == 1 && static_cast<bool>(resolver->ForeignObserver()));
    Check(proactor->Arm(1, uring::ops::PrepareNop()).has_value());
    InstalledObserver installed{resolver->ForeignObserver()};
    Check(proactor->WaitCompletions(1, std::chrono::seconds(2), installed).has_value());
    Check(previous.count == 2);
  }
  Check(::close(sockets[1]) == 0);

  // ForeignObserverScope clears Error() at the start of each DispatchBatch,
  // and raw UringFailed / DnsFailed / FromErrno channels stay intact.
  {
    struct ToggleRoute {
      bool fail_next{true};
      [[nodiscard]] static bool CanRoute(std::uint8_t) noexcept { return true; }
      [[nodiscard]] uring::Result<void> DispatchBatch(std::span<const uring::Delivery>) noexcept {
        if (fail_next) {
          fail_next = false;
          return std::unexpected(uring::UringErrorCode::kInvalid);
        }
        return {};
      }
    } toggle;
    nexora::detail::ForeignObserverScope scope(nullptr, toggle);
    std::array<uring::Delivery, 1> dummy{};
    Check(!scope.DispatchBatch(dummy).has_value() && scope.Error().has_value());
    Check(scope.DispatchBatch(dummy).has_value() && !scope.Error().has_value());

    const auto host_unreach = nexora::detail::MapTcpErrno(EHOSTUNREACH);
    Check(host_unreach.domain == nexora::ErrorDomain::kErrno && host_unreach.SysErrno() == EHOSTUNREACH);
    const auto uring_raw =
        nexora::Error::UringFailed(static_cast<std::int32_t>(std::to_underlying(uring::UringErrorCode::kOverflow)));
    Check(uring_raw.domain == nexora::ErrorDomain::kRuntime &&
          uring_raw.code == static_cast<std::int32_t>(std::to_underlying(nexora::RuntimeErrorCode::kUringError)) &&
          uring_raw.sys_errno == static_cast<std::int16_t>(std::to_underlying(uring::UringErrorCode::kOverflow)));
  }

  auto listener = nexora::LoopbackListener::Bind();
  Check(listener.has_value());
  nexora::detail::UringTransport timed_accept(*proactor);
  auto accepted = timed_accept.Accept(listener->RawFd(), 10);
  Check(!accepted && accepted.error() == nexora::Error::Timeout());
  Check(!timed_accept.IsOpen() && proactor->InFlight() == 0);
  const auto child = ::fork();
  Check(child >= 0);
  if (child == 0) {
    auto client_ring = uring::Proactor::Create();
    if (!client_ring) std::_Exit(1);
    nexora::detail::UringTransport client(*client_ring);
    const cares::Endpoint endpoint{cares::IpAddress::FromV4HostOrder(0x7f000001U), listener->Port()};
    if (!client.Connect(endpoint, 2000)) std::_Exit(2);
    constexpr std::array<std::uint8_t, 4> request{1, 2, 3, 4};
    if (!client.WriteAll(request, 2000)) std::_Exit(3);
    std::array<std::uint8_t, 4> response{};
    auto read = client.ReadSome(response, 2000);
    std::_Exit(read && *read == 4 && response == request ? 0 : 4);
  }
  int accepted_fd_check = -1;
  {
    // Verify TCP_NODELAY is enabled on UringTransport::Accept sockets.
    nexora::detail::UringTransport server(*proactor);
    Check(server.Accept(listener->RawFd(), 2000).has_value());
    Check(server.Peer().has_value());
    int nodelay = 0;
    socklen_t optlen = sizeof(nodelay);
    Check(server.RawFd() >= 0 && ::getsockopt(server.RawFd(), IPPROTO_TCP, TCP_NODELAY, &nodelay, &optlen) == 0 &&
          nodelay == 1);
    std::array<std::uint8_t, 4> request{};
    auto read = server.ReadSome(request, 2000);
    Check(read.has_value() && *read == 4);
    Check(server.WriteAll(request, 2000).has_value());
  }
  static_cast<void>(accepted_fd_check);
  int status = 0;
  Check(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
