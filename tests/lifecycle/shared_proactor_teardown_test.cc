#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <nexora/dispatch/completion_routes.hpp>
#include <nexora/socket/tcp_transport.hpp>
#include <nexora/socket/uring_socket.hpp>

namespace {

struct PeerFds {
  int left{-1};
  int right{-1};
  ~PeerFds() noexcept {
    if (left >= 0) static_cast<void>(::close(left));
    if (right >= 0) static_cast<void>(::close(right));
  }
};

struct AcceptWatch {
  uring::UserDataToken token{};
  int hits{0};
  int result{-1};

  [[nodiscard]] bool OnDelivery(const uring::Delivery& delivery) noexcept {
    if (delivery.completion.token != token) return false;
    ++hits;
    result = delivery.completion.result;
    if (result >= 0) static_cast<void>(::close(result));
    return true;
  }
};

using DeliveryHandler = nexora::Result<bool> (nexora::IoUringSocket::*)(const uring::Delivery&) noexcept;
constexpr DeliveryHandler kOnDelivery = static_cast<DeliveryHandler>(&nexora::IoUringSocket::OnCompletion);

int SharedProactorTeardownKeepsSibling() noexcept {
  auto proactor = uring::Proactor::Create(64);
  if (!proactor) return 1;
  auto listener = nexora::TcpListener::BindLoopbackV4(0);
  if (!listener) return 2;

  std::array<int, 2> pair_a{-1, -1};
  std::array<int, 2> pair_b{-1, -1};
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair_a.data()) != 0) return 3;
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair_b.data()) != 0) {
    static_cast<void>(::close(pair_a[0]));
    static_cast<void>(::close(pair_a[1]));
    return 4;
  }
  PeerFds peers{.left = pair_a[1], .right = pair_b[1]};
  constexpr nexora::SocketConfig config{.rx_buffer_capacity = 128, .tx_buffer_capacity = 128};
  auto sock_b = nexora::IoUringSocket::FromRawFd(pair_b[0], nexora::SocketWord::OpenWord(), std::nullopt, std::nullopt, config);
  nexora::CompletionRoutes<8> routes{};
  AcceptWatch watch{};
  sock_b.BindProactor(*proactor, routes);
  if (!routes.Register(
          nexora::CompletionRoute::BindClaiming<nexora::kSocketSubsystemId, nexora::IoUringSocket, kOnDelivery>(&sock_b)) ||
      !routes.Register(
          nexora::CompletionRoute::BindClaiming<nexora::kSocketSubsystemId, AcceptWatch, &AcceptWatch::OnDelivery>(&watch))) {
    static_cast<void>(::close(pair_a[0]));
    return 5;
  }
  auto accept_token = listener->SubmitAccept(*proactor, nexora::kSocketSubsystemId);
  if (!accept_token) {
    static_cast<void>(::close(pair_a[0]));
    return 6;
  }
  watch.token = *accept_token;

  {
    auto sock_a =
        nexora::IoUringSocket::FromRawFd(pair_a[0], nexora::SocketWord::OpenWord(), std::nullopt, std::nullopt, config);
    sock_a.BindProactor(*proactor, routes);
    if (!routes.Register(
            nexora::CompletionRoute::BindClaiming<nexora::kSocketSubsystemId, nexora::IoUringSocket, kOnDelivery>(&sock_a))) {
      return 7;
    }
    if (!sock_a.SubmitRecv(64) || !sock_b.SubmitRecv(64)) return 8;
    static_cast<void>(proactor->Drive(uring::DriveMode::kPoll, routes));
    constexpr std::array<std::uint8_t, 4> payload{'p', 'i', 'n', 'g'};
    if (::send(peers.right, payload.data(), payload.size(), MSG_NOSIGNAL) != 4) return 9;
    auto client = nexora::TcpTransport::ConnectTo(listener->LocalEndpoint(), 1000);
    if (!client) return 10;
    if (!routes.Unregister(&sock_a)) return 11;
  }

  if (sock_b.InFlightOps() != 0 || sock_b.LastRxResult() != 4 || std::memcmp(sock_b.RxBuffer().data(), "ping", 4) != 0)
    return 12;
  if (watch.hits != 1 || watch.result < 0 || ::fcntl(watch.result, F_GETFD) != -1 || errno != EBADF) return 13;
  if (::fcntl(pair_a[0], F_GETFD) != -1 || errno != EBADF || proactor->InFlight() != 0) return 14;
  if (!routes.Unregister(&sock_b) || !routes.Unregister(&watch) || !routes.Empty()) return 15;
  return 0;
}

}  // namespace

int main() { return SharedProactorTeardownKeepsSibling(); }
