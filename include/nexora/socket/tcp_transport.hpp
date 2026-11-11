#pragma once
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cares/cares.hpp>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <nexora/error/runtime_error.hpp>
#include <nexora/socket/uring_socket.hpp>
#include <nexora/tls/tls_session.hpp>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
namespace nexora {
using ResolvedEndpoint = cares::Endpoint;
namespace detail {
[[nodiscard]] inline Error MapTcpErrno(int err) noexcept {
  switch (err) {
    case 0:
      return Error{};
    case ETIMEDOUT:
      return Error::Timeout();
    case ECANCELED:
      return Error::Cancelled();
    case ECONNREFUSED:
      return Error::FromRuntime(RuntimeErrorCode::kConnectionRefused);
    case ECONNRESET:
    case EPIPE:
    case ECONNABORTED:
      return Error::FromRuntime(RuntimeErrorCode::kConnectionReset);
    case ENOTCONN:
    case EBADF:
      return Error::FromRuntime(RuntimeErrorCode::kConnectionClosed);
    default:
      return Error::FromErrno(err);
  }
}
[[nodiscard]] inline std::uint32_t RemainingTimeoutMs(std::chrono::steady_clock::time_point deadline,
                                                      bool non_blocking_zero) noexcept {
  if (non_blocking_zero) return 0;
  const auto now = std::chrono::steady_clock::now();
  if (now >= deadline) return 0;
  const auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
  const auto clamped = rem > 0x7FFF'FFFFLL ? 0x7FFF'FFFFLL : (rem > 0 ? rem : 1);
  return static_cast<std::uint32_t>(clamped);
}
[[nodiscard]] inline Result<void> PollTcpFdUntil(int fd, short events, std::chrono::steady_clock::time_point deadline,
                                                 bool zero_timeout) noexcept {
  if (fd < 0) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
  for (;;) {
    int wait_ms = 0;
    if (!zero_timeout) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) return std::unexpected(Error::Timeout());
      const auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
      const auto clamped = rem > 0x7FFF'FFFFLL ? 0x7FFF'FFFFLL : (rem > 0 ? rem : 1);
      wait_ms = static_cast<int>(clamped);
    }
    struct ::pollfd pfd{.fd = fd, .events = events, .revents = 0};
    const int rc = ::poll(&pfd, 1, wait_ms);
    if (rc > 0) {
      if ((pfd.revents & POLLNVAL) != 0) {
        return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
      }
      return {};
    }
    if (rc == 0) return std::unexpected(Error::Timeout());
    if (errno == EINTR) continue;
    return std::unexpected(MapTcpErrno(errno));
  }
}
[[nodiscard]] inline Result<void> PollTcpFd(int fd, short events, std::uint32_t timeout_ms) noexcept {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  return PollTcpFdUntil(fd, events, deadline, timeout_ms == 0);
}
}  // namespace detail
class TcpTransport {
  int fd_{-1};
  std::optional<cares::Endpoint> peer_{};
  bool nodelay_{true};
  [[nodiscard]] Result<std::size_t> WriteUntil(std::span<const std::uint8_t> data,
                                               std::chrono::steady_clock::time_point deadline,
                                               bool zero_timeout) const noexcept {
    if (fd_ < 0) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    if (data.empty()) return std::size_t{0};
    for (;;) {
      const ::ssize_t n = ::send(fd_, data.data(), data.size(), MSG_NOSIGNAL);
      if (n >= 0) return static_cast<std::size_t>(n);
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        auto waited = detail::PollTcpFdUntil(fd_, POLLOUT, deadline, zero_timeout);
        if (!waited) return std::unexpected(waited.error());
        continue;
      }
      return std::unexpected(detail::MapTcpErrno(errno));
    }
  }

 public:
  constexpr TcpTransport() noexcept = default;
  explicit constexpr TcpTransport(int fd, std::optional<cares::Endpoint> peer = {}, bool nodelay = true) noexcept
      : fd_(fd), peer_(peer), nodelay_(nodelay) {}
  TcpTransport(const TcpTransport&) = delete ("single-owner TCP transport handle; move instead");
  TcpTransport& operator=(const TcpTransport&) = delete ("single-owner TCP transport handle; move instead");
  constexpr TcpTransport(TcpTransport&& other) noexcept
      : fd_(std::exchange(other.fd_, -1)), peer_(std::exchange(other.peer_, std::nullopt)), nodelay_(other.nodelay_) {}
  TcpTransport& operator=(TcpTransport&& other) noexcept {
    if (this != &other) {
      Close();
      fd_ = std::exchange(other.fd_, -1);
      peer_ = std::exchange(other.peer_, std::nullopt);
      nodelay_ = other.nodelay_;
    }
    return *this;
  }
  ~TcpTransport() noexcept { Close(); }
  [[nodiscard]] static Result<TcpTransport> ConnectTo(const cares::Endpoint& endpoint,
                                                      std::uint32_t timeout_ms = 5000) noexcept {
    TcpTransport transport{};
    auto res = transport.Connect(endpoint, timeout_ms);
    if (!res) return std::unexpected(res.error());
    return transport;
  }
  [[nodiscard]] Result<void> Connect(const cares::Endpoint& endpoint, std::uint32_t timeout_ms = 5000) noexcept {
    if ((!endpoint.ip.IsV4() && !endpoint.ip.IsV6()) || endpoint.port == 0) {
      return std::unexpected(Error::InvalidArgument());
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    Close();
    auto created = detail::CreateNonblockingTcpFd(endpoint.ip.IsV6() ? AF_INET6 : AF_INET, nodelay_);
    if (!created) return std::unexpected(created.error());
    fd_ = *created;
    peer_ = endpoint;
    const auto sa_val = endpoint.ToSockAddrValue();
    const int rc = ::connect(fd_, static_cast<const ::sockaddr*>(static_cast<const void*>(&sa_val.storage)), sa_val.len);
    if (rc == 0) return {};
    if (errno != EINPROGRESS && errno != EALREADY) {
      const int err = errno;
      Close();
      return std::unexpected(detail::MapTcpErrno(err));
    }
    auto waited = detail::PollTcpFdUntil(fd_, POLLOUT, deadline, timeout_ms == 0);
    if (!waited) {
      Close();
      return std::unexpected(waited.error());
    }
    int so_err = 0;
    ::socklen_t len = sizeof(so_err);
    if (::getsockopt(fd_, SOL_SOCKET, SO_ERROR, &so_err, &len) != 0) {
      const int err = errno;
      Close();
      return std::unexpected(detail::MapTcpErrno(err));
    }
    if (so_err != 0) {
      Close();
      return std::unexpected(detail::MapTcpErrno(so_err));
    }
    return {};
  }
  template <typename ResolverT>
  [[nodiscard]] Result<cares::Endpoint> ConnectHost(ResolverT& resolver, std::string_view host, std::uint16_t port,
                                                    std::uint32_t timeout_ms = 5000) noexcept {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    const bool zero_timeout = (timeout_ms == 0);
    auto resolved = resolver.ResolveEndpoints(host, port, cares::IpFamily::DualStack);
    if (!resolved) return std::unexpected(Error::DnsFailed(resolved.error().raw_code));
    if (resolved->empty()) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kDnsError));
    Error last_err = Error::FromRuntime(RuntimeErrorCode::kConnectionRefused);
    for (const auto& ep : *resolved) {
      if (!zero_timeout && std::chrono::steady_clock::now() >= deadline) return std::unexpected(Error::Timeout());
      auto connected = Connect(ep, detail::RemainingTimeoutMs(deadline, zero_timeout));
      if (connected) return ep;
      last_err = connected.error();
    }
    return std::unexpected(last_err);
  }
  [[nodiscard]] Result<std::size_t> Write(std::span<const std::uint8_t> data, std::uint32_t timeout_ms = 5000) noexcept {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    return WriteUntil(data, deadline, timeout_ms == 0);
  }
  [[nodiscard]] Result<void> WriteAll(std::span<const std::uint8_t> data, std::uint32_t timeout_ms = 5000) noexcept {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    const bool zero_timeout = (timeout_ms == 0);
    std::size_t offset = 0;
    while (offset < data.size()) {
      auto written = WriteUntil(data.subspan(offset), deadline, zero_timeout);
      if (!written) return std::unexpected(written.error());
      if (*written == 0) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
      offset += *written;
    }
    return {};
  }
  [[nodiscard]] Result<std::size_t> ReadSome(std::span<std::uint8_t> out, std::uint32_t timeout_ms = 5000) const noexcept {
    if (fd_ < 0) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    if (out.empty()) return std::size_t{0};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    const bool zero_timeout = (timeout_ms == 0);
    for (;;) {
      const ::ssize_t n = ::recv(fd_, out.data(), out.size(), 0);
      if (n >= 0) return static_cast<std::size_t>(n);
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        auto waited = detail::PollTcpFdUntil(fd_, POLLIN, deadline, zero_timeout);
        if (!waited) return std::unexpected(waited.error());
        continue;
      }
      return std::unexpected(detail::MapTcpErrno(errno));
    }
  }
  void ShutdownWrite() const noexcept {
    if (fd_ >= 0) static_cast<void>(::shutdown(fd_, SHUT_WR));
  }
  void Close() noexcept {
    if (fd_ >= 0) static_cast<void>(::close(std::exchange(fd_, -1)));
  }
  [[nodiscard]] constexpr bool IsOpen() const noexcept { return fd_ >= 0; }
  [[nodiscard]] constexpr bool IsClosed() const noexcept { return fd_ < 0; }
  [[nodiscard]] constexpr int NativeFd() const noexcept { return fd_; }
  [[nodiscard]] constexpr int Fd() const noexcept { return fd_; }
  [[nodiscard]] constexpr std::optional<cares::Endpoint> PeerEndpoint() const noexcept { return peer_; }
  [[nodiscard]] int ReleaseFd() noexcept { return std::exchange(fd_, -1); }
};
class TcpListener {
  int fd_{-1};
  cares::Endpoint local_endpoint_{};

 public:
  constexpr TcpListener() noexcept = default;
  constexpr TcpListener(int fd, cares::Endpoint local_ep) noexcept : fd_(fd), local_endpoint_(local_ep) {}
  TcpListener(const TcpListener&) = delete ("single-owner TCP listener handle; move instead");
  TcpListener& operator=(const TcpListener&) = delete ("single-owner TCP listener handle; move instead");
  constexpr TcpListener(TcpListener&& other) noexcept
      : fd_(std::exchange(other.fd_, -1)), local_endpoint_(other.local_endpoint_) {}
  TcpListener& operator=(TcpListener&& other) noexcept {
    if (this != &other) {
      Close();
      fd_ = std::exchange(other.fd_, -1);
      local_endpoint_ = other.local_endpoint_;
    }
    return *this;
  }
  ~TcpListener() noexcept { Close(); }
  [[nodiscard]] static Result<TcpListener> Bind(const cares::Endpoint& bind_ep, int backlog = 128) noexcept {
    if (!bind_ep.ip.IsV4() && !bind_ep.ip.IsV6()) return std::unexpected(Error::InvalidArgument());
    const int domain = bind_ep.ip.IsV6() ? AF_INET6 : AF_INET;
    const int fd = ::socket(domain, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
    if (fd < 0) return std::unexpected(detail::MapTcpErrno(errno));
    const int one = 1;
    static_cast<void>(::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));
    const auto sa_val = bind_ep.ToSockAddrValue();
    const auto* bind_sa = static_cast<const ::sockaddr*>(static_cast<const void*>(&sa_val.storage));
    if (::bind(fd, bind_sa, sa_val.len) != 0 || ::listen(fd, backlog) != 0) {
      const int err = errno;
      static_cast<void>(::close(fd));
      return std::unexpected(detail::MapTcpErrno(err));
    }
    ::sockaddr_storage bound_sa{};
    ::socklen_t bound_len = sizeof(bound_sa);
    if (::getsockname(fd, static_cast<::sockaddr*>(static_cast<void*>(&bound_sa)), &bound_len) != 0) {
      const int err = errno;
      static_cast<void>(::close(fd));
      return std::unexpected(detail::MapTcpErrno(err));
    }
    return TcpListener{fd, cares::Endpoint::FromSockAddr(static_cast<const ::sockaddr*>(static_cast<const void*>(&bound_sa)))};
  }
  [[nodiscard]] static Result<TcpListener> BindLoopbackV4(std::uint16_t port = 0, int backlog = 128) noexcept {
    return Bind(cares::Endpoint{cares::IpAddress::FromV4({127, 0, 0, 1}), port}, backlog);
  }
  [[nodiscard]] Result<TcpTransport> Accept(std::uint32_t timeout_ms = 5000) const noexcept {
    if (fd_ < 0) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    const bool zero_timeout = (timeout_ms == 0);
    for (;;) {
      ::sockaddr_storage peer_sa{};
      ::socklen_t peer_len = sizeof(peer_sa);
      const int client_fd =
          ::accept4(fd_, static_cast<::sockaddr*>(static_cast<void*>(&peer_sa)), &peer_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (client_fd >= 0) {
        const int one = 1;
        static_cast<void>(::setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)));
        return TcpTransport{
            client_fd, cares::Endpoint::FromSockAddr(static_cast<const ::sockaddr*>(static_cast<const void*>(&peer_sa))), true};
      }
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        auto waited = detail::PollTcpFdUntil(fd_, POLLIN, deadline, zero_timeout);
        if (!waited) return std::unexpected(waited.error());
        continue;
      }
      return std::unexpected(detail::MapTcpErrno(errno));
    }
  }
  [[nodiscard]] Result<uring::UserDataToken> SubmitAccept(uring::Proactor& proactor,
                                                          std::uint8_t subsystem_id = kServerSubsystemId) noexcept {
    if (fd_ < 0) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    if (subsystem_id == uring::kInternalSubsystemId || subsystem_id == uring::kMailboxSubsystemId) {
      return std::unexpected(Error::InvalidArgument());
    }
    const auto prep = uring::ops::PrepareAccept(fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
    auto armed = proactor.Arm(subsystem_id, prep);
    if (!armed) return std::unexpected(Error::UringFailed(static_cast<std::int32_t>(std::to_underlying(armed.error()))));
    return *armed;
  }
  void Close() noexcept {
    if (fd_ >= 0) static_cast<void>(::close(std::exchange(fd_, -1)));
  }
  [[nodiscard]] constexpr int Fd() const noexcept { return fd_; }
  [[nodiscard]] constexpr const cares::Endpoint& LocalEndpoint() const noexcept { return local_endpoint_; }
  [[nodiscard]] constexpr std::uint16_t LocalPort() const noexcept { return local_endpoint_.port; }
};
class TlsTransport {
  TcpTransport tcp_{};
  std::optional<TlsSession> tls_{};
  const TlsClientConfig* client_cfg_{nullptr};
  std::string server_name_{};
  std::array<std::uint8_t, 16384> pending_cipher_{};
  std::size_t pending_cipher_off_{0};
  std::size_t pending_cipher_len_{0};
  std::optional<Error> poison_error_{};
  std::optional<Error> deferred_flush_error_{};
  void ResetCipherState() noexcept {
    pending_cipher_off_ = 0;
    pending_cipher_len_ = 0;
    poison_error_.reset();
    deferred_flush_error_.reset();
  }
  [[nodiscard]] Result<void> DrainPendingCipher(std::chrono::steady_clock::time_point deadline, bool zero_timeout) noexcept {
    while (pending_cipher_off_ < pending_cipher_len_) {
      if (!zero_timeout && std::chrono::steady_clock::now() >= deadline) return std::unexpected(Error::Timeout());
      auto n = tcp_.Write(std::span<const std::uint8_t>{pending_cipher_.data() + pending_cipher_off_,
                                                        pending_cipher_len_ - pending_cipher_off_},
                          detail::RemainingTimeoutMs(deadline, zero_timeout));
      if (!n) {
        if (n.error() != Error::Timeout()) poison_error_ = n.error();
        return std::unexpected(n.error());
      }
      if (*n == 0) {
        const auto err = Error::FromRuntime(RuntimeErrorCode::kConnectionClosed);
        poison_error_ = err;
        return std::unexpected(err);
      }
      pending_cipher_off_ += *n;
    }
    pending_cipher_off_ = 0;
    pending_cipher_len_ = 0;
    return {};
  }
  [[nodiscard]] Result<void> FlushPendingCiphertext(std::uint32_t timeout_ms) noexcept {
    if (!tls_.has_value()) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    if (poison_error_) return std::unexpected(*poison_error_);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    const bool zero_timeout = (timeout_ms == 0);
    if (auto drained = DrainPendingCipher(deadline, zero_timeout); !drained) return drained;
    while (tls_->HasPendingCiphertextOut()) {
      auto taken = tls_->TakeCiphertext(pending_cipher_);
      if (!taken) {
        poison_error_ = taken.error();
        return std::unexpected(taken.error());
      }
      if (*taken == 0) break;
      pending_cipher_off_ = 0;
      pending_cipher_len_ = *taken;
      if (auto drained = DrainPendingCipher(deadline, zero_timeout); !drained) return drained;
    }
    return {};
  }

 public:
  TlsTransport() noexcept = default;
  TlsTransport(const TlsClientConfig& client_cfg, std::string_view server_name) noexcept
      : client_cfg_(&client_cfg), server_name_(server_name) {}
  TlsTransport(TcpTransport tcp, TlsSession tls) noexcept : tcp_(std::move(tcp)), tls_(std::move(tls)) {}
  [[nodiscard]] static Result<TlsTransport> ConnectClient(const cares::Endpoint& endpoint, const TlsClientConfig& client_cfg,
                                                          std::string_view server_name,
                                                          std::uint32_t timeout_ms = 5000) noexcept {
    TlsTransport transport{client_cfg, server_name};
    auto res = transport.Connect(endpoint, timeout_ms);
    if (!res) return std::unexpected(res.error());
    return transport;
  }
  [[nodiscard]] static Result<TlsTransport> AcceptServer(TcpTransport tcp, const TlsServerConfig& server_cfg,
                                                         std::uint32_t timeout_ms = 5000) noexcept {
    auto session = TlsSession::CreateServer(server_cfg);
    if (!session) return std::unexpected(session.error());
    TlsTransport transport{std::move(tcp), std::move(*session)};
    auto hs = transport.CompleteHandshake(timeout_ms);
    if (!hs) return std::unexpected(hs.error());
    return transport;
  }
  [[nodiscard]] Result<void> Connect(const cares::Endpoint& endpoint, const TlsClientConfig& cfg, std::string_view server_name,
                                     std::uint32_t timeout_ms = 5000) noexcept {
    client_cfg_ = &cfg;
    server_name_.assign(server_name.data(), server_name.size());
    return Connect(endpoint, timeout_ms);
  }
  [[nodiscard]] Result<void> Connect(const cares::Endpoint& endpoint, std::uint32_t timeout_ms = 5000) noexcept {
    if (client_cfg_ == nullptr) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    ResetCipherState();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    const bool zero_timeout = (timeout_ms == 0);
    auto session = TlsSession::CreateClient(*client_cfg_, server_name_);
    if (!session) return std::unexpected(session.error());
    auto tcp_connected = tcp_.Connect(endpoint, timeout_ms);
    if (!tcp_connected) return std::unexpected(tcp_connected.error());
    tls_.emplace(std::move(*session));
    if (!zero_timeout && std::chrono::steady_clock::now() >= deadline) return std::unexpected(Error::Timeout());
    return CompleteHandshake(detail::RemainingTimeoutMs(deadline, zero_timeout));
  }
  [[nodiscard]] Result<void> Flush(std::uint32_t timeout_ms = 5000) noexcept { return FlushPendingCiphertext(timeout_ms); }
  [[nodiscard]] bool HasPendingCiphertext() const noexcept {
    return pending_cipher_off_ < pending_cipher_len_ || (tls_ && tls_->HasPendingCiphertextOut());
  }
  [[nodiscard]] Result<bool> StepHandshake(std::uint32_t timeout_ms = 50) noexcept {
    if (!tls_.has_value() || !tcp_.IsOpen()) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    if (auto drove = tls_->DriveHandshake(); !drove) return std::unexpected(drove.error());
    if (auto flushed = FlushPendingCiphertext(timeout_ms); !flushed) return std::unexpected(flushed.error());
    if (tls_->IsHandshakeComplete()) return true;
    std::array<std::uint8_t, 16384> wire_buf{};
    auto n = tcp_.ReadSome(wire_buf, timeout_ms);
    if (!n) {
      if (timeout_ms == 0 && n.error() == Error::Timeout()) return false;
      return std::unexpected(n.error());
    }
    if (*n == 0) return std::unexpected(Error::FromProto(ProtoErrorCode::kTlsHandshakeFailed));
    if (auto fed = tls_->FeedCiphertext(std::span<const std::uint8_t>{wire_buf.data(), *n}); !fed) {
      return std::unexpected(fed.error());
    }
    if (auto flushed = FlushPendingCiphertext(timeout_ms); !flushed) return std::unexpected(flushed.error());
    return tls_->IsHandshakeComplete();
  }
  [[nodiscard]] Result<void> CompleteHandshake(std::uint32_t timeout_ms = 5000) noexcept {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    const bool zero_timeout = (timeout_ms == 0);
    while (!IsHandshakeComplete()) {
      if (!zero_timeout && std::chrono::steady_clock::now() >= deadline) return std::unexpected(Error::Timeout());
      auto step = StepHandshake(detail::RemainingTimeoutMs(deadline, zero_timeout));
      if (!step) return std::unexpected(step.error());
    }
    return FlushPendingCiphertext(detail::RemainingTimeoutMs(deadline, zero_timeout));
  }
  [[nodiscard]] Result<std::size_t> WriteSome(std::span<const std::uint8_t> data, std::uint32_t timeout_ms = 5000) noexcept {
    if (!tls_.has_value() || !tcp_.IsOpen()) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    }
    if (poison_error_) return std::unexpected(*poison_error_);
    if (data.empty()) return 0uz;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    const bool zero_timeout = (timeout_ms == 0);
    if (HasPendingCiphertext()) {
      if (auto flushed = FlushPendingCiphertext(detail::RemainingTimeoutMs(deadline, zero_timeout)); !flushed) {
        return std::unexpected(flushed.error());
      }
    }
    auto accepted = tls_->WritePlaintext(data);
    if (!accepted) return std::unexpected(accepted.error());
    if (*accepted == 0) return std::unexpected(Error::Timeout());
    if (auto flushed = FlushPendingCiphertext(detail::RemainingTimeoutMs(deadline, zero_timeout));
        !flushed && flushed.error() != Error::Timeout()) {
      return std::unexpected(flushed.error());
    }
    return *accepted;
  }
  [[nodiscard]] Result<void> WriteAll(std::span<const std::uint8_t> data, std::uint32_t timeout_ms = 5000) noexcept {
    if (!tls_.has_value() || !tcp_.IsOpen()) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    if (poison_error_) return std::unexpected(*poison_error_);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    const bool zero_timeout = (timeout_ms == 0);
    if (auto flushed = FlushPendingCiphertext(detail::RemainingTimeoutMs(deadline, zero_timeout)); !flushed)
      return std::unexpected(flushed.error());
    while (!data.empty()) {
      if (!zero_timeout && std::chrono::steady_clock::now() >= deadline) return std::unexpected(Error::Timeout());
      auto accepted = tls_->WritePlaintext(data);
      if (!accepted) return std::unexpected(accepted.error());
      data = data.subspan(*accepted);
      if (auto flushed = FlushPendingCiphertext(detail::RemainingTimeoutMs(deadline, zero_timeout)); !flushed)
        return std::unexpected(flushed.error());
      if (*accepted == 0 && !data.empty()) return std::unexpected(Error::BufferOverflow());
    }
    return FlushPendingCiphertext(detail::RemainingTimeoutMs(deadline, zero_timeout));
  }
  [[nodiscard]] Result<std::size_t> ReadSome(std::span<std::uint8_t> out, std::uint32_t timeout_ms = 5000) noexcept {
    if (!tls_.has_value() || !tcp_.IsOpen()) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    }
    if (out.empty()) return 0uz;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    const bool zero_timeout = (timeout_ms == 0);
    std::array<std::uint8_t, 16384> wire_buf{};
    for (;;) {
      auto plain = tls_->ReadPlaintext(out);
      if (!plain) return std::unexpected(plain.error());
      if (*plain > 0) {
        if (!deferred_flush_error_ && HasPendingCiphertext()) {
          if (auto flushed = FlushPendingCiphertext(0); !flushed && flushed.error() != Error::Timeout()) {
            deferred_flush_error_ = flushed.error();
          }
        }
        return *plain;
      }
      if (deferred_flush_error_) return std::unexpected(*std::exchange(deferred_flush_error_, std::nullopt));
      if (poison_error_) return std::unexpected(*poison_error_);
      if (!zero_timeout && std::chrono::steady_clock::now() >= deadline) return std::unexpected(Error::Timeout());
      if (auto flushed = FlushPendingCiphertext(detail::RemainingTimeoutMs(deadline, zero_timeout)); !flushed) {
        return std::unexpected(flushed.error());
      }
      if (tls_->IsPeerClosed()) return 0uz;
      auto wire_n = tcp_.ReadSome(wire_buf, detail::RemainingTimeoutMs(deadline, zero_timeout));
      if (!wire_n) return std::unexpected(wire_n.error());
      if (*wire_n == 0) return 0uz;
      auto fed = tls_->FeedCiphertext(std::span<const std::uint8_t>{wire_buf.data(), *wire_n});
      if (!fed) return std::unexpected(fed.error());
    }
  }
  void Close() noexcept {
    if (tls_.has_value() && tcp_.IsOpen() && !poison_error_) {
      if (tls_->SendCloseNotify()) {
        [[maybe_unused]] const auto flushed = FlushPendingCiphertext(200);
      }
    }
    tcp_.Close();
    ResetCipherState();
  }
  [[nodiscard]] bool IsOpen() const noexcept { return tcp_.IsOpen() && tls_.has_value() && !poison_error_; }
  [[nodiscard]] bool IsHandshakeComplete() const noexcept { return tls_.has_value() && tls_->IsHandshakeComplete(); }
  [[nodiscard]] AlpnProtocol NegotiatedAlpn() const noexcept {
    return tls_.has_value() ? tls_->NegotiatedAlpn() : AlpnProtocol::kNone;
  }
  [[nodiscard]] TcpTransport& Tcp() noexcept { return tcp_; }
  [[nodiscard]] const TcpTransport& Tcp() const noexcept { return tcp_; }
  [[nodiscard]] std::optional<TlsSession>& Tls() noexcept { return tls_; }
  [[nodiscard]] const std::optional<TlsSession>& Tls() const noexcept { return tls_; }
};
}  // namespace nexora
