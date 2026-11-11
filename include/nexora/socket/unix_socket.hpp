#pragma once

#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <nexora/error/runtime_error.hpp>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace nexora {

namespace detail {

[[nodiscard]] inline Error MapUnixSocketErrno(int err) noexcept {
  switch (err) {
    case 0:
      return Error{};
    case ETIMEDOUT:
      return Error::Timeout();
    case ECANCELED:
      return Error::Cancelled();
    case ECONNREFUSED:
    case ENOENT:
    case EAGAIN:
      return Error::FromRuntime(RuntimeErrorCode::kConnectionRefused);
    case ECONNRESET:
    case EPIPE:
    case ECONNABORTED:
      return Error::FromRuntime(RuntimeErrorCode::kConnectionReset);
    case ENOTCONN:
    case EBADF:
      return Error::FromRuntime(RuntimeErrorCode::kConnectionClosed);
    case EINVAL:
    case ENAMETOOLONG:
      return Error::InvalidArgument();
    default:
      return Error::FromErrno(err);
  }
}

[[nodiscard]] inline Result<void> WaitFdReadyUntil(int fd, short events, std::chrono::steady_clock::time_point deadline,
                                                   bool zero_timeout) noexcept {
  if (fd < 0) {
    return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
  }
  for (;;) {
    int wait_ms = 0;
    if (!zero_timeout) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        return std::unexpected(Error::Timeout());
      }
      const auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
      if (rem > std::numeric_limits<int>::max()) {
        wait_ms = std::numeric_limits<int>::max();
      } else {
        wait_ms = static_cast<int>(rem > 0 ? rem : 1);
      }
    }
    struct ::pollfd pfd{
        .fd = fd,
        .events = events,
        .revents = 0,
    };
    const int rc = ::poll(&pfd, 1, wait_ms);
    if (rc > 0) {
      if ((pfd.revents & POLLNVAL) != 0) {
        return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
      }
      return {};
    }
    if (rc == 0) {
      return std::unexpected(Error::Timeout());
    }
    if (errno == EINTR) {
      continue;
    }
    return std::unexpected(MapUnixSocketErrno(errno));
  }
}

[[nodiscard]] inline Result<void> WaitFdReady(int fd, short events, std::uint32_t timeout_ms) noexcept {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  return WaitFdReadyUntil(fd, events, deadline, timeout_ms == 0);
}

[[nodiscard]] inline Result<::sockaddr_un> MakeUnixSockaddr(std::string_view path) noexcept {
  ::sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (path.empty() || path.size() >= sizeof(addr.sun_path)) {
    return std::unexpected(Error::InvalidArgument());
  }
  std::memcpy(addr.sun_path, path.data(), path.size());
  addr.sun_path[path.size()] = '\0';
  return addr;
}

}  // namespace detail

class UnixSocket {
  int fd_{-1};
  std::string path_{};

  [[nodiscard]] Result<std::size_t> WriteUntil(std::span<const std::uint8_t> data,
                                               std::chrono::steady_clock::time_point deadline,
                                               bool zero_timeout) const noexcept {
    if (fd_ < 0) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    }
    if (data.empty()) {
      return std::size_t{0};
    }
    for (;;) {
      const ::ssize_t n = ::send(fd_, data.data(), data.size(), MSG_NOSIGNAL);
      if (n >= 0) {
        return static_cast<std::size_t>(n);
      }
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        auto waited = detail::WaitFdReadyUntil(fd_, POLLOUT, deadline, zero_timeout);
        if (!waited) {
          return std::unexpected(waited.error());
        }
        continue;
      }
      return std::unexpected(detail::MapUnixSocketErrno(errno));
    }
  }

 public:
  constexpr UnixSocket() noexcept = default;
  explicit UnixSocket(int fd, std::string path = {}) noexcept : fd_(fd), path_(std::move(path)) {}

  UnixSocket(const UnixSocket&) = delete ("single-owner UnixSocket handle; move instead");
  UnixSocket& operator=(const UnixSocket&) = delete ("single-owner UnixSocket handle; move instead");

  UnixSocket(UnixSocket&& other) noexcept : fd_(std::exchange(other.fd_, -1)), path_(std::move(other.path_)) {
    other.path_ = {};
  }

  UnixSocket& operator=(UnixSocket&& other) noexcept {
    if (this != &other) {
      Close();
      fd_ = std::exchange(other.fd_, -1);
      path_ = std::move(other.path_);
      other.path_ = {};
    }
    return *this;
  }

  ~UnixSocket() noexcept { Close(); }

  [[nodiscard]] static Result<std::pair<UnixSocket, UnixSocket>> CreatePair() noexcept {
    std::array<int, 2> fds{-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds.data()) != 0) {
      return std::unexpected(detail::MapUnixSocketErrno(errno));
    }
    return std::pair<UnixSocket, UnixSocket>{UnixSocket{fds[0]}, UnixSocket{fds[1]}};
  }

  [[nodiscard]] static Result<std::pair<UnixSocket, UnixSocket>> FromPair() noexcept { return CreatePair(); }

  [[nodiscard]] static Result<UnixSocket> Connect(std::string_view path, std::uint32_t timeout_ms = 5000) noexcept {
    UnixSocket sock{};
    auto res = sock.ConnectTo(path, timeout_ms);
    if (!res) {
      return std::unexpected(res.error());
    }
    return sock;
  }

  [[nodiscard]] Result<void> ConnectTo(std::string_view path, std::uint32_t timeout_ms = 5000) noexcept {
    auto addr = detail::MakeUnixSockaddr(path);
    if (!addr) {
      return std::unexpected(addr.error());
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    Close();
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
      return std::unexpected(detail::MapUnixSocketErrno(errno));
    }
    fd_ = fd;
    path_.assign(path.data(), path.size());

    const int rc = ::connect(fd_, reinterpret_cast<const ::sockaddr*>(&*addr), sizeof(::sockaddr_un));
    if (rc == 0) {
      return {};
    }
    if (errno != EINPROGRESS && errno != EALREADY) {
      const int err = errno;
      Close();
      return std::unexpected(detail::MapUnixSocketErrno(err));
    }
    auto waited = detail::WaitFdReadyUntil(fd_, POLLOUT, deadline, timeout_ms == 0);
    if (!waited) {
      Close();
      return std::unexpected(waited.error());
    }
    int so_err = 0;
    ::socklen_t len = sizeof(so_err);
    if (::getsockopt(fd_, SOL_SOCKET, SO_ERROR, &so_err, &len) != 0) {
      const int err = errno;
      Close();
      return std::unexpected(detail::MapUnixSocketErrno(err));
    }
    if (so_err != 0) {
      Close();
      return std::unexpected(detail::MapUnixSocketErrno(so_err));
    }
    return {};
  }

  [[nodiscard]] Result<std::size_t> Write(std::span<const std::uint8_t> data, std::uint32_t timeout_ms = 5000) noexcept {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    return this->WriteUntil(data, deadline, timeout_ms == 0);
  }

  [[nodiscard]] Result<void> WriteAll(std::span<const std::uint8_t> data, std::uint32_t timeout_ms = 5000) noexcept {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    const bool zero_timeout = (timeout_ms == 0);
    std::size_t offset = 0;
    while (offset < data.size()) {
      auto written = this->WriteUntil(data.subspan(offset), deadline, zero_timeout);
      if (!written) {
        return std::unexpected(written.error());
      }
      if (*written == 0) {
        return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
      }
      offset += *written;
    }
    return {};
  }

  [[nodiscard]] Result<std::size_t> ReadSome(std::span<std::uint8_t> out, std::uint32_t timeout_ms = 5000) const noexcept {
    if (fd_ < 0) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    }
    if (out.empty()) {
      return std::size_t{0};
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    const bool zero_timeout = (timeout_ms == 0);
    for (;;) {
      const ::ssize_t n = ::recv(fd_, out.data(), out.size(), 0);
      if (n >= 0) {
        return static_cast<std::size_t>(n);
      }
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        auto waited = detail::WaitFdReadyUntil(fd_, POLLIN, deadline, zero_timeout);
        if (!waited) {
          return std::unexpected(waited.error());
        }
        continue;
      }
      return std::unexpected(detail::MapUnixSocketErrno(errno));
    }
  }

  void ShutdownWrite() const noexcept {
    if (fd_ >= 0) {
      static_cast<void>(::shutdown(fd_, SHUT_WR));
    }
  }

  void Close() noexcept {
    if (fd_ >= 0) {
      static_cast<void>(::close(std::exchange(fd_, -1)));
    }
  }

  [[nodiscard]] constexpr bool IsOpen() const noexcept { return fd_ >= 0; }
  [[nodiscard]] constexpr bool IsClosed() const noexcept { return fd_ < 0; }
  [[nodiscard]] constexpr int NativeFd() const noexcept { return fd_; }
  [[nodiscard]] constexpr int Fd() const noexcept { return fd_; }
  [[nodiscard]] constexpr std::string_view Path() const noexcept { return path_; }
  [[nodiscard]] int ReleaseFd() noexcept { return std::exchange(fd_, -1); }
};

class UnixListener {
  int fd_{-1};
  std::string path_{};
  dev_t bound_dev_{0};
  ino_t bound_ino_{0};
  bool bound_id_{false};

  void CaptureIdentity() noexcept {
    struct ::stat st{};
    if (!path_.empty() && ::lstat(path_.c_str(), &st) == 0 && S_ISSOCK(st.st_mode)) {
      bound_dev_ = st.st_dev;
      bound_ino_ = st.st_ino;
      bound_id_ = true;
    }
  }

 public:
  constexpr UnixListener() noexcept = default;
  UnixListener(int fd, std::string path) noexcept : fd_(fd), path_(std::move(path)) { CaptureIdentity(); }

  UnixListener(const UnixListener&) = delete ("single-owner UnixListener handle; move instead");
  UnixListener& operator=(const UnixListener&) = delete ("single-owner UnixListener handle; move instead");

  UnixListener(UnixListener&& other) noexcept
      : fd_(std::exchange(other.fd_, -1)),
        path_(std::move(other.path_)),
        bound_dev_(std::exchange(other.bound_dev_, 0)),
        bound_ino_(std::exchange(other.bound_ino_, 0)),
        bound_id_(std::exchange(other.bound_id_, false)) {
    other.path_ = {};
  }

  UnixListener& operator=(UnixListener&& other) noexcept {
    if (this != &other) {
      Close();
      fd_ = std::exchange(other.fd_, -1);
      path_ = std::move(other.path_);
      other.path_ = {};
      bound_dev_ = std::exchange(other.bound_dev_, 0);
      bound_ino_ = std::exchange(other.bound_ino_, 0);
      bound_id_ = std::exchange(other.bound_id_, false);
    }
    return *this;
  }

  ~UnixListener() noexcept { Close(); }

  [[nodiscard]] static Result<UnixListener> Bind(std::string_view path, int backlog = 64) noexcept {
    auto addr = detail::MakeUnixSockaddr(path);
    if (!addr) {
      return std::unexpected(addr.error());
    }
    struct ::stat existing{};
    if (::lstat(addr->sun_path, &existing) == 0) {
      if (!S_ISSOCK(existing.st_mode)) {
        return std::unexpected(Error::FromErrno(EADDRINUSE));
      }
      static_cast<void>(::unlink(addr->sun_path));
    } else if (errno != ENOENT) {
      return std::unexpected(detail::MapUnixSocketErrno(errno));
    }
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
      return std::unexpected(detail::MapUnixSocketErrno(errno));
    }
    if (::bind(fd, reinterpret_cast<const ::sockaddr*>(&*addr), sizeof(::sockaddr_un)) != 0) {
      const int err = errno;
      static_cast<void>(::close(fd));
      return std::unexpected(detail::MapUnixSocketErrno(err));
    }
    if (::listen(fd, backlog) != 0) {
      const int err = errno;
      static_cast<void>(::close(fd));
      static_cast<void>(::unlink(addr->sun_path));
      return std::unexpected(detail::MapUnixSocketErrno(err));
    }
    return UnixListener{fd, std::string(path)};
  }

  [[nodiscard]] Result<UnixSocket> Accept(std::uint32_t timeout_ms = 5000) noexcept {
    if (fd_ < 0) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    const bool zero_timeout = (timeout_ms == 0);
    for (;;) {
      const int client_fd = ::accept4(fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (client_fd >= 0) {
        return UnixSocket{client_fd, path_};
      }
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        auto waited = detail::WaitFdReadyUntil(fd_, POLLIN, deadline, zero_timeout);
        if (!waited) {
          return std::unexpected(waited.error());
        }
        continue;
      }
      return std::unexpected(detail::MapUnixSocketErrno(errno));
    }
  }

  void Close() noexcept {
    if (fd_ < 0) return;
    static_cast<void>(::close(std::exchange(fd_, -1)));
    if (!path_.empty() && bound_id_) {
      struct ::stat st{};
      if (::lstat(path_.c_str(), &st) == 0 && S_ISSOCK(st.st_mode) && st.st_dev == bound_dev_ && st.st_ino == bound_ino_) {
        static_cast<void>(::unlink(path_.c_str()));
      }
    }
    path_.clear();
    bound_dev_ = 0;
    bound_ino_ = 0;
    bound_id_ = false;
  }

  [[nodiscard]] constexpr int Fd() const noexcept { return fd_; }
  [[nodiscard]] constexpr std::string_view Path() const noexcept { return path_; }
};

}  // namespace nexora
