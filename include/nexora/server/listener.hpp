#pragma once

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bit>
#include <cerrno>
#include <concepts>
#include <cstdint>
#include <nexora/error/runtime_error.hpp>
#include <utility>

namespace nexora {
namespace detail {
template <std::unsigned_integral T>
[[nodiscard]] constexpr T ByteOrderSwapIfLittle(T value) noexcept {
  if constexpr (std::endian::native == std::endian::little) {
    return std::byteswap(value);
  }
  return value;
}
}  // namespace detail

class LoopbackListener {
  int fd_{-1};
  std::uint16_t port_{0};
  explicit LoopbackListener(int fd) noexcept : fd_(fd) {}

 public:
  LoopbackListener(const LoopbackListener&) = delete ("single-owner listener fd; move instead");
  LoopbackListener& operator=(const LoopbackListener&) = delete ("single-owner listener fd; move instead");
  LoopbackListener(LoopbackListener&& other) noexcept : fd_(std::exchange(other.fd_, -1)), port_(other.port_) {}
  LoopbackListener& operator=(LoopbackListener&&) = delete ("listener handle cannot be reassigned after bind");
  ~LoopbackListener() noexcept {
    if (fd_ >= 0) static_cast<void>(::close(fd_));
  }
  [[nodiscard]] static Result<LoopbackListener> Bind(std::uint16_t port = 0) noexcept {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return std::unexpected(Error::FromErrno(errno));
    LoopbackListener listener(fd);
    const int reuse = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) return std::unexpected(Error::FromErrno(errno));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = detail::ByteOrderSwapIfLittle(static_cast<std::uint32_t>(INADDR_LOOPBACK));
    address.sin_port = detail::ByteOrderSwapIfLittle(port);
    const auto* raw_addr = static_cast<const sockaddr*>(static_cast<const void*>(&address));
    if (::bind(fd, raw_addr, sizeof(address)) < 0 || ::listen(fd, 64) < 0) return std::unexpected(Error::FromErrno(errno));
    socklen_t size = sizeof(address);
    if (::getsockname(fd, static_cast<sockaddr*>(static_cast<void*>(&address)), &size) < 0)
      return std::unexpected(Error::FromErrno(errno));
    listener.port_ = detail::ByteOrderSwapIfLittle(address.sin_port);
    return listener;
  }
  [[nodiscard]] int RawFd() const noexcept { return fd_; }
  [[nodiscard]] std::uint16_t Port() const noexcept { return port_; }
};
}  // namespace nexora
