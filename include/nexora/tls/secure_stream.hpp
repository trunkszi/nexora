#pragma once
#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <nexora/tls/detail/uring_transport.hpp>
#include <nexora/tls/tls_session.hpp>
#include <optional>
#include <span>
#include <utility>

namespace nexora {
namespace detail {
using Deadline = std::chrono::steady_clock::time_point;
[[nodiscard]] inline Deadline After(std::uint32_t timeout_ms) noexcept {
  return std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
}
[[nodiscard]] inline std::uint32_t Remaining(Deadline deadline) noexcept {
  const auto now = std::chrono::steady_clock::now();
  if (now >= deadline) return 0;
  const auto millis = std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count();
  return static_cast<std::uint32_t>(std::min<std::int64_t>(millis, UINT32_MAX));
}
[[nodiscard]] inline std::uint64_t SteadyNowNs() noexcept {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}
}  // namespace detail

class SecureStream {
  detail::UringTransport transport_;
  std::optional<TlsSession> tls_{};
  std::array<std::uint8_t, 32768> tx_ciphertext_{};
  std::size_t tx_off_{0};
  std::size_t tx_len_{0};
  std::array<std::uint8_t, 18437> rx_ciphertext_{};
  std::optional<Error> poison_error_{};
  std::optional<Error> deferred_flush_error_{};

  void ResetTlsState() noexcept {
    tls_.reset();
    tx_off_ = 0;
    tx_len_ = 0;
    poison_error_.reset();
    deferred_flush_error_.reset();
  }

  [[nodiscard]] Result<void> DrainTxBuffer(detail::Deadline deadline) noexcept {
    while (tx_off_ < tx_len_) {
      const auto rem = detail::Remaining(deadline);
      if (rem == 0) return std::unexpected(Error::Timeout());
      auto wrote = transport_.WriteSome(std::span(tx_ciphertext_).subspan(tx_off_, tx_len_ - tx_off_), rem);
      if (!wrote) {
        if (wrote.error() != Error::Timeout()) poison_error_ = wrote.error();
        return std::unexpected(wrote.error());
      }
      tx_off_ += *wrote;
    }
    tx_off_ = 0;
    tx_len_ = 0;
    return {};
  }

  [[nodiscard]] Result<void> FlushDeadline(detail::Deadline deadline) noexcept {
    if (poison_error_) return std::unexpected(*poison_error_);
    if (auto drained = DrainTxBuffer(deadline); !drained) return drained;
    while (tls_ && tls_->HasPendingCiphertextOut()) {
      auto count = tls_->TakeCiphertext(tx_ciphertext_);
      if (!count) {
        poison_error_ = count.error();
        return std::unexpected(count.error());
      }
      if (*count == 0) return std::unexpected(Error::FromProto(ProtoErrorCode::kTlsIoError));
      tx_off_ = 0;
      tx_len_ = *count;
      if (auto drained = DrainTxBuffer(deadline); !drained) return drained;
    }
    return {};
  }

  [[nodiscard]] Result<void> ReceiveCiphertext(detail::Deadline deadline) noexcept {
    auto count = transport_.ReadSome(rx_ciphertext_, detail::Remaining(deadline));
    if (!count) return std::unexpected(count.error());
    if (*count == 0) return std::unexpected(Error::FromProto(ProtoErrorCode::kTlsIoError));
    auto consumed = tls_->FeedCiphertext(std::span(rx_ciphertext_).first(*count));
    if (!consumed) return std::unexpected(consumed.error());
    if (*consumed != *count) return std::unexpected(Error::FromProto(ProtoErrorCode::kTlsIoError));
    return {};
  }

  [[nodiscard]] Result<void> Handshake(detail::Deadline deadline) noexcept {
    for (;;) {
      if (poison_error_) return std::unexpected(*poison_error_);
      if (auto drove = tls_->DriveHandshake(); !drove) return drove;
      if (auto flushed = FlushDeadline(deadline); !flushed) return flushed;
      if (tls_->IsHandshakeComplete()) return {};
      if (auto read = ReceiveCiphertext(deadline); !read) return read;
    }
  }

 public:
  explicit SecureStream(uring::Proactor& proactor, cares::Resolver<>* resolver = nullptr,
                        std::uint8_t subsystem = kDefaultSocketIoSubsystemId, CompletionRoute fallback = {},
                        detail::ParkedOperations* parked = nullptr) noexcept
      : transport_(proactor, resolver, subsystem, fallback, parked) {}
  [[nodiscard]] std::size_t ParkedCount() const noexcept { return transport_.ParkedCount(); }
  [[nodiscard]] bool HasPendingCiphertext() const noexcept {
    return tx_off_ < tx_len_ || (tls_ && tls_->HasPendingCiphertextOut());
  }
  [[nodiscard]] Result<void> Connect(const cares::Endpoint& endpoint, std::uint32_t timeout_ms) noexcept {
    ResetTlsState();
    return transport_.Connect(endpoint, timeout_ms);
  }
  [[nodiscard]] Result<void> Accept(int listener, std::uint32_t timeout_ms) noexcept {
    ResetTlsState();
    return transport_.Accept(listener, timeout_ms);
  }
  [[nodiscard]] Result<void> Adopt(int fd) noexcept {
    ResetTlsState();
    return transport_.Adopt(fd);
  }
  [[nodiscard]] Result<void> StartClient(const TlsClientConfig& config, std::string_view name,
                                         std::uint32_t timeout_ms) noexcept {
    ResetTlsState();
    auto session = TlsSession::CreateClient(config, name);
    if (!session) return std::unexpected(session.error());
    tls_.emplace(std::move(*session));
    return Handshake(detail::After(timeout_ms));
  }
  [[nodiscard]] Result<void> StartServer(const TlsServerConfig& config, std::uint32_t timeout_ms) noexcept {
    ResetTlsState();
    auto session = TlsSession::CreateServer(config);
    if (!session) return std::unexpected(session.error());
    tls_.emplace(std::move(*session));
    return Handshake(detail::After(timeout_ms));
  }
  [[nodiscard]] Result<void> CompleteHandshake(std::uint32_t timeout_ms) noexcept {
    if (!tls_) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    return Handshake(detail::After(timeout_ms));
  }
  [[nodiscard]] Result<void> Flush(std::uint32_t timeout_ms) noexcept {
    if (!tls_) return {};
    return FlushDeadline(detail::After(timeout_ms));
  }
  [[nodiscard]] const std::optional<cares::Endpoint>& Peer() const noexcept { return transport_.Peer(); }
  [[nodiscard]] AlpnProtocol Alpn() const noexcept { return tls_ ? tls_->NegotiatedAlpn() : AlpnProtocol::kNone; }
  [[nodiscard]] bool IsOpen() const noexcept {
    return transport_.IsOpen() && !poison_error_ && (!tls_ || !tls_->IsPeerClosed());
  }
  [[nodiscard]] Result<std::size_t> WriteSome(std::span<const std::uint8_t> data, std::uint32_t timeout_ms) noexcept {
    if (!tls_) return transport_.WriteSome(data, timeout_ms);
    if (poison_error_) return std::unexpected(*poison_error_);
    if (data.empty()) return 0uz;
    const auto deadline = detail::After(timeout_ms);
    if (HasPendingCiphertext()) {
      if (auto flushed = FlushDeadline(deadline); !flushed) return std::unexpected(flushed.error());
    }
    auto written = tls_->WritePlaintext(data);
    if (!written) return std::unexpected(written.error());
    if (*written == 0) return std::unexpected(Error::Timeout());
    if (auto flushed = FlushDeadline(deadline); !flushed && flushed.error() != Error::Timeout()) {
      return std::unexpected(flushed.error());
    }
    return *written;
  }
  [[nodiscard]] Result<void> WriteAll(std::span<const std::uint8_t> data, std::uint32_t timeout_ms) noexcept {
    if (!tls_) return transport_.WriteAll(data, timeout_ms);
    if (poison_error_) return std::unexpected(*poison_error_);
    const auto deadline = detail::After(timeout_ms);
    if (auto flushed = FlushDeadline(deadline); !flushed) return flushed;
    while (!data.empty()) {
      if (detail::Remaining(deadline) == 0) return std::unexpected(Error::Timeout());
      auto written = tls_->WritePlaintext(data);
      if (!written) return std::unexpected(written.error());
      if (*written > data.size()) return std::unexpected(Error::FromProto(ProtoErrorCode::kTlsIoError));
      if (auto flushed = FlushDeadline(deadline); !flushed) return flushed;
      if (*written == 0) return std::unexpected(Error::FromProto(ProtoErrorCode::kTlsIoError));
      data = data.subspan(*written);
    }
    return {};
  }
  [[nodiscard]] Result<std::size_t> ReadSome(std::span<std::uint8_t> out, std::uint32_t timeout_ms) noexcept {
    if (!tls_) return transport_.ReadSome(out, timeout_ms);
    if (out.empty()) return 0uz;
    const auto deadline = detail::After(timeout_ms);
    for (;;) {
      auto read = tls_->ReadPlaintext(out);
      if (!read) return std::unexpected(read.error());
      if (*read != 0) {
        if (!deferred_flush_error_ && HasPendingCiphertext()) {
          if (auto flushed = FlushDeadline(detail::After(0)); !flushed && flushed.error() != Error::Timeout()) {
            deferred_flush_error_ = flushed.error();
          }
        }
        return *read;
      }
      if (deferred_flush_error_) return std::unexpected(*std::exchange(deferred_flush_error_, std::nullopt));
      if (poison_error_) return std::unexpected(*poison_error_);
      if (auto flushed = FlushDeadline(deadline); !flushed) return std::unexpected(flushed.error());
      if (tls_->IsPeerClosed()) return 0uz;
      if (auto received = ReceiveCiphertext(deadline); !received) return std::unexpected(received.error());
    }
  }
  [[nodiscard]] Result<void> SendCloseNotify(std::uint32_t timeout_ms) noexcept {
    if (!tls_) return {};
    if (poison_error_) return std::unexpected(*poison_error_);
    if (auto sent = tls_->SendCloseNotify(); !sent) return sent;
    return FlushDeadline(detail::After(timeout_ms));
  }
  void Close() noexcept {
    transport_.Close();
    ResetTlsState();
  }
};

}  // namespace nexora
