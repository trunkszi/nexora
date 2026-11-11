#pragma once

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cares/cares.hpp>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <nexora/dispatch/completion_routes.hpp>
#include <nexora/error/runtime_error.hpp>
#include <nexora/socket/socket_word.hpp>
#include <nexora/tls/tls_session.hpp>
#include <optional>
#include <span>
#include <uring/uring.hpp>
#include <utility>
#include <vector>

namespace nexora {

struct SocketConfig {
  std::size_t rx_buffer_capacity{64 * 1024};
  std::size_t tx_buffer_capacity{64 * 1024};
  std::chrono::milliseconds connect_timeout{5000};
  std::chrono::milliseconds read_timeout{30000};
  std::chrono::milliseconds write_timeout{30000};
  bool nodelay{true};
};

namespace detail {

[[nodiscard]] inline Result<int> CreateTcpFd(int domain, bool non_blocking, bool nodelay) noexcept {
  const int flags = SOCK_STREAM | SOCK_CLOEXEC | (non_blocking ? SOCK_NONBLOCK : 0);
  const int fd = ::socket(domain, flags, IPPROTO_TCP);
  if (fd < 0) return std::unexpected(Error::FromErrno(errno));
  if (nodelay) {
    const int one = 1;
    if (::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0) {
      const int err = errno;
      static_cast<void>(::close(fd));
      return std::unexpected(Error::FromErrno(err));
    }
  }
  return fd;
}

[[nodiscard]] inline Result<int> CreateNonblockingTcpFd(int domain, bool nodelay) noexcept {
  return CreateTcpFd(domain, true, nodelay);
}

}  // namespace detail

class IoUringSocket {
  int fd_{-1};
  SocketWord word_{SocketWord::IdleWord()};
  std::optional<cares::Endpoint> peer_addr_{};
  std::optional<TlsSession> tls_{};
  SocketConfig config_{};
  std::vector<std::uint8_t> rx_buffer_{};
  std::vector<std::uint8_t> tx_buffer_{};
  uring::Proactor* proactor_{nullptr};
  detail::SocketDmaQuarantine* quarantine_{nullptr};
  void* shared_routes_ctx_{nullptr};
  bool (*shared_can_route_fn_)(const void*, std::uint8_t) noexcept {nullptr};
  uring::Result<void> (*shared_dispatch_fn_)(void*, const uring::Delivery&) noexcept {nullptr};
  std::optional<uring::UserDataToken> rx_token_{};
  std::optional<uring::UserDataToken> tx_token_{};
  std::optional<uring::UserDataToken> connect_token_{};
  std::int32_t last_rx_result_{0};
  std::int32_t last_tx_result_{0};
  std::int32_t last_connect_result_{0};
  std::uint16_t generation_{1};

  constexpr void BumpGeneration() noexcept {
    const auto next = static_cast<std::uint16_t>(generation_ + 1U);
    generation_ = next == 0U ? std::uint16_t{1} : next;
  }

  constexpr void ClearProactorBinding() noexcept {
    proactor_ = nullptr;
    quarantine_ = nullptr;
    shared_routes_ctx_ = nullptr;
    shared_can_route_fn_ = nullptr;
    shared_dispatch_fn_ = nullptr;
  }

  [[nodiscard]] constexpr bool HasTrackedToken() const noexcept {
    return rx_token_.has_value() || tx_token_.has_value() || connect_token_.has_value();
  }

  struct DrainDispatcher {
    IoUringSocket* self{nullptr};

    [[nodiscard]] bool CanRoute(std::uint8_t id) const noexcept {
      if (id == kSocketSubsystemId) return true;
      return self->shared_can_route_fn_ != nullptr && self->shared_can_route_fn_(self->shared_routes_ctx_, id);
    }

    [[nodiscard]] uring::Result<void> DispatchBatch(std::span<const uring::Delivery> deliveries) const noexcept {
      std::optional<uring::UringErrorCode> first_error{};
      for (const auto& delivery : deliveries) {
        const std::uint8_t id = uring::Subsystem(delivery.completion.token);
        if (id == kSocketSubsystemId) {
          auto mine = self->OnCompletion(delivery);
          if (mine.has_value() && *mine) continue;
        }
        if (self->shared_dispatch_fn_ == nullptr || self->shared_can_route_fn_ == nullptr) continue;
        auto routed = self->shared_dispatch_fn_(self->shared_routes_ctx_, delivery);
        if (!routed && routed.error() != uring::UringErrorCode::kNoEntry && !first_error.has_value()) {
          first_error = routed.error();
        }
      }
      if (first_error.has_value()) return std::unexpected(*first_error);
      return {};
    }
  };

  void DrainInFlightOnProactor() noexcept {
    if (proactor_ == nullptr || word_.InFlight() == 0) return;
    const auto cancelled = SubmitCancel();
    static_cast<void>(cancelled);
    if (!HasTrackedToken()) return;
    DrainDispatcher mux{.self = this};
    const uring::detail::LoopRequest bounded{
        .submit = true,
        .minimum = 0,
        .timeout = std::chrono::milliseconds(5),
    };
    for (std::size_t step = 0; step < 16 && word_.InFlight() > 0 && HasTrackedToken(); ++step) {
      auto poll_res = proactor_->Drive(uring::DriveMode::kPoll, mux);
      if (!poll_res && poll_res.error() == uring::UringErrorCode::kReentrantDrive) return;
      if (word_.InFlight() == 0 || !HasTrackedToken()) break;
      auto wait_res = proactor_->Drive(uring::DriveMode::kWait, mux, bounded);
      if (!wait_res && wait_res.error() == uring::UringErrorCode::kReentrantDrive) return;
    }
  }

 public:
  constexpr IoUringSocket() noexcept = default;

  IoUringSocket(const IoUringSocket&) = delete ("single-owner socket handle; move instead");
  IoUringSocket& operator=(const IoUringSocket&) = delete ("single-owner socket handle; move instead");

  IoUringSocket(IoUringSocket&& other) noexcept
      : fd_(std::exchange(other.fd_, -1)),
        word_(std::exchange(other.word_, SocketWord::IdleWord().WithPhase(SocketPhase::kClosed))),
        peer_addr_(other.peer_addr_),
        tls_(std::move(other.tls_)),
        config_(other.config_),
        rx_buffer_(std::move(other.rx_buffer_)),
        tx_buffer_(std::move(other.tx_buffer_)),
        proactor_(std::exchange(other.proactor_, nullptr)),
        quarantine_(std::exchange(other.quarantine_, nullptr)),
        shared_routes_ctx_(std::exchange(other.shared_routes_ctx_, nullptr)),
        shared_can_route_fn_(std::exchange(other.shared_can_route_fn_, nullptr)),
        shared_dispatch_fn_(std::exchange(other.shared_dispatch_fn_, nullptr)),
        rx_token_(std::exchange(other.rx_token_, std::nullopt)),
        tx_token_(std::exchange(other.tx_token_, std::nullopt)),
        connect_token_(std::exchange(other.connect_token_, std::nullopt)),
        last_rx_result_(std::exchange(other.last_rx_result_, 0)),
        last_tx_result_(std::exchange(other.last_tx_result_, 0)),
        last_connect_result_(std::exchange(other.last_connect_result_, 0)),
        generation_(other.generation_) {}

  IoUringSocket& operator=(IoUringSocket&& other) noexcept {
    if (this != &other) {
      Quiesce();
      fd_ = std::exchange(other.fd_, -1);
      word_ = std::exchange(other.word_, SocketWord::IdleWord().WithPhase(SocketPhase::kClosed));
      peer_addr_ = other.peer_addr_;
      tls_ = std::move(other.tls_);
      config_ = other.config_;
      rx_buffer_ = std::move(other.rx_buffer_);
      tx_buffer_ = std::move(other.tx_buffer_);
      proactor_ = std::exchange(other.proactor_, nullptr);
      quarantine_ = std::exchange(other.quarantine_, nullptr);
      shared_routes_ctx_ = std::exchange(other.shared_routes_ctx_, nullptr);
      shared_can_route_fn_ = std::exchange(other.shared_can_route_fn_, nullptr);
      shared_dispatch_fn_ = std::exchange(other.shared_dispatch_fn_, nullptr);
      rx_token_ = std::exchange(other.rx_token_, std::nullopt);
      tx_token_ = std::exchange(other.tx_token_, std::nullopt);
      connect_token_ = std::exchange(other.connect_token_, std::nullopt);
      last_rx_result_ = std::exchange(other.last_rx_result_, 0);
      last_tx_result_ = std::exchange(other.last_tx_result_, 0);
      last_connect_result_ = std::exchange(other.last_connect_result_, 0);
      generation_ = other.generation_;
    }
    return *this;
  }

  ~IoUringSocket() noexcept { Quiesce(); }

  void Quiesce() noexcept {
    if (fd_ < 0 && rx_buffer_.empty() && tx_buffer_.empty() && word_.InFlight() == 0) {
      ClearProactorBinding();
      return;
    }
    if (word_.InFlight() > 0) {
      DrainInFlightOnProactor();
    }
    const bool close_submitted = (word_.Phase() == SocketPhase::kCloseSubmitted);
    if (word_.InFlight() > 0) {
      if (quarantine_ != nullptr && HasTrackedToken()) {
        const std::uint64_t ring_inst = (proactor_ != nullptr) ? proactor_->Instance() : 0ULL;
        quarantine_->Park(ring_inst, std::exchange(fd_, -1), std::move(rx_buffer_), std::move(tx_buffer_),
                          std::exchange(rx_token_, std::nullopt), std::exchange(tx_token_, std::nullopt),
                          std::exchange(connect_token_, std::nullopt));
      } else if (fd_ >= 0 || HasTrackedToken()) {
        detail::LeakDmaBuffer(std::move(rx_buffer_));
        detail::LeakDmaBuffer(std::move(tx_buffer_));
        fd_ = -1;
        rx_token_.reset();
        tx_token_.reset();
        connect_token_.reset();
      }
      rx_buffer_.clear();
      tx_buffer_.clear();
      word_ = SocketWord::IdleWord().WithPhase(SocketPhase::kClosed);
      ClearProactorBinding();
      BumpGeneration();
      return;
    }
    rx_buffer_.clear();
    tx_buffer_.clear();
    if (!close_submitted && fd_ >= 0) {
      static_cast<void>(::close(fd_));
    }
    fd_ = -1;
    rx_token_.reset();
    tx_token_.reset();
    connect_token_.reset();
    word_ = SocketWord::IdleWord().WithPhase(SocketPhase::kClosed);
    ClearProactorBinding();
    BumpGeneration();
  }

  void Close() noexcept { Quiesce(); }

  template <std::size_t MaxRoutes>
  void BindProactor(uring::Proactor& proactor, CompletionRoutes<MaxRoutes>& shared_routes) noexcept {
    proactor_ = &proactor;
    quarantine_ = &shared_routes.Quarantine();
    shared_routes_ctx_ = static_cast<void*>(&shared_routes);
    shared_can_route_fn_ = +[](const void* ctx, std::uint8_t id) noexcept -> bool {
      return static_cast<const CompletionRoutes<MaxRoutes>*>(ctx)->CanRoute(id);
    };
    shared_dispatch_fn_ = +[](void* ctx, const uring::Delivery& d) noexcept -> uring::Result<void> {
      return static_cast<CompletionRoutes<MaxRoutes>*>(ctx)->Dispatch(d);
    };
  }

  void UnbindProactor() noexcept {
    if (word_.InFlight() > 0) {
      DrainInFlightOnProactor();
      if (word_.InFlight() > 0) {
        Quiesce();
        return;
      }
    }
    ClearProactorBinding();
  }

  void DetachProactor() noexcept { UnbindProactor(); }
  [[nodiscard]] constexpr bool HasProactor() const noexcept { return proactor_ != nullptr; }
  [[nodiscard]] constexpr std::uint16_t Generation() const noexcept { return generation_; }

  [[nodiscard]] constexpr uring::UserDataToken MakeToken(std::uint16_t slot = 1) const noexcept {
    return uring::MakeToken(slot, 0, kSocketSubsystemId, generation_);
  }

  [[nodiscard]] static IoUringSocket FromRawFd(int fd, SocketWord word, std::optional<cares::Endpoint> peer_addr = {},
                                               std::optional<TlsSession> tls = {}, SocketConfig config = {}) noexcept {
    IoUringSocket sock{};
    sock.fd_ = fd;
    sock.word_ = word;
    sock.peer_addr_ = peer_addr;
    sock.tls_ = std::move(tls);
    sock.config_ = config;
    sock.rx_buffer_.resize(config.rx_buffer_capacity, 0);
    sock.tx_buffer_.resize(std::max<std::size_t>(config.tx_buffer_capacity, sizeof(::sockaddr_storage)), 0);
    return sock;
  }

  [[nodiscard]] static Result<IoUringSocket> OpenTcp(int family, bool non_blocking = true, SocketConfig config = {}) noexcept {
    auto fd = detail::CreateTcpFd(family, non_blocking, config.nodelay);
    if (!fd) return std::unexpected(fd.error());
    return FromRawFd(*fd, SocketWord::IdleWord(), std::nullopt, std::nullopt, config);
  }

  [[nodiscard]] static Result<IoUringSocket> CreateTcpIpv4(SocketConfig config = {}) noexcept {
    return OpenTcp(AF_INET, true, config);
  }

  [[nodiscard]] static Result<IoUringSocket> CreateTcpIpv6(SocketConfig config = {}) noexcept {
    return OpenTcp(AF_INET6, true, config);
  }

  [[nodiscard]] static Result<IoUringSocket> CreateForEndpoint(const cares::Endpoint& endpoint,
                                                               SocketConfig config = {}) noexcept {
    return endpoint.ip.IsV6() ? CreateTcpIpv6(config) : CreateTcpIpv4(config);
  }

  [[nodiscard]] constexpr int NativeFd() const noexcept { return fd_; }
  [[nodiscard]] constexpr int RawFd() const noexcept { return fd_; }
  [[nodiscard]] constexpr int Fd() const noexcept { return fd_; }

  [[nodiscard]] constexpr const SocketWord& State() const noexcept { return word_; }
  [[nodiscard]] constexpr SocketWord& State() noexcept { return word_; }
  [[nodiscard]] constexpr SocketWord Word() const noexcept { return word_; }

  [[nodiscard]] constexpr SocketPhase Phase() const noexcept { return word_.Phase(); }
  [[nodiscard]] constexpr SocketSuperstate Superstate() const noexcept { return word_.Superstate(); }
  [[nodiscard]] constexpr std::uint32_t InFlightOps() const noexcept { return word_.InFlight(); }

  [[nodiscard]] constexpr std::optional<uring::UserDataToken> RxToken() const noexcept { return rx_token_; }
  [[nodiscard]] constexpr std::optional<uring::UserDataToken> TxToken() const noexcept { return tx_token_; }
  [[nodiscard]] constexpr std::optional<uring::UserDataToken> ConnectToken() const noexcept { return connect_token_; }
  [[nodiscard]] constexpr std::int32_t LastRxResult() const noexcept { return last_rx_result_; }
  [[nodiscard]] constexpr std::int32_t LastTxResult() const noexcept { return last_tx_result_; }
  [[nodiscard]] constexpr std::int32_t LastConnectResult() const noexcept { return last_connect_result_; }

  [[nodiscard]] constexpr std::optional<cares::Endpoint> PeerAddr() const noexcept { return peer_addr_; }
  [[nodiscard]] constexpr const SocketConfig& Config() const noexcept { return config_; }

  [[nodiscard]] constexpr const std::optional<TlsSession>& Tls() const noexcept { return tls_; }
  [[nodiscard]] constexpr std::optional<TlsSession>& TlsMut() noexcept { return tls_; }

  void AttachTls(TlsSession tls) noexcept { tls_.emplace(std::move(tls)); }

  [[nodiscard]] std::optional<TlsSession> TakeTls() noexcept {
    std::optional<TlsSession> out = std::move(tls_);
    tls_.reset();
    return out;
  }

  [[nodiscard]] std::span<const std::uint8_t> RxBuffer() const noexcept { return rx_buffer_; }
  [[nodiscard]] std::span<std::uint8_t> RxBufferMut() noexcept { return rx_buffer_; }
  [[nodiscard]] std::span<const std::uint8_t> TxBuffer() const noexcept { return tx_buffer_; }
  [[nodiscard]] std::span<std::uint8_t> TxBufferMut() noexcept { return tx_buffer_; }

  [[nodiscard]] Result<void> RenewBuffers() noexcept {
    if (word_.InFlight() > 0 || word_.Phase() == SocketPhase::kCancelling) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    }
    std::fill(rx_buffer_.begin(), rx_buffer_.end(), std::uint8_t{0});
    std::fill(tx_buffer_.begin(), tx_buffer_.end(), std::uint8_t{0});
    return {};
  }

  [[nodiscard]] Result<uring::UserDataToken> SubmitConnect(const cares::Endpoint& peer) noexcept {
    if ((!peer.ip.IsV4() && !peer.ip.IsV6()) || peer.port == 0) {
      return std::unexpected(Error::InvalidArgument());
    }
    if (proactor_ == nullptr || fd_ < 0 || connect_token_.has_value() || tx_token_.has_value() ||
        word_.Phase() != SocketPhase::kIdle || word_.InFlight() != 0) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    }
    if (tx_buffer_.size() < sizeof(::sockaddr_storage)) {
      tx_buffer_.resize(sizeof(::sockaddr_storage), 0);
    }
    const auto sa_val = peer.ToSockAddrValue();
    std::memcpy(tx_buffer_.data(), &sa_val.storage, sa_val.len);
    const SocketWord prev_word = word_;
    const auto prev_peer = peer_addr_;
    auto begun = BeginConnect(peer);
    if (!begun) return std::unexpected(begun.error());
    const auto prep =
        uring::ops::PrepareConnect(fd_, uring::ops::UserAddress{tx_buffer_.data()}, static_cast<std::uint32_t>(sa_val.len));
    auto armed = proactor_->Arm(kSocketSubsystemId, prep);
    if (!armed) {
      word_ = prev_word;
      peer_addr_ = prev_peer;
      return std::unexpected(Error::BufferOverflow());
    }
    connect_token_ = *armed;
    return *armed;
  }

  [[nodiscard]] Result<uring::UserDataToken> SubmitRecv(std::size_t max_bytes = 0) noexcept {
    if (proactor_ == nullptr || fd_ < 0 || rx_token_.has_value() || rx_buffer_.empty()) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    }
    const std::size_t len = (max_bytes == 0 || max_bytes > rx_buffer_.size()) ? rx_buffer_.size() : max_bytes;
    auto prep = uring::ops::PrepareRecv(fd_, std::span<std::uint8_t>{rx_buffer_.data(), len});
    if (!prep) return std::unexpected(Error::InvalidArgument());
    auto begun = BeginOp();
    if (!begun) return std::unexpected(begun.error());
    auto armed = proactor_->Arm(kSocketSubsystemId, *prep);
    if (!armed) {
      CompleteOp();
      return std::unexpected(Error::BufferOverflow());
    }
    rx_token_ = *armed;
    return *armed;
  }

  [[nodiscard]] Result<uring::UserDataToken> SubmitSend(std::span<const std::uint8_t> data) noexcept {
    if (proactor_ == nullptr || fd_ < 0 || tx_token_.has_value() || connect_token_.has_value() || data.empty() ||
        data.size() > tx_buffer_.size()) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    }
    std::memcpy(tx_buffer_.data(), data.data(), data.size());
    auto prep = uring::ops::PrepareSend(fd_, std::span<const std::uint8_t>{tx_buffer_.data(), data.size()});
    if (!prep) return std::unexpected(Error::InvalidArgument());
    auto begun = BeginOp();
    if (!begun) return std::unexpected(begun.error());
    auto armed = proactor_->Arm(kSocketSubsystemId, *prep);
    if (!armed) {
      CompleteOp();
      return std::unexpected(Error::BufferOverflow());
    }
    tx_token_ = *armed;
    return *armed;
  }

  [[nodiscard]] Result<void> SubmitCancel() noexcept {
    RequestCancel();
    if (proactor_ != nullptr) {
      if (rx_token_.has_value()) static_cast<void>(proactor_->Cancel(*rx_token_));
      if (tx_token_.has_value()) static_cast<void>(proactor_->Cancel(*tx_token_));
      if (connect_token_.has_value()) static_cast<void>(proactor_->Cancel(*connect_token_));
    }
    return {};
  }

  [[nodiscard]] Result<bool> OnCompletion(CompletionEvent cqe) noexcept {
    if (uring::Subsystem(cqe.token) != kSocketSubsystemId) {
      return std::unexpected(Error::InvalidArgument());
    }
    if (rx_token_.has_value() && cqe.token == *rx_token_) {
      rx_token_.reset();
      last_rx_result_ = cqe.result;
      CompleteOp();
      return true;
    }
    if (tx_token_.has_value() && cqe.token == *tx_token_) {
      tx_token_.reset();
      last_tx_result_ = cqe.result;
      CompleteOp();
      return true;
    }
    if (connect_token_.has_value() && cqe.token == *connect_token_) {
      connect_token_.reset();
      last_connect_result_ = cqe.result;
      if (cqe.result == 0 && (word_.Phase() == SocketPhase::kConnecting || word_.Phase() == SocketPhase::kCancelling)) {
        const auto opened = ConnectCompleted();
        static_cast<void>(opened);
      } else {
        CompleteOp();
        if (word_.Phase() == SocketPhase::kConnecting) {
          word_ = word_.TransitionTo(word_.InFlight() == 0 ? SocketPhase::kCloseReady : SocketPhase::kCancelling);
        }
      }
      return true;
    }
    return false;
  }

  [[nodiscard]] Result<bool> OnCompletion(const uring::Delivery& delivery) noexcept {
    if (proactor_ != nullptr && delivery.key.ring_instance != 0 && delivery.key.ring_instance != proactor_->Instance()) {
      return false;
    }
    return OnCompletion(delivery.completion);
  }

  void HandleCqe(CompletionEvent cqe) noexcept {
    const auto handled = OnCompletion(cqe);
    static_cast<void>(handled);
  }

  [[nodiscard]] Result<void> BeginConnect(cares::Endpoint peer_addr) noexcept {
    if (word_.Phase() != SocketPhase::kIdle) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    }
    peer_addr_ = peer_addr;
    word_ = word_.BeginConnect();
    return {};
  }

  // NOLINTNEXTLINE(readability-convert-member-functions-to-static) -- <meta> AST recovery drops word_ accesses.
  [[nodiscard]] Result<void> ConnectCompleted() noexcept {
    const SocketPhase cur = word_.Phase();
    if (cur != SocketPhase::kConnecting && cur != SocketPhase::kCancelling) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    }
    word_ = word_.ConnectCompleted(tls_.has_value());
    return {};
  }

  // NOLINTNEXTLINE(readability-convert-member-functions-to-static) -- <meta> AST recovery drops word_ accesses.
  [[nodiscard]] Result<void> BeginOp() noexcept {
    const SocketPhase cur = word_.Phase();
    if (cur != SocketPhase::kConnecting && cur != SocketPhase::kHandshaking && cur != SocketPhase::kOpen) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    }
    word_ = word_.BeginOp();
    return {};
  }

  void CompleteOp() noexcept { word_ = word_.CompleteOp(); }
  void RequestCancel() noexcept { word_ = word_.RequestCancel(); }
  void RequestClose() noexcept { word_ = word_.RequestClose(); }

  // NOLINTNEXTLINE(readability-convert-member-functions-to-static) -- <meta> AST recovery drops word_ accesses.
  [[nodiscard]] constexpr bool CanSubmitClose() const noexcept {
    const SocketPhase cur = word_.Phase();
    return (cur == SocketPhase::kCloseReady || cur == SocketPhase::kCloseQueued) && word_.InFlight() == 0;
  }

  // NOLINTNEXTLINE(readability-make-member-function-const) -- <meta> AST recovery drops word_ accesses.
  [[nodiscard]] Result<void> CloseStarted() noexcept {
    if (!CanSubmitClose()) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    word_ = word_.CloseStarted();
    return {};
  }

  // NOLINTNEXTLINE(readability-convert-member-functions-to-static) -- <meta> AST recovery drops word_ accesses.
  [[nodiscard]] Result<void> CloseSubmissionFailed() noexcept {
    if (word_.Phase() != SocketPhase::kCloseQueued || word_.InFlight() != 0) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    }
    word_ = word_.CloseSubmissionFailed();
    return {};
  }

  // NOLINTNEXTLINE(readability-convert-member-functions-to-static) -- <meta> AST recovery drops word_ accesses.
  [[nodiscard]] Result<void> CloseCancelled() noexcept {
    if (word_.Phase() != SocketPhase::kCloseSubmitted) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    }
    word_ = word_.CloseCancelled();
    return {};
  }

  void CloseCompleted() noexcept {
    if (word_.InFlight() != 0) return;
    const SocketPhase cur = word_.Phase();
    if (cur != SocketPhase::kCloseReady && cur != SocketPhase::kCloseQueued && cur != SocketPhase::kCloseSubmitted &&
        cur != SocketPhase::kClosed) {
      return;
    }
    if (fd_ >= 0) {
      const bool submitted = (cur == SocketPhase::kCloseSubmitted);
      if (!submitted) static_cast<void>(::close(fd_));
      fd_ = -1;
    }
    word_ = word_.CloseCompleted();
    BumpGeneration();
  }

  [[nodiscard]] Result<std::size_t> FeedTlsCiphertext(std::span<const std::uint8_t> data) noexcept {
    if (!tls_.has_value()) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    auto consumed = tls_->FeedCiphertext(data);
    if (!consumed) return std::unexpected(consumed.error());
    if (word_.Phase() == SocketPhase::kHandshaking && tls_->IsHandshakeComplete()) {
      word_ = word_.TransitionTo(SocketPhase::kOpen);
    }
    return *consumed;
  }

  [[nodiscard]] Result<std::size_t> TakeTlsCiphertext(std::span<std::uint8_t> out) noexcept {
    if (!tls_.has_value()) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    return tls_->TakeCiphertext(out);
  }

  [[nodiscard]] Result<std::size_t> WriteTlsPlaintext(std::span<const std::uint8_t> data) noexcept {
    if (!tls_.has_value()) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    return tls_->WritePlaintext(data);
  }

  [[nodiscard]] Result<std::size_t> ReadTlsPlaintext(std::span<std::uint8_t> out) noexcept {
    if (!tls_.has_value()) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    auto res = tls_->ReadPlaintext(out);
    if (res && word_.Phase() == SocketPhase::kHandshaking && tls_->IsHandshakeComplete()) {
      word_ = word_.TransitionTo(SocketPhase::kOpen);
    }
    return res;
  }
};

}  // namespace nexora
