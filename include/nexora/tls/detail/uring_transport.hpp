#pragma once
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cares/cares.hpp>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <nexora/dispatch/completion_routes.hpp>
#include <nexora/dispatch/parked_registry.hpp>
#include <nexora/error/runtime_error.hpp>
#include <nexora/socket/uring_socket.hpp>
#include <nexora/tls/detail/foreign_observer.hpp>
#include <optional>
#include <span>
#include <uring/uring.hpp>
#include <utility>

// The LeakSanitizer entry point is a reserved identifier; the weak declaration has to match it.
// NOLINTNEXTLINE(bugprone-reserved-identifier,readability-identifier-naming)
extern "C" void __lsan_ignore_object(const void*) __attribute__((weak));

namespace nexora::detail {
struct TransportOperation {
  std::optional<IoUringSocket> socket{};
  cares::SockAddrValue address{};
};

inline void IgnoreLeaked(const void* pointer) noexcept {
  if (pointer != nullptr && __lsan_ignore_object != nullptr) __lsan_ignore_object(pointer);
}

inline void LeakTransportOperation(std::unique_ptr<TransportOperation> storage) noexcept {
  if (!storage) return;
  if (storage->socket) {
    const auto rx = storage->socket->RxBuffer();
    const auto tx = storage->socket->TxBuffer();
    if (!rx.empty()) IgnoreLeaked(rx.data());
    if (!tx.empty()) IgnoreLeaked(tx.data());
  }
  IgnoreLeaked(storage.release());
}

inline void CloseTransportOperation(std::unique_ptr<TransportOperation> storage) noexcept {
  if (!storage) return;
  if (storage->socket) {
    storage->socket->RequestCancel();
    while (storage->socket->InFlightOps() > 0) storage->socket->CompleteOp();
  }
  storage.reset();
}

class ParkedOperations {
 public:
  static constexpr std::size_t kCapacity = ParkedRegistry::kCapacity;

  ParkedOperations() noexcept = default;
  ParkedOperations(const ParkedOperations&) = delete ("parked operations own kernel-visible addresses");
  ParkedOperations& operator=(const ParkedOperations&) = delete ("parked operations own kernel-visible addresses");
  ~ParkedOperations() noexcept {
    for (auto& slot : slots_) {
      if (!slot.active) continue;
      SharedParkedRegistry().Unregister(slot.token, slot.ring_instance);
      LeakTransportOperation(std::move(slot.storage));
      slot.active = false;
    }
    active_count_ = 0;
  }

  [[nodiscard]] std::size_t Count() const noexcept { return active_count_; }
  [[nodiscard]] bool Contains(uring::UserDataToken token, std::uint64_t ring_instance) const noexcept {
    return Find(token, ring_instance) != nullptr;
  }

  // NOLINTNEXTLINE(readability-convert-member-functions-to-static) -- stock clang-tidy lacks <meta> for BitWord tokens.
  void Park(uring::UserDataToken token, std::uint64_t ring_instance, std::unique_ptr<TransportOperation> storage) noexcept {
    if (!storage) return;
    if (storage->socket && storage->socket->RawFd() >= 0) static_cast<void>(::shutdown(storage->socket->RawFd(), SHUT_RDWR));
    for (auto& slot : slots_) {
      if (slot.active) continue;
      slot.active = true;
      slot.token = token;
      slot.ring_instance = ring_instance;
      slot.storage = std::move(storage);
      ++active_count_;
      const bool registered = SharedParkedRegistry().Register(
          token, ring_instance, ParkedSlotRef{this, +[](void* owner, uring::UserDataToken parked, std::uint64_t ring) noexcept {
                                                return static_cast<ParkedOperations*>(owner)->Release(parked, ring);
                                              }});
      if (!registered) {
        auto leaked = std::move(slot.storage);
        slot = {};
        --active_count_;
        LeakTransportOperation(std::move(leaked));
      }
      return;
    }
    LeakTransportOperation(std::move(storage));
  }

 private:
  struct Slot {
    bool active{false};
    uring::UserDataToken token{};
    std::uint64_t ring_instance{0};
    std::unique_ptr<TransportOperation> storage{};
  };

  // NOLINTNEXTLINE(readability-convert-member-functions-to-static) -- stock clang-tidy lacks <meta> for BitWord tokens.
  [[nodiscard]] const Slot* Find(uring::UserDataToken token, std::uint64_t ring_instance) const noexcept {
    for (const auto& slot : slots_) {
      if (slot.active && slot.token == token && slot.ring_instance == ring_instance) return &slot;
    }
    return nullptr;
  }

  // NOLINTNEXTLINE(readability-convert-member-functions-to-static) -- stock clang-tidy lacks <meta> for BitWord tokens.
  bool Release(uring::UserDataToken token, std::uint64_t ring_instance) noexcept {
    for (auto& slot : slots_) {
      if (!slot.active || slot.token != token || slot.ring_instance != ring_instance) continue;
      auto storage = std::move(slot.storage);
      slot = {};
      if (active_count_ > 0) --active_count_;
      CloseTransportOperation(std::move(storage));
      return true;
    }
    return false;
  }

  std::array<Slot, kCapacity> slots_{};
  std::size_t active_count_{0};
};

class UringTransport {
  uring::Proactor* proactor_;
  cares::Resolver<>* resolver_;
  CompletionRoute fallback_{};
  ParkedOperations owned_parked_{};
  ParkedOperations* parked_{nullptr};
  std::unique_ptr<TransportOperation> operation_{std::make_unique<TransportOperation>()};
  std::optional<uring::UserDataToken> token_{};
  std::optional<std::int32_t> result_{};
  std::optional<cares::Endpoint> peer_{};
  std::uint8_t subsystem_;
  bool connecting_{false};

  [[nodiscard]] static Error NativeError(uring::UringErrorCode error) noexcept {
    if (error == uring::UringErrorCode::kTimedOut) return Error::Timeout();
    return Error::UringFailed(static_cast<std::int32_t>(std::to_underlying(error)));
  }
  void ParkOperation() noexcept {
    if (!token_) return;
    // The kernel reads the descriptor number when the SQE is issued, so the number stays reserved.
    auto next = std::make_unique<TransportOperation>();
    parked_->Park(*token_, proactor_->Instance(), std::exchange(operation_, std::move(next)));
    token_.reset();
    result_.reset();
    connecting_ = false;
  }
  template <typename Dispatcher>
  void DrainCancelled(Dispatcher& dispatcher, bool closing = false) noexcept {
    if (!token_) return;
    if (closing && operation_->socket) operation_->socket->RequestCancel();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
    for (unsigned step = 0; token_ && step < 128; ++step) {
      if (proactor_->Contains(*token_)) static_cast<void>(proactor_->Cancel(*token_));
      if (proactor_->Stage() != uring::DrainStage::kRunning || std::chrono::steady_clock::now() >= deadline) break;
      if (resolver_ != nullptr) resolver_->StepDriver();
      auto waited = proactor_->WaitCompletions(1, std::chrono::milliseconds(1), dispatcher);
      if (!waited && waited.error() == uring::UringErrorCode::kBusy) waited = proactor_->Tick(dispatcher);
      if (!waited && waited.error() != uring::UringErrorCode::kTimedOut && waited.error() != uring::UringErrorCode::kNoEntry)
        break;
    }
    if (token_) ParkOperation();
  }
  [[nodiscard]] Result<std::size_t> Wait(std::uint32_t timeout_ms) noexcept {
    ForeignObserverScope dispatcher(resolver_, *this);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (token_) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        DrainCancelled(dispatcher);
        if (result_ && *result_ >= 0) return static_cast<std::size_t>(*result_);
        return std::unexpected(Error::Timeout());
      }
      if (resolver_ != nullptr) resolver_->StepDriver();
      if (!token_) break;
      if (dispatcher.Error()) {
        DrainCancelled(dispatcher);
        if (result_ && *result_ >= 0) break;
        return std::unexpected(NativeError(*dispatcher.Error()));
      }
      if (!token_) break;
      auto waited = proactor_->WaitCompletions(1, deadline - now, dispatcher);
      if (!waited && waited.error() == uring::UringErrorCode::kBusy) waited = proactor_->Tick(dispatcher);
      if (!waited && waited.error() != uring::UringErrorCode::kTimedOut) {
        DrainCancelled(dispatcher);
        if (result_ && *result_ >= 0) break;
        return std::unexpected(NativeError(waited.error()));
      }
    }
    if (!result_) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    if (*result_ < -4095) return std::unexpected(Error::UringFailed(*result_));
    if (*result_ < 0) return std::unexpected(Error::FromErrno(-*result_));
    return static_cast<std::size_t>(*result_);
  }
  template <typename Op>
  [[nodiscard]] Result<void> Arm(const Op& operation) noexcept {
    if (token_) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    result_.reset();
    auto token = proactor_->Arm(subsystem_, operation);
    if (!token) {
      if (operation_->socket) operation_->socket->CompleteOp();
      return std::unexpected(NativeError(token.error()));
    }
    token_ = *token;
    return {};
  }
  [[nodiscard]] static bool IsWouldBlock(const Error& error) noexcept {
    if (error.domain != ErrorDomain::kErrno) return false;
    const auto sys = error.SysErrno();
    return sys == EAGAIN || sys == EWOULDBLOCK;
  }
  // A full or empty SOCK_NONBLOCK buffer completes with EAGAIN. Poll stays in io_uring, so cancel does not park the fd.
  [[nodiscard]] Result<void> PollReady(std::uint32_t events, std::chrono::steady_clock::time_point deadline) noexcept {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) return std::unexpected(Error::Timeout());
    const auto remaining_ms = std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count();
    const auto wait_ms = static_cast<std::uint32_t>(std::min<std::int64_t>(remaining_ms, UINT32_MAX));
    if (auto begun = operation_->socket->BeginOp(); !begun) return std::unexpected(begun.error());
    if (auto armed = Arm(uring::ops::PreparePollAdd(operation_->socket->RawFd(), events)); !armed)
      return std::unexpected(armed.error());
    auto ready = Wait(wait_ms);
    if (!ready) return std::unexpected(ready.error());
    return {};
  }
  [[nodiscard]] static std::uint32_t NextWaitMs(std::chrono::steady_clock::time_point deadline) noexcept {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) return 0;
    const auto remaining_ms = std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count();
    return static_cast<std::uint32_t>(std::min<std::int64_t>(remaining_ms, UINT32_MAX));
  }

 public:
  explicit UringTransport(uring::Proactor& proactor, cares::Resolver<>* resolver = nullptr,
                          std::uint8_t subsystem = kDefaultSocketIoSubsystemId, CompletionRoute fallback = {},
                          ParkedOperations* parked = nullptr) noexcept
      : proactor_(&proactor),
        resolver_(resolver),
        fallback_(fallback),
        parked_(parked != nullptr ? parked : &owned_parked_),
        subsystem_(subsystem) {}
  UringTransport(const UringTransport&) = delete ("transport owns pinned operation storage");
  UringTransport& operator=(const UringTransport&) = delete ("transport owns pinned operation storage");
  ~UringTransport() noexcept { Close(); }
  [[nodiscard]] bool CanRoute(std::uint8_t id) const noexcept {
    return id == subsystem_ || (resolver_ != nullptr && resolver_->CanRoute(id)) || fallback_.Accepts(id);
  }
  [[nodiscard]] std::size_t ParkedCount() const noexcept { return parked_->Count(); }
  // NOLINTNEXTLINE(readability-convert-member-functions-to-static) -- stock clang-tidy lacks <meta> for BitWord tokens.
  [[nodiscard]] bool CanRouteDelivery(const uring::Delivery& delivery) const noexcept {
    const auto id = uring::Subsystem(delivery.completion.token);
    return (token_ && delivery.completion.token == *token_) ||
           parked_->Contains(delivery.completion.token, delivery.key.ring_instance) ||
           (resolver_ != nullptr && resolver_->CanRoute(id)) || fallback_.Accepts(id);
  }
  [[nodiscard]] uring::Result<void> DispatchBatch(std::span<const uring::Delivery> deliveries) noexcept {
    std::optional<uring::UringErrorCode> error;
    for (const auto& delivery : deliveries) {
      if (RetireParked(delivery.completion.token, delivery.key.ring_instance)) continue;
      if (token_ && delivery.completion.token == *token_) {
        result_ = delivery.completion.result;
        if (connecting_)
          static_cast<void>(operation_->socket->ConnectCompleted());
        else if (operation_->socket)
          operation_->socket->CompleteOp();
        token_.reset();
      } else if (resolver_ != nullptr && resolver_->CanRoute(uring::Subsystem(delivery.completion.token))) {
        resolver_->OnCompletions(std::span<const uring::Delivery>(&delivery, 1));
      } else {
        if (auto routed = fallback_.Dispatch(delivery); !routed && !error) error = routed.error();
      }
    }
    if (error) return std::unexpected(*error);
    return {};
  }
  [[nodiscard]] bool IsOpen() const noexcept {
    return operation_->socket.has_value() && operation_->socket->Phase() == SocketPhase::kOpen;
  }
  [[nodiscard]] int RawFd() const noexcept { return operation_->socket ? operation_->socket->RawFd() : -1; }
  [[nodiscard]] Result<void> Accept(int listener, std::uint32_t timeout_ms) noexcept {
    Close();
    if (listener < 0) return std::unexpected(Error::InvalidArgument());
    operation_->address.len = sizeof(operation_->address.storage);
    const auto operation =
        uring::ops::PrepareAccept(listener, uring::ops::UserAddress(&operation_->address.storage),
                                  uring::ops::UserAddress(&operation_->address.len), SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (auto armed = Arm(operation); !armed) return armed;
    auto accepted = Wait(timeout_ms);
    if (!accepted) {
      if (result_ && *result_ >= 0) static_cast<void>(::close(*result_));
      return std::unexpected(accepted.error());
    }
    auto adopted = Adopt(static_cast<int>(*accepted));
    if (adopted) {
      const int one = 1;
      static_cast<void>(::setsockopt(operation_->socket->RawFd(), IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)));
      peer_ = cares::SocketAddress::FromSockAddr(
          static_cast<const sockaddr*>(static_cast<const void*>(&operation_->address.storage)));
    }
    return adopted;
  }
  [[nodiscard]] Result<void> Adopt(int fd) noexcept {
    if (fd < 0) return std::unexpected(Error::InvalidArgument());
    Close();
    operation_->socket.emplace(IoUringSocket::FromRawFd(fd, SocketWord::OpenWord()));
    return {};
  }
  [[nodiscard]] const std::optional<cares::Endpoint>& Peer() const noexcept { return peer_; }
  [[nodiscard]] Result<void> Connect(const cares::Endpoint& endpoint, std::uint32_t timeout_ms) noexcept {
    Close();
    if (subsystem_ == uring::kInternalSubsystemId || subsystem_ == uring::kMailboxSubsystemId ||
        (resolver_ != nullptr && resolver_->CanRoute(subsystem_)))
      return std::unexpected(Error::InvalidArgument());
    auto socket = IoUringSocket::CreateForEndpoint(endpoint);
    if (!socket) return std::unexpected(socket.error());
    operation_->socket.emplace(std::move(*socket));
    operation_->address = endpoint.ToSockAddrValue();
    if (auto begun = operation_->socket->BeginConnect(endpoint); !begun) {
      Close();
      return begun;
    }
    connecting_ = true;
    const auto operation = uring::ops::PrepareConnect(
        operation_->socket->RawFd(), uring::ops::UserAddress(&operation_->address.storage), operation_->address.len);
    if (auto armed = Arm(operation); !armed) {
      Close();
      return armed;
    }
    auto connected = Wait(timeout_ms);
    connecting_ = false;
    if (!connected) {
      Close();
      return std::unexpected(connected.error());
    }
    peer_ = endpoint;
    return {};
  }
  [[nodiscard]] Result<std::size_t> WriteSome(std::span<const std::uint8_t> bytes, std::uint32_t timeout_ms) noexcept {
    if (!IsOpen()) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    if (bytes.empty()) return 0uz;
    const auto count = std::min(bytes.size(), operation_->socket->TxBufferMut().size());
    if (count == 0) return std::unexpected(Error::BufferOverflow());
    std::memcpy(operation_->socket->TxBufferMut().data(), bytes.data(), count);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    auto wait_ms = timeout_ms;
    for (;;) {
      // MSG_DONTWAIT completes a full buffer with EAGAIN instead of blocking an io-wq worker.
      auto op = uring::ops::PrepareSend(operation_->socket->RawFd(), operation_->socket->TxBuffer().first(count),
                                        static_cast<std::uint32_t>(MSG_NOSIGNAL | MSG_DONTWAIT));
      if (!op) return std::unexpected(NativeError(op.error()));
      if (auto begun = operation_->socket->BeginOp(); !begun) return std::unexpected(begun.error());
      if (auto armed = Arm(*op); !armed) return std::unexpected(armed.error());
      auto written = Wait(wait_ms);
      if (written) {
        if (*written == 0) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
        if (*written > count) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
        return *written;
      }
      if (!IsWouldBlock(written.error())) return std::unexpected(written.error());
      if (auto ready = PollReady(POLLOUT, deadline); !ready) return std::unexpected(ready.error());
      wait_ms = NextWaitMs(deadline);
      if (wait_ms == 0) return std::unexpected(Error::Timeout());
    }
  }
  [[nodiscard]] Result<void> WriteAll(std::span<const std::uint8_t> bytes, std::uint32_t timeout_ms) noexcept {
    if (!IsOpen()) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (!bytes.empty()) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) return std::unexpected(Error::Timeout());
      const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count();
      auto written = WriteSome(bytes, static_cast<std::uint32_t>(remaining));
      if (!written) return std::unexpected(written.error());
      bytes = bytes.subspan(*written);
    }
    return {};
  }
  [[nodiscard]] Result<std::size_t> ReadSome(std::span<std::uint8_t> bytes, std::uint32_t timeout_ms) noexcept {
    if (!IsOpen()) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    if (bytes.empty()) return 0uz;
    const auto count = std::min(bytes.size(), operation_->socket->RxBufferMut().size());
    if (count == 0) return std::unexpected(Error::BufferOverflow());
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    auto wait_ms = timeout_ms;
    Result<std::size_t> read = std::unexpected(Error::Timeout());
    for (;;) {
      auto op =
          uring::ops::PrepareRecv(operation_->socket->RawFd(), operation_->socket->RxBufferMut().first(count), MSG_DONTWAIT);
      if (!op) return std::unexpected(NativeError(op.error()));
      if (auto begun = operation_->socket->BeginOp(); !begun) return std::unexpected(begun.error());
      if (auto armed = Arm(*op); !armed) return std::unexpected(armed.error());
      read = Wait(wait_ms);
      if (read) break;
      if (!IsWouldBlock(read.error())) return std::unexpected(read.error());
      if (auto ready = PollReady(POLLIN, deadline); !ready) return std::unexpected(ready.error());
      wait_ms = NextWaitMs(deadline);
      if (wait_ms == 0) return std::unexpected(Error::Timeout());
    }
    const auto size = static_cast<std::size_t>(*read);
    if (size > count) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    std::memcpy(bytes.data(), operation_->socket->RxBuffer().data(), size);
    return size;
  }
  void Close() noexcept {
    ForeignObserverScope dispatcher(resolver_, *this);
    DrainCancelled(dispatcher, true);
    operation_->socket.reset();
    peer_.reset();
    connecting_ = false;
  }
};

inline void DrainParkedOnProactor(uring::Proactor& proactor, cares::Resolver<>* resolver,
                                  std::size_t (*parked_fn)(const void*) noexcept, const void* ctx) noexcept {
  struct DrainRouter {
    cares::Resolver<>* resolver{nullptr};
    [[nodiscard]] static bool CanRoute(std::uint8_t) noexcept { return true; }
    [[nodiscard]] uring::Result<void> DispatchBatch(std::span<const uring::Delivery> deliveries) const noexcept {
      for (const auto& d : deliveries) {
        if (RetireParked(d.completion.token, d.key.ring_instance)) continue;
        if (resolver != nullptr && resolver->CanRoute(uring::Subsystem(d.completion.token))) {
          resolver->OnCompletions(std::span<const uring::Delivery>(&d, 1));
        }
      }
      return {};
    }
  } router{resolver};
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
  for (unsigned step = 0; step < 256 && parked_fn(ctx) != 0; ++step) {
    if (proactor.Stage() != uring::DrainStage::kRunning || std::chrono::steady_clock::now() >= deadline) break;
    if (resolver != nullptr) resolver->StepDriver();
    auto waited = proactor.WaitCompletions(1, std::chrono::milliseconds(2), router);
    if (!waited && waited.error() == uring::UringErrorCode::kBusy) waited = proactor.Tick(router);
    if (!waited && waited.error() != uring::UringErrorCode::kTimedOut && waited.error() != uring::UringErrorCode::kNoEntry)
      break;
  }
}
}  // namespace nexora::detail
