#pragma once

#include <array>
#include <chrono>
#include <compare>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <nexora/bytes/bytes.hpp>
#include <nexora/error/runtime_error.hpp>
#include <nexora/http/message.hpp>
#include <nexora/websocket/codec.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <uarch/uarch.hpp>
#include <utility>

namespace nexora {

struct WebSocketCloseFrame {
  std::uint16_t code{1000};
  std::string reason{};
  constexpr bool operator==(const WebSocketCloseFrame&) const noexcept = default;
};

[[nodiscard]] inline WebSocketMessage MakeWebSocketText(std::string_view text) noexcept {
  return WebSocketMessage{WebSocketMessageKind::kText, Bytes::CopyFromString(text), std::nullopt};
}

[[nodiscard]] inline WebSocketMessage MakeWebSocketBinary(Bytes payload) noexcept {
  return WebSocketMessage{WebSocketMessageKind::kBinary, std::move(payload), std::nullopt};
}

struct RequestId {
  std::uint64_t raw{0};
  constexpr RequestId() noexcept = default;
  constexpr explicit RequestId(std::uint64_t value) noexcept : raw(value) {}
  [[nodiscard]] constexpr std::uint64_t Raw() const noexcept { return raw; }
  constexpr auto operator<=>(const RequestId&) const noexcept = default;
};

struct TimerId {
  std::uint64_t raw{0};
  constexpr TimerId() noexcept = default;
  constexpr explicit TimerId(std::uint64_t value) noexcept : raw(value) {}
  [[nodiscard]] constexpr std::uint64_t Raw() const noexcept { return raw; }
  constexpr auto operator<=>(const TimerId&) const noexcept = default;
};

struct WebSocketSessionId {
  static constexpr std::uint64_t kReservedIdMask = (1ULL << 52) - 1ULL;
  std::uint64_t raw{0};
  constexpr WebSocketSessionId() noexcept = default;
  constexpr explicit WebSocketSessionId(std::uint64_t value) noexcept : raw(value & kReservedIdMask) {}
  [[nodiscard]] constexpr std::uint64_t Raw() const noexcept { return raw; }
  constexpr auto operator<=>(const WebSocketSessionId&) const noexcept = default;
};

static_assert((uarch::assert_no_padding<RequestId>(), uarch::assert_register_pass<RequestId>(),
               uarch::NoPadding<RequestId>&& uarch::RegisterPassable<RequestId>));
static_assert((uarch::assert_no_padding<TimerId>(), uarch::assert_register_pass<TimerId>(),
               uarch::NoPadding<TimerId>&& uarch::RegisterPassable<TimerId>));
static_assert((uarch::assert_no_padding<WebSocketSessionId>(), uarch::assert_register_pass<WebSocketSessionId>(),
               uarch::NoPadding<WebSocketSessionId>&& uarch::RegisterPassable<WebSocketSessionId>));

template <typename Signature>
class InboxCallback;

template <typename R, typename... Args>
class InboxCallback<R(Args...)> {
  static constexpr std::size_t kInlineBytes = 64;
  struct Ops {
    R (*invoke)(void* storage, Args... args) noexcept;
    void (*move_to)(void* src, void* dst) noexcept;
    void (*destroy)(void* storage) noexcept;
  };
  alignas(std::max_align_t) std::array<std::byte, kInlineBytes> storage_{};
  const Ops* ops_{nullptr};

 public:
  constexpr InboxCallback() noexcept = default;
  constexpr InboxCallback(std::nullptr_t) noexcept {}

  template <typename F>
    requires(!std::same_as<std::decay_t<F>, InboxCallback> && std::invocable<std::decay_t<F>&, Args...>)
  InboxCallback(F&& fn) noexcept {
    using Decayed = std::decay_t<F>;
    static_assert(sizeof(Decayed) <= kInlineBytes && alignof(Decayed) <= alignof(std::max_align_t));
    static constexpr Ops ops{
        .invoke = +[](void* ptr, Args... call_args) noexcept -> R {
          return (*std::launder(static_cast<Decayed*>(ptr)))(std::forward<Args>(call_args)...);
        },
        .move_to =
            +[](void* src, void* dst) noexcept {
              auto* s = std::launder(static_cast<Decayed*>(src));
              std::construct_at(static_cast<Decayed*>(dst), std::move(*s));
              std::destroy_at(s);
            },
        .destroy = +[](void* ptr) noexcept { std::destroy_at(std::launder(static_cast<Decayed*>(ptr))); },
    };
    void* dst = storage_.data();
    std::construct_at(static_cast<Decayed*>(dst), std::forward<F>(fn));
    ops_ = &ops;
  }

  InboxCallback(const InboxCallback&) = delete ("move-only one-shot inbox callback");
  InboxCallback& operator=(const InboxCallback&) = delete ("move-only one-shot inbox callback");

  InboxCallback(InboxCallback&& other) noexcept {
    if (other.ops_ != nullptr) {
      other.ops_->move_to(other.storage_.data(), storage_.data());
      ops_ = std::exchange(other.ops_, nullptr);
    }
  }

  InboxCallback& operator=(InboxCallback&& other) noexcept {
    if (this != &other) {
      Reset();
      if (other.ops_ != nullptr) {
        other.ops_->move_to(other.storage_.data(), storage_.data());
        ops_ = std::exchange(other.ops_, nullptr);
      }
    }
    return *this;
  }

  ~InboxCallback() noexcept { Reset(); }

  void Reset() noexcept {
    if (ops_ != nullptr) {
      std::exchange(ops_, nullptr)->destroy(storage_.data());
    }
  }

  [[nodiscard]] constexpr explicit operator bool() const noexcept { return ops_ != nullptr; }
  [[nodiscard]] constexpr bool HasValue() const noexcept { return ops_ != nullptr; }

  R operator()(Args... args) noexcept {
    const Ops* ops = std::exchange(ops_, nullptr);
    struct DestroyGuard {
      const Ops* o;
      void* s;
      ~DestroyGuard() noexcept { o->destroy(s); }
    } guard{ops, storage_.data()};
    return ops->invoke(storage_.data(), std::forward<Args>(args)...);
  }
};

class ClientContext;

using ResponseCallback = InboxCallback<void(Result<Response>)>;
using TimerCallback = InboxCallback<void(ClientContext&)>;

enum class InboxState : std::uint8_t {
  kOpen = 0,
  kDraining = 1,
  kClosed = 2,
};

[[nodiscard]] constexpr bool CanTransitionInboxState(InboxState from, InboxState to) noexcept {
  switch (from) {
    case InboxState::kOpen:
      return to == InboxState::kOpen || to == InboxState::kDraining;
    case InboxState::kDraining:
      return to == InboxState::kDraining || to == InboxState::kClosed;
    case InboxState::kClosed:
      return to == InboxState::kClosed;
  }
  return false;
}

struct InboxCommand {
  enum class Kind : std::uint8_t {
    kSubmit = 0,
    kCancel = 1,
    kArmTimer = 2,
    kCancelTimer = 3,
    kSendWebSocket = 4,
    kCloseWebSocket = 5,
  };

  Kind kind{Kind::kCancel};
  RequestId request_id{};
  Request request{};
  ResponseCallback response_callback{};
  TimerId timer_id{};
  std::chrono::nanoseconds delay{0};
  TimerCallback timer_callback{};
  WebSocketSessionId session_id{};
  std::optional<WebSocketMessage> ws_message{};
  std::optional<WebSocketCloseFrame> ws_close{};

  [[nodiscard]] static InboxCommand MakeSubmit(RequestId id, Request req, ResponseCallback cb) noexcept {
    InboxCommand cmd{};
    cmd.kind = Kind::kSubmit;
    cmd.request_id = id;
    cmd.request = std::move(req);
    cmd.response_callback = std::move(cb);
    return cmd;
  }

  [[nodiscard]] static InboxCommand MakeCancel(RequestId id) noexcept {
    return InboxCommand{.kind = Kind::kCancel, .request_id = id};
  }

  [[nodiscard]] static InboxCommand MakeArmTimer(TimerId id, std::chrono::nanoseconds d, TimerCallback cb) noexcept {
    InboxCommand cmd{};
    cmd.kind = Kind::kArmTimer;
    cmd.timer_id = id;
    cmd.delay = d;
    cmd.timer_callback = std::move(cb);
    return cmd;
  }

  [[nodiscard]] static InboxCommand MakeCancelTimer(TimerId id) noexcept {
    return InboxCommand{.kind = Kind::kCancelTimer, .timer_id = id};
  }

  [[nodiscard]] static InboxCommand MakeSendWs(WebSocketSessionId id, WebSocketMessage msg) noexcept {
    InboxCommand cmd{};
    cmd.kind = Kind::kSendWebSocket;
    cmd.session_id = id;
    cmd.ws_message.emplace(std::move(msg));
    return cmd;
  }

  [[nodiscard]] static InboxCommand MakeCloseWs(WebSocketSessionId id,
                                                std::optional<WebSocketCloseFrame> close_frame) noexcept {
    InboxCommand cmd{};
    cmd.kind = Kind::kCloseWebSocket;
    cmd.session_id = id;
    cmd.ws_close = std::move(close_frame);
    return cmd;
  }
};

namespace detail {

struct InboxCommandSink {
  void* instance{nullptr};
  InboxState (*get_state)(const void* instance) noexcept {nullptr};
  RequestId (*next_request_id)(void* instance) noexcept {nullptr};
  TimerId (*next_timer_id)(void* instance) noexcept {nullptr};
  Result<void> (*push_command)(void* instance, InboxCommand&& cmd) noexcept {nullptr};
  void (*retain_weak)(void* instance) noexcept {nullptr};
  void (*release_weak)(void* instance) noexcept {nullptr};
};

template <std::size_t Capacity>
struct InboxRingBlock {
  static_assert(Capacity > 0, "SubsystemInbox Capacity must be > 0");
  InboxState state{InboxState::kOpen};
  std::array<std::optional<InboxCommand>, Capacity> ring{};
  std::size_t head{0};
  std::size_t tail{0};
  std::size_t count{0};
  std::uint64_t next_request_id{1};
  std::uint64_t next_timer_id{1};
  std::uint64_t next_ws_session_id{1};
  std::uint32_t owner_count{1};
  std::uint32_t weak_count{1};

  [[nodiscard]] static InboxRingBlock* Allocate() noexcept {
    std::allocator<InboxRingBlock> alloc{};
    InboxRingBlock* ptr = alloc.allocate(1);
    std::construct_at(ptr);
    return ptr;
  }

  static void RetainOwner(InboxRingBlock* ptr) noexcept {
    if (ptr != nullptr) {
      ++ptr->owner_count;
      ++ptr->weak_count;
    }
  }

  static void ReleaseOwner(InboxRingBlock* ptr) noexcept {
    if (ptr == nullptr) return;
    if (--ptr->owner_count == 0) ptr->DrainAndClose();
    ReleaseWeak(ptr);
  }

  static void RetainWeak(InboxRingBlock* ptr) noexcept {
    if (ptr != nullptr) ++ptr->weak_count;
  }

  static void ReleaseWeak(InboxRingBlock* ptr) noexcept {
    if (ptr == nullptr) return;
    if (--ptr->weak_count == 0) {
      std::destroy_at(ptr);
      std::allocator<InboxRingBlock> alloc{};
      alloc.deallocate(ptr, 1);
    }
  }

  [[nodiscard]] bool TransitionState(InboxState target) noexcept {
    if (!CanTransitionInboxState(state, target)) return false;
    state = target;
    return true;
  }

  [[nodiscard]] Result<void> PushCommand(InboxCommand&& cmd) noexcept {
    if (state != InboxState::kOpen) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    }
    if (count >= Capacity) return std::unexpected(Error::BufferOverflow());
    ring[tail].emplace(std::move(cmd));
    tail = (tail + 1U) % Capacity;
    ++count;
    return {};
  }

  [[nodiscard]] std::optional<InboxCommand> PopCommand() noexcept {
    if (count == 0) return std::nullopt;
    std::optional<InboxCommand> out = std::move(ring[head]);
    ring[head].reset();
    head = (head + 1U) % Capacity;
    --count;
    return out;
  }

  void DrainAndClose() noexcept {
    if (state == InboxState::kClosed) return;
    static_cast<void>(TransitionState(InboxState::kDraining));
    while (auto cmd = PopCommand()) {
      if (cmd->kind == InboxCommand::Kind::kSubmit && cmd->response_callback.HasValue()) {
        cmd->response_callback(std::unexpected(Error::Cancelled()));
      }
    }
    static_cast<void>(TransitionState(InboxState::kClosed));
  }

  [[nodiscard]] InboxCommandSink MakeSink() noexcept {
    return InboxCommandSink{
        .instance = this,
        .get_state = +[](const void* p) noexcept { return static_cast<const InboxRingBlock*>(p)->state; },
        .next_request_id = +[](void* p) noexcept { return RequestId{static_cast<InboxRingBlock*>(p)->next_request_id++}; },
        .next_timer_id = +[](void* p) noexcept { return TimerId{static_cast<InboxRingBlock*>(p)->next_timer_id++}; },
        .push_command =
            +[](void* p, InboxCommand&& c) noexcept { return static_cast<InboxRingBlock*>(p)->PushCommand(std::move(c)); },
        .retain_weak = +[](void* p) noexcept { RetainWeak(static_cast<InboxRingBlock*>(p)); },
        .release_weak = +[](void* p) noexcept { ReleaseWeak(static_cast<InboxRingBlock*>(p)); },
    };
  }
};

}  // namespace detail

class ClientContext {
  detail::InboxCommandSink sink_{};

  explicit ClientContext(detail::InboxCommandSink sink) noexcept : sink_(sink) {
    if (sink_.instance != nullptr && sink_.retain_weak != nullptr) sink_.retain_weak(sink_.instance);
  }

  template <typename EventT, std::size_t Capacity>
  friend class SubsystemInbox;

 public:
  constexpr ClientContext() noexcept = default;

  ClientContext(const ClientContext& other) noexcept : sink_(other.sink_) {
    if (sink_.instance != nullptr && sink_.retain_weak != nullptr) sink_.retain_weak(sink_.instance);
  }

  ClientContext& operator=(const ClientContext& other) noexcept {
    if (this != &other) {
      if (other.sink_.instance != nullptr && other.sink_.retain_weak != nullptr) {
        other.sink_.retain_weak(other.sink_.instance);
      }
      if (sink_.instance != nullptr && sink_.release_weak != nullptr) sink_.release_weak(sink_.instance);
      sink_ = other.sink_;
    }
    return *this;
  }

  constexpr ClientContext(ClientContext&& other) noexcept : sink_(std::exchange(other.sink_, {})) {}

  ClientContext& operator=(ClientContext&& other) noexcept {
    if (this != &other) {
      if (sink_.instance != nullptr && sink_.release_weak != nullptr) sink_.release_weak(sink_.instance);
      sink_ = std::exchange(other.sink_, {});
    }
    return *this;
  }

  ~ClientContext() noexcept {
    if (sink_.instance != nullptr && sink_.release_weak != nullptr) sink_.release_weak(sink_.instance);
  }

  [[nodiscard]] ClientContext Clone() const noexcept { return *this; }

  template <typename F>
  [[nodiscard]] Result<RequestId> Submit(Request request, F&& callback) noexcept {
    if (sink_.instance == nullptr || sink_.get_state(sink_.instance) != InboxState::kOpen) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    }
    const RequestId id = sink_.next_request_id(sink_.instance);
    auto pushed = sink_.push_command(
        sink_.instance, InboxCommand::MakeSubmit(id, std::move(request), ResponseCallback{std::forward<F>(callback)}));
    if (!pushed) return std::unexpected(pushed.error());
    return id;
  }

  [[nodiscard]] Result<void> Cancel(RequestId request_id) const noexcept {
    if (sink_.instance == nullptr) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    return sink_.push_command(sink_.instance, InboxCommand::MakeCancel(request_id));
  }

  template <typename Rep, typename Period, typename F>
  [[nodiscard]] Result<TimerId> ArmTimer(std::chrono::duration<Rep, Period> delay, F&& callback) noexcept {
    if (sink_.instance == nullptr || sink_.get_state(sink_.instance) != InboxState::kOpen) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    }
    const TimerId id = sink_.next_timer_id(sink_.instance);
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(delay);
    auto pushed =
        sink_.push_command(sink_.instance, InboxCommand::MakeArmTimer(id, ns, TimerCallback{std::forward<F>(callback)}));
    if (!pushed) return std::unexpected(pushed.error());
    return id;
  }

  [[nodiscard]] Result<void> CancelTimer(TimerId timer_id) const noexcept {
    if (sink_.instance == nullptr) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    return sink_.push_command(sink_.instance, InboxCommand::MakeCancelTimer(timer_id));
  }

  [[nodiscard]] Result<void> SendWs(WebSocketSessionId session_id, WebSocketMessage message) const noexcept {
    if (sink_.instance == nullptr) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    return sink_.push_command(sink_.instance, InboxCommand::MakeSendWs(session_id, std::move(message)));
  }

  [[nodiscard]] Result<void> CloseWs(WebSocketSessionId session_id,
                                     std::optional<WebSocketCloseFrame> close_frame = std::nullopt) const noexcept {
    if (sink_.instance == nullptr) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    return sink_.push_command(sink_.instance, InboxCommand::MakeCloseWs(session_id, std::move(close_frame)));
  }
};

template <typename EventT = InboxCommand, std::size_t Capacity = 64>
class SubsystemInbox {
  static_assert(Capacity > 0, "SubsystemInbox Capacity must be > 0");
  std::array<std::optional<EventT>, Capacity> ring_{};
  std::size_t head_{0};
  std::size_t tail_{0};
  std::size_t size_{0};

 public:
  constexpr SubsystemInbox() noexcept = default;

  [[nodiscard]] constexpr bool Push(const EventT& ev) noexcept {
    if (size_ >= Capacity) return false;
    ring_[tail_].emplace(ev);
    tail_ = (tail_ + 1U) % Capacity;
    ++size_;
    return true;
  }

  [[nodiscard]] constexpr bool Push(EventT&& ev) noexcept {
    if (size_ >= Capacity) return false;
    ring_[tail_].emplace(std::move(ev));
    tail_ = (tail_ + 1U) % Capacity;
    ++size_;
    return true;
  }

  [[nodiscard]] constexpr std::optional<EventT> Pop() noexcept {
    if (size_ == 0) return std::nullopt;
    std::optional<EventT> out = std::move(ring_[head_]);
    ring_[head_].reset();
    head_ = (head_ + 1U) % Capacity;
    --size_;
    return out;
  }
  [[nodiscard]] constexpr bool Empty() const noexcept { return size_ == 0; }
  [[nodiscard]] constexpr std::size_t Size() const noexcept { return size_; }
};

template <std::size_t Capacity>
class SubsystemInbox<InboxCommand, Capacity> {
  detail::InboxRingBlock<Capacity>* shared_{nullptr};

 public:
  SubsystemInbox() noexcept : shared_(detail::InboxRingBlock<Capacity>::Allocate()) {}

  SubsystemInbox(const SubsystemInbox& other) noexcept : shared_(other.shared_) {
    detail::InboxRingBlock<Capacity>::RetainOwner(shared_);
  }

  SubsystemInbox& operator=(const SubsystemInbox& other) noexcept {
    if (this != &other) {
      detail::InboxRingBlock<Capacity>::RetainOwner(other.shared_);
      detail::InboxRingBlock<Capacity>::ReleaseOwner(shared_);
      shared_ = other.shared_;
    }
    return *this;
  }

  constexpr SubsystemInbox(SubsystemInbox&& other) noexcept : shared_(std::exchange(other.shared_, nullptr)) {}

  SubsystemInbox& operator=(SubsystemInbox&& other) noexcept {
    if (this != &other) {
      detail::InboxRingBlock<Capacity>::ReleaseOwner(shared_);
      shared_ = std::exchange(other.shared_, nullptr);
    }
    return *this;
  }

  ~SubsystemInbox() noexcept { detail::InboxRingBlock<Capacity>::ReleaseOwner(shared_); }

  [[nodiscard]] SubsystemInbox Clone() const noexcept { return *this; }

  [[nodiscard]] ClientContext Context() const noexcept {
    return (shared_ != nullptr) ? ClientContext{shared_->MakeSink()} : ClientContext{};
  }

  [[nodiscard]] WebSocketSessionId AllocateWebSocketSessionId() const noexcept {
    return (shared_ != nullptr) ? WebSocketSessionId{shared_->next_ws_session_id++} : WebSocketSessionId{0};
  }

  [[nodiscard]] InboxState State() const noexcept { return (shared_ != nullptr) ? shared_->state : InboxState::kClosed; }

  [[nodiscard]] bool Push(InboxCommand&& ev) noexcept {
    return shared_ != nullptr && shared_->PushCommand(std::move(ev)).has_value();
  }

  [[nodiscard]] std::optional<InboxCommand> Pop() noexcept {
    return (shared_ != nullptr) ? shared_->PopCommand() : std::nullopt;
  }

  [[nodiscard]] constexpr std::size_t Size() const noexcept { return (shared_ != nullptr) ? shared_->count : 0; }

  [[nodiscard]] constexpr bool Empty() const noexcept { return Size() == 0; }

  void Close() noexcept {
    if (shared_ != nullptr) shared_->DrainAndClose();
  }
};

SubsystemInbox() -> SubsystemInbox<InboxCommand, 64>;

}  // namespace nexora
