#pragma once

#include <compare>
#include <cstdint>
#include <optional>
#include <string_view>
#include <uarch/uarch.hpp>

namespace nexora {

enum class SocketSuperstate : std::uint8_t {
  kInactive = 0,
  kEstablishing = 1,
  kActive = 2,
  kTeardown = 3,

  kIdle = kInactive,
};

enum class SocketPhase : std::uint8_t {
  kIdle = 0,
  kConnecting = 1,
  kHandshaking = 2,
  kOpen = 3,
  kCancelling = 4,
  kCloseReady = 5,
  kCloseQueued = 6,
  kCloseSubmitted = 7,
  kClosed = 8,

  kConnected = kHandshaking,
  kCancelRequested = kCancelling,
  kClosing = kCloseSubmitted,
  kFaulted = kClosed,
};

using SocketState = SocketPhase;

[[nodiscard]] constexpr std::optional<SocketPhase> SocketPhaseFromRaw(std::uint8_t raw) noexcept {
  switch (raw) {
    case 0:
      return SocketPhase::kIdle;
    case 1:
      return SocketPhase::kConnecting;
    case 2:
      return SocketPhase::kHandshaking;
    case 3:
      return SocketPhase::kOpen;
    case 4:
      return SocketPhase::kCancelling;
    case 5:
      return SocketPhase::kCloseReady;
    case 6:
      return SocketPhase::kCloseQueued;
    case 7:
      return SocketPhase::kCloseSubmitted;
    case 8:
      return SocketPhase::kClosed;
    default:
      return std::nullopt;
  }
}

[[nodiscard]] constexpr SocketSuperstate SuperstateOf(SocketPhase phase) noexcept {
  switch (phase) {
    case SocketPhase::kIdle:
    case SocketPhase::kClosed:
      return SocketSuperstate::kInactive;
    case SocketPhase::kConnecting:
    case SocketPhase::kHandshaking:
      return SocketSuperstate::kEstablishing;
    case SocketPhase::kOpen:
      return SocketSuperstate::kActive;
    case SocketPhase::kCancelling:
    case SocketPhase::kCloseReady:
    case SocketPhase::kCloseQueued:
    case SocketPhase::kCloseSubmitted:
      return SocketSuperstate::kTeardown;
  }
  return SocketSuperstate::kInactive;
}

[[nodiscard]] constexpr std::uint16_t SocketAllowedNextMask(SocketPhase phase) noexcept {
  constexpr auto bit = [](SocketPhase p) consteval noexcept -> std::uint16_t {
    return static_cast<std::uint16_t>(1U << static_cast<std::uint8_t>(p));
  };
  switch (phase) {
    case SocketPhase::kIdle:
      return bit(SocketPhase::kConnecting) | bit(SocketPhase::kHandshaking) | bit(SocketPhase::kOpen) |
             bit(SocketPhase::kCloseReady) | bit(SocketPhase::kClosed);
    case SocketPhase::kConnecting:
    case SocketPhase::kHandshaking:
      return bit(SocketPhase::kHandshaking) | bit(SocketPhase::kOpen) | bit(SocketPhase::kCancelling) |
             bit(SocketPhase::kCloseReady) | bit(SocketPhase::kClosed);
    case SocketPhase::kOpen:
      return bit(SocketPhase::kOpen) | bit(SocketPhase::kCancelling) | bit(SocketPhase::kCloseReady) |
             bit(SocketPhase::kClosed);
    case SocketPhase::kCancelling:
      return bit(SocketPhase::kCancelling) | bit(SocketPhase::kCloseReady) | bit(SocketPhase::kClosed);
    case SocketPhase::kCloseReady:
      return bit(SocketPhase::kCloseQueued) | bit(SocketPhase::kCloseSubmitted) | bit(SocketPhase::kClosed);
    case SocketPhase::kCloseQueued:
      return bit(SocketPhase::kCloseReady) | bit(SocketPhase::kCloseSubmitted) | bit(SocketPhase::kClosed);
    case SocketPhase::kCloseSubmitted:
      return bit(SocketPhase::kCloseReady) | bit(SocketPhase::kClosed);
    case SocketPhase::kClosed:
      return bit(SocketPhase::kClosed);
  }
  return 0;
}

[[nodiscard]] constexpr bool CanTransition(SocketPhase from, SocketPhase to) noexcept {
  const auto bit = static_cast<std::uint16_t>(1U << static_cast<std::uint8_t>(to));
  return (SocketAllowedNextMask(from) & bit) != 0;
}

[[nodiscard]] constexpr std::string_view SocketPhaseName(SocketPhase phase) noexcept {
  switch (phase) {
    case SocketPhase::kIdle:
      return "idle";
    case SocketPhase::kConnecting:
      return "connecting";
    case SocketPhase::kHandshaking:
      return "handshaking";
    case SocketPhase::kOpen:
      return "open";
    case SocketPhase::kCancelling:
      return "cancelling";
    case SocketPhase::kCloseReady:
      return "close_ready";
    case SocketPhase::kCloseQueued:
      return "close_queued";
    case SocketPhase::kCloseSubmitted:
      return "close_submitted";
    case SocketPhase::kClosed:
      return "closed";
  }
  return "unknown";
}

struct SocketWordSpec {
  using Word = std::uint64_t;
  [[= uarch::Field{0, 8}]] SocketPhase phase{SocketPhase::kIdle};
  [[= uarch::Field{32, 32}]] std::uint32_t in_flight{0};
};

class SocketWord {
 public:
  using Word = std::uint64_t;
  using Backing = uarch::BitWord<SocketWordSpec>;

 private:
  Backing bits_{};

  explicit constexpr SocketWord(Backing bits) noexcept : bits_(bits) {}

 public:
  constexpr SocketWord() noexcept = default;

  [[nodiscard, gnu::always_inline]] static constexpr SocketWord FromRaw(std::uint64_t raw) noexcept {
    return SocketWord{Backing::from_raw(raw)};
  }

  [[nodiscard, gnu::always_inline]] static constexpr SocketWord IdleWord() noexcept { return SocketWord{}; }

  [[nodiscard, gnu::always_inline]] static constexpr SocketWord OpenWord() noexcept {
    return SocketWord{}.WithPhase(SocketPhase::kOpen);
  }

  [[nodiscard, gnu::always_inline]] constexpr std::uint64_t Raw() const noexcept { return bits_.raw(); }
  [[nodiscard, gnu::always_inline]] constexpr Backing Bits() const noexcept { return bits_; }

  template <std::meta::info M>
  [[nodiscard, gnu::always_inline]] constexpr auto Get() const noexcept {
    return bits_.template get<M>();
  }

  template <std::meta::info M, class Input>
  [[nodiscard, gnu::always_inline]] constexpr SocketWord With(Input value) const noexcept {
    return SocketWord{bits_.template with<M>(value)};
  }

  [[nodiscard, gnu::always_inline]] constexpr SocketPhase Phase() const noexcept {
    const auto& bits = this->bits_;
    const auto raw_phase = static_cast<std::uint8_t>(bits.get<^^SocketWordSpec::phase>());
    return SocketPhaseFromRaw(raw_phase).value_or(SocketPhase::kClosed);
  }

  [[nodiscard, gnu::always_inline]] constexpr SocketSuperstate Superstate() const noexcept { return SuperstateOf(Phase()); }

  [[nodiscard, gnu::always_inline]] constexpr std::uint32_t InFlight() const noexcept {
    return bits_.get<^^SocketWordSpec::in_flight>();
  }

  [[nodiscard, gnu::always_inline]] constexpr SocketWord WithPhase(SocketPhase next) const noexcept {
    return SocketWord{bits_.with<^^SocketWordSpec::phase>(next)};
  }

  [[nodiscard, gnu::always_inline]] constexpr SocketWord WithInFlight(std::uint32_t count) const noexcept {
    return SocketWord{bits_.with<^^SocketWordSpec::in_flight>(count)};
  }

  [[nodiscard, gnu::always_inline]] constexpr bool CanTransitionTo(SocketPhase next) const noexcept {
    const SocketPhase cur = Phase();
    if (!CanTransition(cur, next)) {
      return false;
    }
    const std::uint32_t active = InFlight();
    switch (next) {
      case SocketPhase::kCancelling:
        return active > 0;
      case SocketPhase::kCloseReady:
      case SocketPhase::kCloseQueued:
      case SocketPhase::kCloseSubmitted:
        return active == 0;
      case SocketPhase::kClosed:
        return active == 0 || cur == SocketPhase::kCloseSubmitted;
      default:
        return true;
    }
  }

  [[nodiscard, gnu::always_inline]] constexpr SocketWord TransitionTo(SocketPhase next) const noexcept {
    return CanTransitionTo(next) ? WithPhase(next) : *this;
  }

  [[nodiscard, gnu::always_inline]] constexpr SocketWord BeginConnect() const noexcept {
    if (Phase() == SocketPhase::kIdle) {
      return WithPhase(SocketPhase::kConnecting).WithInFlight(uarch::saturating_add(InFlight(), 1U));
    }
    return *this;
  }

  [[nodiscard, gnu::always_inline]] constexpr SocketWord ConnectCompleted(bool tls_required) const noexcept {
    const std::uint32_t remaining = uarch::saturating_sub(InFlight(), 1U);
    const SocketWord after_op = WithInFlight(remaining);
    const SocketPhase cur = Phase();
    if (cur == SocketPhase::kConnecting) {
      const SocketPhase next = tls_required ? SocketPhase::kHandshaking : SocketPhase::kOpen;
      return after_op.TransitionTo(next);
    }
    if (cur == SocketPhase::kCancelling && remaining == 0) {
      return after_op.TransitionTo(SocketPhase::kCloseReady);
    }
    return after_op;
  }

  [[nodiscard, gnu::always_inline]] constexpr SocketWord BeginOp() const noexcept {
    const SocketPhase cur = Phase();
    if (cur == SocketPhase::kConnecting || cur == SocketPhase::kHandshaking || cur == SocketPhase::kOpen) {
      return WithInFlight(uarch::saturating_add(InFlight(), 1U));
    }
    return *this;
  }

  [[nodiscard, gnu::always_inline]] constexpr SocketWord CompleteOp() const noexcept {
    const std::uint32_t remaining = uarch::saturating_sub(InFlight(), 1U);
    const SocketWord next = WithInFlight(remaining);
    if (Phase() == SocketPhase::kCancelling && remaining == 0) {
      return next.TransitionTo(SocketPhase::kCloseReady);
    }
    return next;
  }

  [[nodiscard, gnu::always_inline]] constexpr SocketWord RequestCancel() const noexcept {
    const SocketPhase cur = Phase();
    if (cur == SocketPhase::kConnecting || cur == SocketPhase::kHandshaking || cur == SocketPhase::kOpen) {
      const SocketPhase target = (InFlight() == 0) ? SocketPhase::kCloseReady : SocketPhase::kCancelling;
      return TransitionTo(target);
    }
    return *this;
  }

  [[nodiscard, gnu::always_inline]] constexpr SocketWord RequestClose() const noexcept {
    const SocketPhase cur = Phase();
    switch (cur) {
      case SocketPhase::kIdle:
        return (InFlight() == 0) ? TransitionTo(SocketPhase::kCloseReady).TransitionTo(SocketPhase::kCloseQueued) : *this;
      case SocketPhase::kConnecting:
      case SocketPhase::kHandshaking:
      case SocketPhase::kOpen:
        if (InFlight() == 0) {
          return TransitionTo(SocketPhase::kCloseReady).TransitionTo(SocketPhase::kCloseQueued);
        }
        return TransitionTo(SocketPhase::kCancelling);
      case SocketPhase::kCloseReady:
        return TransitionTo(SocketPhase::kCloseQueued);
      default:
        return *this;
    }
  }

  [[nodiscard, gnu::always_inline]] constexpr SocketWord CloseStarted() const noexcept {
    const SocketPhase cur = Phase();
    if ((cur == SocketPhase::kCloseReady || cur == SocketPhase::kCloseQueued) && InFlight() == 0) {
      return TransitionTo(SocketPhase::kCloseSubmitted).WithInFlight(1U);
    }
    return *this;
  }

  [[nodiscard, gnu::always_inline]] constexpr SocketWord CloseSubmissionFailed() const noexcept {
    if (Phase() == SocketPhase::kCloseQueued && InFlight() == 0) {
      return TransitionTo(SocketPhase::kCloseReady);
    }
    return *this;
  }

  [[nodiscard, gnu::always_inline]] constexpr SocketWord CloseCancelled() const noexcept {
    if (Phase() == SocketPhase::kCloseSubmitted) {
      const std::uint32_t remaining = uarch::saturating_sub(InFlight(), 1U);
      const SocketWord next = WithInFlight(remaining);
      return (remaining == 0) ? next.TransitionTo(SocketPhase::kCloseReady) : next;
    }
    return *this;
  }

  [[nodiscard, gnu::always_inline]] constexpr SocketWord CloseCompleted() const noexcept {
    const SocketPhase cur = Phase();
    if (cur == SocketPhase::kCloseReady || cur == SocketPhase::kCloseQueued || cur == SocketPhase::kCloseSubmitted) {
      return WithInFlight(0U).TransitionTo(SocketPhase::kClosed);
    }
    return *this;
  }

  constexpr auto operator<=>(const SocketWord&) const noexcept = default;
};

static_assert((uarch::assert_no_padding<SocketWord>(), uarch::assert_register_pass<SocketWord>(),
               uarch::NoPadding<SocketWord>&& uarch::RegisterPassable<SocketWord>));

}  // namespace nexora
