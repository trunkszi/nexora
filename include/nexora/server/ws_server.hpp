#pragma once
#include <array>
#include <cstdint>
#include <nexora/error/runtime_error.hpp>
#include <nexora/websocket/codec.hpp>
#include <nexora/websocket/handshake.hpp>
#include <optional>
#include <span>
#include <utility>

namespace nexora {
class WebSocketServerSession {
  WebSocketCodec<> codec_{WebSocketRole::kServer};
  BytesMut<65536> input_{};
  BytesMut<65536> output_{};
  std::array<std::optional<WebSocketMessage>, 64> messages_{};
  std::uint32_t head_{0};
  std::uint32_t count_{0};
  enum class Phase : std::uint8_t { kIdle, kOpen, kClosing, kClosed };
  Phase phase_{Phase::kIdle};

 public:
  [[nodiscard]] bool IsOpen() const noexcept { return phase_ == Phase::kOpen; }
  [[nodiscard]] Result<Response> AcceptUpgrade(const Request& request) noexcept {
    if (phase_ != Phase::kIdle) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    const auto key = WebSocketHandshake::ValidateUpgradeRequest(request);
    if (!key) return std::unexpected(key.error());
    auto response = WebSocketHandshake::BuildUpgradeResponse(key->View());
    if (response) phase_ = Phase::kOpen;
    return response;
  }
  [[nodiscard]] Result<void> Feed(std::span<const std::uint8_t> bytes) noexcept {
    if (phase_ != Phase::kOpen && phase_ != Phase::kClosing)
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    auto appended = input_.Append(bytes);
    if (!appended) return appended;
    return Pump();
  }
  [[nodiscard]] Result<void> Pump() noexcept {
    if (phase_ != Phase::kOpen && phase_ != Phase::kClosing) return {};
    for (;;) {
      const auto pending = codec_.PendingControl();
      if (pending.size() > output_.CapacityRemaining()) return {};
      if (auto wrote = output_.Append(pending); !wrote) return wrote;
      codec_.ClearPendingControl();
      if (count_ == messages_.size() || output_.CapacityRemaining() < 131) return {};
      const auto before = input_.Size();
      auto decoded = codec_.DecodeMessage(input_.ReadableSpan());
      if (!decoded) return std::unexpected(decoded.error());
      input_.Consume(decoded->consumed);
      auto& message = decoded->message;
      if (message) {
        if ((*message).kind == WebSocketMessageKind::kClose) {
          if (phase_ == Phase::kOpen) {
            auto echoed = codec_.EncodeMessage(*message);
            if (!echoed) return std::unexpected(echoed.error());
            if (auto appended = output_.Append(echoed->ReadableSpan()); !appended) return appended;
          }
          phase_ = Phase::kClosed;
        }
        const auto slot = uarch::arithmetic::divisor_u32<64>().rem(head_ + count_);
        messages_[slot] = std::move(*message);
        ++count_;
        if (phase_ == Phase::kClosed) return {};
      } else if (before == input_.Size())
        return {};
    }
  }
  [[nodiscard]] Result<std::optional<WebSocketMessage>> PollMessage() noexcept {
    if (auto pumped = Pump(); !pumped) return std::unexpected(pumped.error());
    if (count_ == 0) return std::optional<WebSocketMessage>{};
    auto result = std::move(messages_[head_]);
    messages_[head_].reset();
    head_ = uarch::arithmetic::divisor_u32<64>().rem(head_ + 1);
    --count_;
    return result;
  }
  [[nodiscard]] Result<void> Send(const WebSocketMessage& message) noexcept {
    if (phase_ != Phase::kOpen) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    if (output_.CapacityRemaining() < message.payload.Size() + 16) return std::unexpected(Error::BufferOverflow());
    auto encoded = codec_.EncodeMessage(message);
    if (!encoded) return std::unexpected(encoded.error());
    auto appended = output_.Append(encoded->ReadableSpan());
    if (appended && message.kind == WebSocketMessageKind::kClose) phase_ = Phase::kClosing;
    return appended;
  }
  [[nodiscard]] std::span<const std::uint8_t> PendingOutput() const noexcept { return output_.ReadableSpan(); }
  [[nodiscard]] Result<void> ConsumeOutput(std::size_t bytes) noexcept {
    if (bytes > output_.Size()) return std::unexpected(Error::InvalidArgument());
    output_.Consume(bytes);
    return Pump();
  }
};
}  // namespace nexora
