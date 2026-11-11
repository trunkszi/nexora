#pragma once

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <cstring>
#include <memory>
#include <nexora/client/detail/native_runtime.hpp>
#include <nexora/client/detail/private_ring_route.hpp>
#include <nexora/client/detail/resolve.hpp>
#include <nexora/error/runtime_error.hpp>
#include <nexora/http1/http1_codec.hpp>
#include <nexora/pool/endpoint_failover.hpp>
#include <nexora/socket/memory_pipe.hpp>
#include <nexora/tls/secure_stream.hpp>
#include <nexora/websocket/codec.hpp>
#include <nexora/websocket/handshake.hpp>
#include <optional>
#include <span>
#include <string_view>

namespace nexora {
struct WebSocketClientConfig {
  std::uint32_t default_timeout_ms{2000};
  bool enable_tls{true};
  const TlsClientConfig* tls_config{nullptr};
};
class WebSocketClient {
  WebSocketClientConfig config_{};
  std::unique_ptr<detail::NativeRuntime> runtime_{};
  uring::Proactor* proactor_{nullptr};
  cares::Resolver<>* resolver_{nullptr};
  CompletionRoute fallback_{};
  detail::ParkedOperations parked_{};
  std::optional<SecureStream> stream_{};
  enum class Phase : std::uint8_t { kIdle, kHandshake, kOpen, kClosing, kClosed, kFailed };
  Phase phase_{Phase::kIdle};
  Http1ClientCodec<> http1_{};
  WebSocketCodec<> codec_{WebSocketRole::kClient};
  BytesMut<65536> input_{};
  BytesMut<65536> output_{};
  std::array<char, 25> key_{};
  std::array<std::optional<WebSocketMessage>, 64> messages_{};
  std::uint32_t head_{0};
  std::uint32_t count_{0};

 public:
  explicit WebSocketClient(WebSocketClientConfig config = {}) noexcept : config_(config) {}
  WebSocketClient(uring::Proactor& proactor, cares::Resolver<>& resolver, WebSocketClientConfig config,
                  CompletionRoute fallback) noexcept
      : config_(config), proactor_(&proactor), resolver_(&resolver), fallback_(fallback) {}
  template <std::size_t N>
  WebSocketClient(uring::Proactor& proactor, cares::Resolver<>& resolver, CompletionRoutes<N>& routes,
                  WebSocketClientConfig config = {}) noexcept
      : WebSocketClient(proactor, resolver, config, CompletionRoute::Bind(routes)) {}
  WebSocketClient(const WebSocketClient&) = delete ("websocket client owns its transport and session state");
  WebSocketClient& operator=(const WebSocketClient&) = delete ("websocket client owns its transport and session state");
  ~WebSocketClient() noexcept {
    if (stream_) stream_->Close();
    stream_.reset();
    if (runtime_ && runtime_->proactor && parked_.Count() != 0) {
      detail::DrainParkedOnProactor(
          *runtime_->proactor, runtime_->resolver ? &*runtime_->resolver : nullptr,
          +[](const void* p) noexcept { return static_cast<const detail::ParkedOperations*>(p)->Count(); }, &parked_);
    }
  }
  [[nodiscard]] Result<void> Start(const Uri& uri, const Headers<>& headers = {}) noexcept {
    if (phase_ != Phase::kIdle) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    std::array<unsigned char, 16> nonce{};
    std::array<unsigned char, 25> encoded_key{};
    if (RAND_bytes(nonce.data(), nonce.size()) != 1 || EVP_EncodeBlock(encoded_key.data(), nonce.data(), nonce.size()) != 24)
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketHandshakeFailed));
    std::memcpy(key_.data(), encoded_key.data(), key_.size());
    auto request = WebSocketHandshake::BuildUpgradeRequest(uri, std::string_view(key_.data(), 24), headers);
    if (!request) return std::unexpected(request.error());
    auto encoded = http1_.EncodeRequest(*request);
    if (!encoded) return std::unexpected(encoded.error());
    auto appended = output_.Append(encoded->ReadableSpan());
    if (appended) phase_ = Phase::kHandshake;
    return appended;
  }
  [[nodiscard]] bool IsOpen() const noexcept { return phase_ == Phase::kOpen; }
  [[nodiscard]] Result<void> Feed(std::span<const std::uint8_t> bytes) noexcept {
    if (phase_ == Phase::kIdle || phase_ == Phase::kFailed)
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    if (auto appended = input_.Append(bytes); !appended) return appended;
    auto pumped = Pump();
    if (!pumped) phase_ = Phase::kFailed;
    return pumped;
  }
  [[nodiscard]] Result<void> Pump() noexcept {
    if (phase_ == Phase::kHandshake) {
      auto response = http1_.DecodeResponse(input_.ReadableSpan(), Method::kGet);
      if (!response) return std::unexpected(response.error());
      if (!*response) {
        input_.Clear();
        return {};
      }
      input_.Consume((**response).consumed);
      auto accepted = WebSocketHandshake::ValidateUpgradeResponse((**response).message, std::string_view(key_.data(), 24));
      if (!accepted) return accepted;
      phase_ = Phase::kOpen;
    }
    if (phase_ != Phase::kOpen && phase_ != Phase::kClosing) return {};
    for (;;) {
      const auto pending = codec_.PendingControl();
      if (pending.size() > output_.CapacityRemaining()) return {};
      if (auto written = output_.Append(pending); !written) return written;
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
        messages_[uarch::arithmetic::divisor_u32<64>().rem(head_ + count_)] = std::move(*message);
        ++count_;
        if (phase_ == Phase::kClosed) return {};
      } else if (input_.Size() == before)
        return {};
    }
  }
  [[nodiscard]] Result<void> Send(const WebSocketMessage& message) noexcept {
    if (!IsOpen()) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    if (output_.CapacityRemaining() < message.payload.Size() + 16) return std::unexpected(Error::BufferOverflow());
    auto encoded = codec_.EncodeMessage(message);
    if (!encoded) return std::unexpected(encoded.error());
    auto appended = output_.Append(encoded->ReadableSpan());
    if (appended && message.kind == WebSocketMessageKind::kClose) phase_ = Phase::kClosing;
    return appended;
  }
  [[nodiscard]] Result<std::optional<WebSocketMessage>> PollMessage() noexcept {
    if (auto pumped = Pump(); !pumped) return std::unexpected(pumped.error());
    if (count_ == 0) return std::optional<WebSocketMessage>{};
    auto message = std::move(messages_[head_]);
    messages_[head_].reset();
    head_ = uarch::arithmetic::divisor_u32<64>().rem(head_ + 1);
    --count_;
    return message;
  }
  [[nodiscard]] std::span<const std::uint8_t> PendingOutput() const noexcept { return output_.ReadableSpan(); }
  [[nodiscard]] Result<void> ConsumeOutput(std::size_t bytes) noexcept {
    if (bytes > output_.Size()) return std::unexpected(Error::InvalidArgument());
    output_.Consume(bytes);
    return Pump();
  }
  template <typename Transport>
  [[nodiscard]] Result<void> Flush(Transport& transport, std::uint32_t timeout_ms) noexcept {
    const auto deadline = detail::After(timeout_ms);
    while (!PendingOutput().empty()) {
      const auto bytes = PendingOutput();
      if (auto wrote = transport.WriteAll(bytes, detail::Remaining(deadline)); !wrote) return wrote;
      if (auto consumed = ConsumeOutput(bytes.size()); !consumed) return consumed;
    }
    return {};
  }
  template <typename Transport>
  [[nodiscard]] Result<void> DriveOnce(Transport& transport, std::uint32_t timeout_ms) noexcept {
    const auto deadline = detail::After(timeout_ms);
    if (auto flushed = Flush(transport, detail::Remaining(deadline)); !flushed) return flushed;
    std::array<std::uint8_t, 32768> bytes{};
    auto read = transport.ReadSome(bytes, detail::Remaining(deadline));
    if (!read) return std::unexpected(read.error());
    if (*read == 0) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    return Feed(std::span(bytes).first(*read));
  }
  [[nodiscard]] Result<void> ConnectOverPipe(const Uri& uri, MemoryPipe& pipe) noexcept {
    if (phase_ == Phase::kIdle) {
      if (auto started = Start(uri); !started) return started;
    }
    if (IsOpen()) return {};
    auto driven = DriveOnce(pipe, config_.default_timeout_ms);
    if (!driven) return driven;
    return IsOpen() ? Result<void>{} : std::unexpected(Error::Incomplete());
  }
  [[nodiscard]] Result<void> Connect(const Uri& uri, std::uint32_t timeout_ms = 2000) noexcept {
    if (phase_ != Phase::kIdle || (uri.Scheme() != Scheme::kWs && uri.Scheme() != Scheme::kWss))
      return std::unexpected(Error::InvalidArgument());
    const auto deadline = detail::After(timeout_ms);
    if (!proactor_) {
      runtime_ = std::make_unique<detail::NativeRuntime>();
      if (auto initialized = runtime_->Init(); !initialized) return initialized;
      proactor_ = &*runtime_->proactor;
      resolver_ = &*runtime_->resolver;
      fallback_ = detail::PrivateRingRoute();
    }
    if (!detail::HasRoute(fallback_)) return std::unexpected(Error::InvalidArgument());
    if (uri.IsTls() && !config_.enable_tls) return std::unexpected(Error::InvalidArgument());
    auto endpoints =
        detail::ResolveEndpoints(*proactor_, *resolver_, uri.Authority(), uri.EffectivePort(), deadline, fallback_);
    if (!endpoints) return std::unexpected(endpoints.error());
    EndpointFailover<> failover;
    if (auto set = failover.SetEndpoints(*endpoints); !set) return std::unexpected(set.error());
    stream_.emplace(*proactor_, resolver_, kDefaultSocketIoSubsystemId, fallback_, &parked_);
    std::optional<Error> error;
    for (std::size_t index = 0; index < endpoints->size(); ++index) {
      auto selected = failover.SelectNext(detail::SteadyNowNs());
      if (!selected) break;
      auto connected = stream_->Connect((*endpoints)[*selected], detail::Remaining(deadline));
      if (connected) {
        error.reset();
        break;
      }
      error = connected.error();
      failover.MarkFailure(*selected, detail::SteadyNowNs());
    }
    if (!stream_->IsOpen())
      return std::unexpected(error.value_or(Error::FromRuntime(RuntimeErrorCode::kAllEndpointsUnhealthy)));
    if (uri.IsTls()) {
      std::optional<TlsClientConfig> defaults;
      if (!config_.tls_config) {
        auto created = TlsClientConfig::CreateDefault();
        if (!created) return std::unexpected(created.error());
        defaults.emplace(std::move(*created));
        constexpr std::array protocols{AlpnProtocol::kHttp11};
        if (auto set = defaults->SetAlpn(protocols); !set) return set;
      }
      const auto& config = config_.tls_config ? *config_.tls_config : *defaults;
      if (auto secured = stream_->StartClient(config, uri.Host(), detail::Remaining(deadline)); !secured) {
        stream_->Close();
        return secured;
      }
      if (stream_->Alpn() == AlpnProtocol::kHttp2) {
        stream_->Close();
        return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketHandshakeFailed));
      }
    }
    if (auto started = Start(uri); !started) {
      stream_->Close();
      return started;
    }
    while (!IsOpen()) {
      if (auto drove = DriveOnce(*stream_, detail::Remaining(deadline)); !drove) {
        phase_ = Phase::kFailed;
        stream_->Close();
        return drove;
      }
    }
    return {};
  }
  [[nodiscard]] Result<void> SendText(std::string_view text) noexcept {
    auto queued = Send(WebSocketMessage{.kind = WebSocketMessageKind::kText, .payload = Bytes::CopyFromString(text)});
    if (!queued || !stream_) return queued;
    return Flush(*stream_, config_.default_timeout_ms);
  }
  [[nodiscard]] Result<void> SendBinary(Bytes bytes) noexcept {
    auto queued = Send(WebSocketMessage{.kind = WebSocketMessageKind::kBinary, .payload = std::move(bytes)});
    if (!queued || !stream_) return queued;
    return Flush(*stream_, config_.default_timeout_ms);
  }
  [[nodiscard]] Result<WebSocketMessage> Receive(std::uint32_t timeout_ms = 2000) noexcept {
    if (!stream_) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    const auto deadline = detail::After(timeout_ms);
    for (;;) {
      if (auto pumped = Pump(); !pumped) return std::unexpected(pumped.error());
      if (!PendingOutput().empty()) {
        if (auto flushed = Flush(*stream_, detail::Remaining(deadline)); !flushed) return std::unexpected(flushed.error());
      }
      auto message = PollMessage();
      if (!message) return std::unexpected(message.error());
      if (*message) {
        if ((**message).kind == WebSocketMessageKind::kClose) {
          [[maybe_unused]] const auto notify = stream_->SendCloseNotify(detail::Remaining(deadline));
          stream_->Close();
        }
        return std::move(**message);
      }
      if (auto drove = DriveOnce(*stream_, detail::Remaining(deadline)); !drove) return std::unexpected(drove.error());
    }
  }
  [[nodiscard]] Result<void> Close(std::uint16_t code = 1000) noexcept {
    if (!IsOpen()) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    if (auto sent = Send(WebSocketMessage{.kind = WebSocketMessageKind::kClose, .close_code = code}); !sent) return sent;
    if (stream_) {
      if (auto flushed = Flush(*stream_, config_.default_timeout_ms); !flushed) return flushed;
    }
    return {};
  }
};
}  // namespace nexora
