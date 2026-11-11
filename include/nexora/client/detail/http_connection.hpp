#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <nexora/client/config.hpp>
#include <nexora/error/runtime_error.hpp>
#include <nexora/http1/http1_codec.hpp>
#include <nexora/http2/connection.hpp>
#include <nexora/http2/detail/event_flow.hpp>
#include <nexora/inbox/inbox.hpp>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

namespace nexora::detail {
struct ClientDriveSpec {
  using Word = std::uint64_t;
  bool draining[[= uarch::bits::Flag{0}]];
  bool driving[[= uarch::bits::Flag{1}]];
  bool finishing_all[[= uarch::bits::Flag{2}]];
};

[[nodiscard]] inline Result<void> PrevalidateHttp2Submit(const Request& req, std::size_t pending_out_bytes) noexcept {
  if (4uz + req.headers.Size() > 72uz) return std::unexpected(Error::BufferOverflow());
  const auto authority = req.uri.Authority();
  const auto path = req.uri.PathAndQuery();
  if (authority.empty() || path.empty() || !IsValidHeaderValue(authority) || !IsValidHeaderValue(path)) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
  }
  HeaderField probe{};
  if (!probe.value.TryAssign(authority) || !probe.value.TryAssign(path)) {
    return std::unexpected(Error::BufferOverflow());
  }
  std::size_t wire_budget = kHttp2FrameHeaderSize + 32uz + authority.size() + path.size();
  for (const auto& field : req.headers.Fields()) {
    const std::string_view name = field.name;
    const std::string_view value = field.value;
    const bool hop_by_hop = name == "connection" || name == "keep-alive" || name == "proxy-connection" ||
                            name == "transfer-encoding" || name == "upgrade" || (name == "te" && value != "trailers");
    if (!IsValidHttp2HeaderName(name, false) || hop_by_hop) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2ProtocolError));
    }
    if (!IsValidHeaderValue(value)) return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
    if (!probe.name.TryAssign(name) || !probe.value.TryAssign(value)) {
      return std::unexpected(Error::BufferOverflow());
    }
    wire_budget += 8uz + name.size() + value.size();
  }
  if (req.trailers.Size() > 72uz) return std::unexpected(Error::BufferOverflow());
  for (const auto& field : req.trailers.Fields()) {
    const std::string_view name = field.name;
    const std::string_view value = field.value;
    const bool edged =
        (!name.empty() && (name.front() == ' ' || name.front() == '\t' || name.back() == ' ' || name.back() == '\t')) ||
        (!value.empty() && (value.front() == ' ' || value.front() == '\t' || value.back() == ' ' || value.back() == '\t'));
    const bool hop_by_hop = name == "connection" || name == "keep-alive" || name == "proxy-connection" ||
                            name == "transfer-encoding" || name == "upgrade" || (name == "te" && value != "trailers");
    if (!IsValidHttp2HeaderName(name, false) || hop_by_hop) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2ProtocolError));
    }
    if (edged || !IsValidHeaderValue(value)) return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
    if (!probe.name.TryAssign(name) || !probe.value.TryAssign(value)) return std::unexpected(Error::BufferOverflow());
  }
  wire_budget += (wire_budget / 16384uz) * kHttp2FrameHeaderSize;
  if (pending_out_bytes >= 65536uz || (65536uz - pending_out_bytes) < wire_budget) {
    return std::unexpected(Error::BufferOverflow());
  }
  return {};
}

class HttpClientConnection {
 public:
  struct Completion {
    ResponseCallback callback;
    Result<Response> response;
    std::unique_ptr<Completion> next{};
  };

 private:
  struct Pending {
    RequestId id{};
    Request request{};
    ResponseCallback callback{};
    std::chrono::steady_clock::time_point deadline{};
    std::optional<Response> response{};
    std::uint32_t stream{0};
    std::uint32_t unreplenished{0};
    std::size_t sent{0};
    std::size_t received{0};
    bool upload_done{false};
    bool internal{false};
  };
  std::unique_ptr<Completion> completions_{};
  Completion* completion_tail_{nullptr};
  ClientConfig config_{};
  Http1ClientCodec<> http1_{};
  std::unique_ptr<Http2Connection> http2_{};
  BytesMut<65536> input_{};
  BytesMut<65536> output_{};
  std::unique_ptr<std::array<Pending, 64>> pending_{std::make_unique<std::array<Pending, 64>>()};
  uarch::Bitmap64 active_{};
  std::array<std::uint32_t, 64> order_{};
  std::uint32_t order_head_{0};
  std::uint32_t order_count_{0};
  std::uint32_t conn_unreplenished_{0};
  uarch::BitWord<ClientDriveSpec> flags_{};
  cares::Delegate<void(RequestId, const Http2Event&)> stream_hook_{};
  cares::Delegate<void(RequestId)> completion_hook_{};

  [[nodiscard]] std::optional<std::uint32_t> Stream(std::uint32_t stream) const noexcept {
    auto bits = active_;
    while (const auto slot = bits.pop_lowest_one())
      if ((*pending_)[*slot].stream == stream) return slot;
    return std::nullopt;
  }
  void ReplenishWindows(bool force_conn = false) noexcept {
    if (!http2_) return;
    constexpr std::uint32_t half_window = 32767U;
    ReplenishConnectionWindow(*http2_, conn_unreplenished_, force_conn, half_window);
    auto bits = active_;
    while (const auto slot = bits.pop_lowest_one()) {
      auto& p = (*pending_)[*slot];
      if (p.stream != 0 && p.unreplenished >= half_window) {
        if (http2_->SubmitWindowUpdate(p.stream, p.unreplenished)) p.unreplenished = 0;
      }
    }
  }
  void Finish(std::uint32_t slot, Result<Response> response) noexcept {
    const auto id = (*pending_)[slot].id;
    const bool pending_internal = (*pending_)[slot].internal;
    auto callback = std::move((*pending_)[slot].callback);
    (*pending_)[slot] = Pending{};
    active_ = active_.clear(slot);
    if (completion_hook_) completion_hook_(id);
    if (callback && pending_internal)
      callback(std::move(response));
    else if (callback) {
      auto completion = std::make_unique<Completion>(std::move(callback), std::move(response));
      auto* tail = completion.get();
      if (completion_tail_)
        completion_tail_->next = std::move(completion);
      else
        completions_ = std::move(completion);
      completion_tail_ = tail;
    }
  }
  [[nodiscard]] Result<void> FlushBodies(std::optional<std::uint32_t> owner = std::nullopt) noexcept {
    if (!http2_) return {};
    ReplenishWindows();
    auto bits = active_;
    while (const auto slot = bits.pop_lowest_one()) {
      auto& pending = (*pending_)[*slot];
      if (pending.upload_done) continue;
      std::optional<Error> failed;
      while (pending.sent < pending.request.body.Size()) {
        auto sent = http2_->SubmitData(pending.stream, pending.request.body.Span().subspan(pending.sent),
                                       pending.request.trailers.Empty());
        if (!sent) {
          if (sent.error() == Error::BufferOverflow()) return {};
          failed = sent.error();
          break;
        }
        if (*sent == 0) break;
        pending.sent += *sent;
      }
      if (!failed && pending.sent >= pending.request.body.Size() && !pending.request.trailers.Empty()) {
        auto trailers = http2_->SubmitTrailers(pending.stream, pending.request.trailers);
        if (!trailers) {
          if (trailers.error() == Error::BufferOverflow()) return {};
          failed = trailers.error();
        }
      }
      if (failed) {
        if (owner && *owner == *slot) return std::unexpected(*failed);
        const auto stream = pending.stream;
        [[maybe_unused]] const auto reset = http2_->SubmitRstStream(stream, Http2ErrorCode::kCancel);
        Finish(*slot, std::unexpected(*failed));
        continue;
      }
      if (pending.sent < pending.request.body.Size()) continue;
      pending.upload_done = true;
    }
    return {};
  }
  [[nodiscard]] Result<void> ReadHttp1() noexcept {
    while (order_count_ != 0) {
      const auto slot = order_[order_head_];
      auto response = http1_.DecodeResponse(input_.ReadableSpan(), (*pending_)[slot].request.method);
      if (!response) return std::unexpected(response.error());
      if (!*response) {
        input_.Clear();
        break;
      }
      auto& decoded = **response;
      input_.Consume(decoded.consumed);
      if (decoded.message.status.IsInformational() && decoded.message.status.AsU16() != 101) continue;
      if (decoded.message.body.Size() > config_.max_body_size) return std::unexpected(Error::BufferOverflow());
      flags_ = flags_.with<^^ClientDriveSpec::draining>(decoded.keep_alive != Http1KeepAlive::kKeepAlive);
      order_head_ = uarch::arithmetic::divisor_u32<64>().rem(order_head_ + 1);
      --order_count_;
      Finish(slot, std::move(decoded.message));
      if (flags_.test<^^ClientDriveSpec::draining>()) {
        CancelAll(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
        break;
      }
    }
    if (order_count_ == 0 && !input_.Empty()) {
      flags_ = flags_.with<^^ClientDriveSpec::draining>(true);
      input_.Clear();
    }
    return {};
  }
  [[nodiscard]] Result<void> ReadHttp2() noexcept {
    while (auto event = http2_->PollEvent()) {
      if (event->kind == Http2Event::Kind::kGoaway) {
        flags_ = flags_.with<^^ClientDriveSpec::draining>(true);
        auto bits = active_;
        while (const auto slot = bits.pop_lowest_one())
          if ((*pending_)[*slot].stream > event->last_stream_id)
            Finish(*slot, std::unexpected(Error::FromHttp2(Http2ErrorCode::kRefusedStream)));
        continue;
      }
      if (event->kind == Http2Event::Kind::kData) {
        if (const auto credit = EventFlowControlBytes(*event); credit != 0) {
          conn_unreplenished_ = uarch::saturating_add(conn_unreplenished_, static_cast<std::uint32_t>(credit));
        }
      }
      const auto slot = Stream(event->stream_id);
      if (!slot) {
        ReplenishWindows(event->kind == Http2Event::Kind::kData);
        continue;
      }
      auto& pending = (*pending_)[*slot];
      const auto id = pending.id;
      if (event->kind == Http2Event::Kind::kHeaders) {
        pending.response.emplace();
        pending.response->status = event->status;
        pending.response->version = Version::kHttp2;
        pending.response->headers = event->headers;
      } else if (event->kind == Http2Event::Kind::kData) {
        if (event->data.size() > config_.max_body_size - pending.received) {
          if (!http2_->SubmitRstStream(pending.stream, Http2ErrorCode::kCancel))
            flags_ = flags_.with<^^ClientDriveSpec::draining>(true);
          Finish(*slot, std::unexpected(Error::BufferOverflow()));
          ReplenishWindows(true);
          continue;
        }
        pending.received += event->data.size();
        if (!event->end_stream)
          pending.unreplenished =
              uarch::saturating_add(pending.unreplenished, static_cast<std::uint32_t>(EventFlowControlBytes(*event)));
        else
          pending.unreplenished = 0;
        ReplenishWindows();
      } else if (event->kind == Http2Event::Kind::kTrailers) {
        if (pending.response) pending.response->trailers = event->headers;
      } else if (event->kind == Http2Event::Kind::kStreamReset) {
        Finish(*slot, std::unexpected(event->error_code == Http2ErrorCode::kNoError ? Error::Cancelled()
                                                                                    : Error::FromHttp2(event->error_code)));
        ReplenishWindows(true);
      } else if (event->kind == Http2Event::Kind::kMessageComplete) {
        if (!pending.response) {
          [[maybe_unused]] const auto reset = http2_->SubmitRstStream(pending.stream, Http2ErrorCode::kProtocolError);
          Finish(*slot, std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2ProtocolError)));
          ReplenishWindows(true);
          continue;
        }
        if (event->data.size() > config_.max_body_size) {
          [[maybe_unused]] const auto reset = http2_->SubmitRstStream(pending.stream, Http2ErrorCode::kCancel);
          Finish(*slot, std::unexpected(Error::BufferOverflow()));
          ReplenishWindows(true);
          continue;
        }
        pending.response->body = Bytes::CopyFromSlice(event->data);
        auto response = std::move(*pending.response);
        Finish(*slot, std::move(response));
        ReplenishWindows();
      }
      if (stream_hook_) stream_hook_(id, *event);
    }
    return FlushBodies();
  }

 public:
  [[nodiscard]] std::unique_ptr<Completion> TakeCallbacks() noexcept {
    completion_tail_ = nullptr;
    return std::move(completions_);
  }
  explicit HttpClientConnection(ClientConfig config = {}) noexcept : config_(std::move(config)) {}
  HttpClientConnection(const HttpClientConnection&) = delete ("connection owns pending protocol state");
  HttpClientConnection& operator=(const HttpClientConnection&) = delete ("connection owns pending protocol state");
  ~HttpClientConnection() noexcept { CancelAll(); }
  [[nodiscard]] Result<void> UseHttp2() noexcept {
    if (flags_.test<^^ClientDriveSpec::driving>() || http2_ || !active_.is_empty() || !input_.Empty() || !output_.Empty())
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    Http2Limits limits{};
    limits.max_coalesced_body_bytes = std::max<std::size_t>(262144uz, config_.max_body_size);
    conn_unreplenished_ = 0;
    http2_ = std::make_unique<Http2Connection>(Http2Role::kClient, Http2Settings{}, limits);
    return http2_->InitiateHandshake();
  }
  void SetCompletionHook(cares::Delegate<void(RequestId)> hook) noexcept { completion_hook_ = hook; }
  void SetStreamHook(cares::Delegate<void(RequestId, const Http2Event&)> hook) noexcept { stream_hook_ = hook; }
  [[nodiscard]] bool IsHttp2() const noexcept { return static_cast<bool>(http2_); }
  [[nodiscard]] bool Reusable() const noexcept { return !flags_.test<^^ClientDriveSpec::draining>(); }
  [[nodiscard]] std::size_t ActiveCount() const noexcept { return active_.count(); }
  [[nodiscard]] std::optional<std::chrono::steady_clock::time_point> NextDeadline() const noexcept {
    std::optional<std::chrono::steady_clock::time_point> deadline;
    auto bits = active_;
    while (const auto slot = bits.pop_lowest_one())
      if (!deadline || (*pending_)[*slot].deadline < *deadline) deadline = (*pending_)[*slot].deadline;
    return deadline;
  }
  [[nodiscard]] Result<void> Submit(RequestId id, Request request, ResponseCallback callback,
                                    std::chrono::steady_clock::time_point deadline, bool internal = false) noexcept {
    if (flags_.test<^^ClientDriveSpec::draining>() || !callback)
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    if (request.body.Size() > config_.max_request_body_size || request.uri.Host().empty())
      return std::unexpected(Error::InvalidArgument());
    const auto slot = active_.lowest_zero();
    if (!slot) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kPoolExhausted));
    if (http2_) {
      if (auto valid = PrevalidateHttp2Submit(request, http2_->PendingOutput().size()); !valid) return valid;
    } else if (output_.CapacityRemaining() < 32768) {
      return std::unexpected(Error::BufferOverflow());
    }
    auto& pending = (*pending_)[*slot];
    pending.internal = internal;
    pending.id = id;
    pending.request = std::move(request);
    pending.callback = std::move(callback);
    pending.deadline = deadline;
    active_ = active_.set(*slot);
    Result<void> encoded;
    if (http2_) {
      auto stream = http2_->OpenStream();
      if (!stream) {
        pending = Pending{};
        active_ = active_.clear(*slot);
        return std::unexpected(stream.error());
      }
      pending.stream = *stream;
      const bool ended = pending.request.body.Empty() && pending.request.trailers.Empty();
      encoded = http2_->SubmitRequestHeaders(*stream, pending.request.method, pending.request.uri.IsTls() ? "https" : "http",
                                             pending.request.uri.Authority(), pending.request.uri.PathAndQuery(),
                                             pending.request.headers, ended);
      pending.upload_done = ended;
    } else {
      auto wire = http1_.EncodeRequest(pending.request);
      encoded = wire ? output_.Append(wire->ReadableSpan()) : Result<void>(std::unexpected(wire.error()));
      if (encoded) {
        order_[uarch::arithmetic::divisor_u32<64>().rem(order_head_ + order_count_)] = *slot;
        ++order_count_;
      }
    }
    if (!encoded) {
      // HEADERS were never emitted on the wire; never send RST_STREAM on an idle stream.
      pending = Pending{};
      active_ = active_.clear(*slot);
      return encoded;
    }
    auto flushed = FlushBodies(slot);
    if (!flushed) {
      if (http2_) {
        [[maybe_unused]] const auto reset = http2_->SubmitRstStream(pending.stream, Http2ErrorCode::kCancel);
      }
      pending = Pending{};
      active_ = active_.clear(*slot);
    }
    return flushed;
  }
  [[nodiscard]] Result<void> Feed(std::span<const std::uint8_t> bytes) noexcept {
    if (flags_.test<^^ClientDriveSpec::driving>()) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    struct Guard {
      uarch::BitWord<ClientDriveSpec>& flags;
      explicit Guard(uarch::BitWord<ClientDriveSpec>& value) noexcept : flags(value) {
        flags = flags.with<^^ClientDriveSpec::driving>(true);
      }
      // NOLINTNEXTLINE(modernize-use-equals-default) -- stock clang-tidy lacks <meta> for BitWord Guard reset.
      ~Guard() { flags = flags.with<^^ClientDriveSpec::driving>(false); }
    } guard(flags_);
    if (http2_) {
      return DrainHttp2Ingress(*http2_, input_, bytes, [this]() noexcept { return ReadHttp2(); });
    }
    if (auto appended = input_.Append(bytes); !appended) return appended;
    return ReadHttp1();
  }
  [[nodiscard]] std::span<const std::uint8_t> PendingOutput() const noexcept {
    return http2_ ? http2_->PendingOutput() : output_.ReadableSpan();
  }
  [[nodiscard]] Result<void> ConsumeOutput(std::size_t bytes) noexcept {
    if (bytes > PendingOutput().size()) return std::unexpected(Error::InvalidArgument());
    if (flags_.test<^^ClientDriveSpec::driving>()) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    if (!http2_) {
      output_.Consume(bytes);
      return {};
    }
    struct Guard {
      uarch::BitWord<ClientDriveSpec>& flags;
      explicit Guard(uarch::BitWord<ClientDriveSpec>& value) noexcept : flags(value) {
        flags = flags.with<^^ClientDriveSpec::driving>(true);
      }
      // NOLINTNEXTLINE(modernize-use-equals-default) -- stock clang-tidy lacks <meta> for BitWord Guard reset.
      ~Guard() { flags = flags.with<^^ClientDriveSpec::driving>(false); }
    } guard(flags_);
    http2_->ConsumeOutput(bytes);
    if (!input_.Empty() || http2_->IsIngressPaused() || http2_->PeekEventView().has_value()) {
      return DrainHttp2Ingress(*http2_, input_, {}, [this]() noexcept { return ReadHttp2(); });
    }
    return FlushBodies();
  }
  [[nodiscard]] bool Cancel(RequestId id, Error error = Error::Cancelled()) noexcept {
    auto bits = active_;
    while (const auto slot = bits.pop_lowest_one()) {
      if ((*pending_)[*slot].id != id) continue;
      if (!http2_) {
        CancelAll(error);
        return true;
      }
      auto reset = http2_->SubmitRstStream((*pending_)[*slot].stream, Http2ErrorCode::kCancel);
      if (!reset) flags_ = flags_.with<^^ClientDriveSpec::draining>(true);
      Finish(*slot, std::unexpected(error));
      ReplenishWindows(true);
      return true;
    }
    return false;
  }
  void Tick(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) noexcept {
    auto bits = active_;
    while (const auto slot = bits.pop_lowest_one())
      if (active_.test(*slot) && now >= (*pending_)[*slot].deadline)
        static_cast<void>(Cancel((*pending_)[*slot].id, Error::Timeout()));
  }
  void CancelAll(Error error = Error::Cancelled()) noexcept {
    if (flags_.test<^^ClientDriveSpec::finishing_all>()) return;
    flags_ = flags_.with<^^ClientDriveSpec::finishing_all>(true);
    flags_ = flags_.with<^^ClientDriveSpec::draining>(true);
    order_count_ = 0;
    input_.Clear();
    if (!http2_) output_.Clear();
    auto bits = active_;
    while (const auto slot = bits.pop_lowest_one())
      if (active_.test(*slot)) Finish(*slot, std::unexpected(error));
    flags_ = flags_.with<^^ClientDriveSpec::finishing_all>(false);
  }
};
}  // namespace nexora::detail
