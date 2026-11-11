#pragma once
#include <algorithm>
#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <nexora/error/runtime_error.hpp>
#include <nexora/http1/http1_codec.hpp>
#include <nexora/http2/connection.hpp>
#include <nexora/http2/detail/event_flow.hpp>
#include <nexora/server/detail/http_server_helpers.hpp>
#include <nexora/server/listener.hpp>
#include <nexora/server/service.hpp>
#include <nexora/server/ws_server.hpp>
#include <nexora/socket/memory_pipe.hpp>
#include <nexora/tls/secure_stream.hpp>
#include <optional>
#include <span>
#include <string>
#include <utility>

namespace nexora {
struct ServerConfig {
  std::size_t max_inflight{64};
  std::size_t max_body_size{16384};
  bool allow_http2{true};
  Http2Settings http2{};
};

class HttpServer {
  enum class Protocol : std::uint8_t { kSniff, kHttp1, kHttp2, kWebSocket, kClosed };
  struct Work {
    std::uint32_t stream{0};
    std::uint32_t unreplenished{0};
    Version version{Version::kHttp11};
    Method method{Method::kGet};
    std::string target{};
    std::optional<Request> request{};
    std::size_t received{0};
    std::optional<ServerRequestHandle> handle{};
    std::optional<ServerReply> reply{};
    std::size_t sent{0};
    uarch::BitWord<detail::ServerWorkSpec> flags{};
  };
  ServerConfig config_{};
  HttpService service_{};
  ResponseChannel responses_{};
  Protocol protocol_{Protocol::kSniff};
  Http1ServerCodec<> http1_{};
  std::unique_ptr<Http2Connection> http2_{};
  std::optional<WebSocketServerSession> websocket_{};
  cares::Delegate<Result<void>(std::string_view, WebSocketServerSession&, WebSocketMessage)> ws_handler_{};
  std::string websocket_path_{};
  cares::Delegate<bool(std::string_view)> ws_route_{};
  BytesMut<65536> input_{};
  BytesMut<65536> output_{};
  std::unique_ptr<std::array<Work, 64>> work_{std::make_unique<std::array<Work, 64>>()};
  uarch::Bitmap64 occupied_{};
  std::array<std::uint32_t, 64> order_{};
  std::uint32_t order_head_{0};
  std::uint32_t order_count_{0};
  std::uint32_t conn_unreplenished_{0};
  uarch::BitWord<detail::ServerDriveSpec> flags_{};
  std::optional<cares::Endpoint> peer_{};

  [[nodiscard]] std::unique_ptr<Http2Connection> MakeHttp2() const noexcept {
    Http2Limits limits{};
    limits.max_coalesced_body_bytes = std::max<std::size_t>(262144uz, config_.max_body_size);
    return std::make_unique<Http2Connection>(Http2Role::kServer, config_.http2, limits);
  }
  [[nodiscard]] std::optional<std::uint32_t> FindStream(std::uint32_t stream) const noexcept {
    auto bits = occupied_;
    while (const auto slot = bits.pop_lowest_one())
      if ((*work_)[*slot].stream == stream) return slot;
    return std::nullopt;
  }
  void Release(std::uint32_t slot) noexcept {
    if ((*work_)[slot].handle) responses_.Complete(*(*work_)[slot].handle);
    (*work_)[slot] = Work{};
    occupied_ = occupied_.clear(slot);
  }
  void ResetStream(std::uint32_t stream_id, Http2ErrorCode code) noexcept {
    if (http2_) {
      [[maybe_unused]] const auto reset = http2_->SubmitRstStream(stream_id, code);
    }
  }
  void ReplenishWindows(bool force_conn = false) noexcept {
    if (!http2_) return;
    const std::uint32_t stream_threshold = std::max<std::uint32_t>(1U, config_.http2.initial_window_size / 2U);
    constexpr std::uint32_t conn_threshold = 32767U;
    detail::ReplenishConnectionWindow(*http2_, conn_unreplenished_, force_conn, conn_threshold);
    auto bits = occupied_;
    while (const auto slot = bits.pop_lowest_one()) {
      auto& w = (*work_)[*slot];
      if (w.stream != 0 && w.unreplenished >= stream_threshold) {
        if (http2_->SubmitWindowUpdate(w.stream, w.unreplenished)) w.unreplenished = 0;
      }
    }
  }
  [[nodiscard]] Result<std::uint32_t> Allocate(std::uint32_t stream) noexcept {
    if (occupied_.count() >= config_.max_inflight) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kPoolExhausted));
    const auto slot = occupied_.lowest_zero();
    if (!slot) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kPoolExhausted));
    occupied_ = occupied_.set(*slot);
    (*work_)[*slot].stream = stream;
    return *slot;
  }
  [[nodiscard]] Result<void> Dispatch(std::uint32_t slot) noexcept {
    auto& work = (*work_)[slot];
    auto responder = responses_.Open(work.stream);
    if (!responder) return std::unexpected(responder.error());
    work.handle = responder->Handle();
    RequestContext context{};
    context.target = work.target;
    context.peer = peer_;
    context.version = work.version;
    context.stream_id = work.stream;
    context.request_id = work.handle->Raw();
    // NOLINTNEXTLINE(performance-move-const-arg) -- stock clang-tidy lacks <meta> for WorkSlot Request move.
    auto request = std::move(*work.request);
    work.request.reset();
    return service_.Call(context, std::move(request), std::move(*responder));
  }
  [[nodiscard]] Result<void> ReadHttp1() noexcept {
    while (!flags_.test<^^detail::ServerDriveSpec::stop_reading>() && occupied_.count() < config_.max_inflight &&
           !input_.Empty()) {
      auto decoded = http1_.DecodeRequest(input_.ReadableSpan());
      if (!decoded) return std::unexpected(decoded.error());
      if (!*decoded) {
        input_.Clear();
        break;
      }
      input_.Consume((**decoded).consumed);
      Request request = std::move((**decoded).message);
      if (request.body.Size() > config_.max_body_size) return std::unexpected(Error::BufferOverflow());
      if ((**decoded).keep_alive == Http1KeepAlive::kUpgrade) {
        if (order_count_ != 0) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
        const auto target = request.uri.PathAndQuery();
        websocket_path_ = target.substr(0, target.find('?'));
        if (ws_route_ && !ws_route_(websocket_path_)) {
          auto rejected = Response::WithStatus(StatusCode{404});
          if (auto set = rejected.headers.Set("connection", "close"); !set) return set;
          flags_ =
              flags_.with<^^detail::ServerDriveSpec::stop_reading>(true).with<^^detail::ServerDriveSpec::close_when_flushed>(
                  true);
          auto encoded = http1_.EncodeResponse(rejected);
          if (!encoded) return std::unexpected(encoded.error());
          return output_.Append(encoded->ReadableSpan());
        }
        WebSocketServerSession candidate;
        auto accepted = candidate.AcceptUpgrade(request);
        if (!accepted) return std::unexpected(accepted.error());
        auto encoded = http1_.EncodeResponse(*accepted);
        if (!encoded) return std::unexpected(encoded.error());
        if (auto appended = output_.Append(encoded->ReadableSpan()); !appended) return appended;
        websocket_.emplace(std::move(candidate));
        protocol_ = Protocol::kWebSocket;
        auto fed = websocket_->Feed(input_.ReadableSpan());
        if (fed) input_.Clear();
        return fed;
      }
      auto slot = Allocate(0);
      if (!slot) return std::unexpected(slot.error());
      auto& work = (*work_)[*slot];
      const bool closing = (**decoded).keep_alive == Http1KeepAlive::kClose;
      work.flags = work.flags.with<^^detail::ServerWorkSpec::close_after>(closing);
      flags_ = flags_.with<^^detail::ServerDriveSpec::stop_reading>(closing);
      work.version = request.version;
      work.method = request.method;
      work.target = request.uri.PathAndQuery();
      work.request.emplace(std::move(request));
      const auto tail = uarch::arithmetic::divisor_u32<64>().rem(order_head_ + order_count_);
      order_[tail] = *slot;
      ++order_count_;
      if (auto dispatched = Dispatch(*slot); !dispatched) return dispatched;
    }
    return {};
  }
  [[nodiscard]] Result<void> ReadHttp2() noexcept {
    while (auto event = http2_->PollEvent()) {
      if (event->kind == Http2Event::Kind::kHeaders) {
        auto request = detail::BuildValidatedHttp2Request(*event);
        if (!request) {
          ResetStream(event->stream_id, Http2ErrorCode::kProtocolError);
          continue;
        }
        auto slot = Allocate(event->stream_id);
        if (!slot) {
          ResetStream(event->stream_id, Http2ErrorCode::kRefusedStream);
          continue;
        }
        (*work_)[*slot].target = event->path;
        (*work_)[*slot].method = event->method;
        (*work_)[*slot].version = Version::kHttp2;
        (*work_)[*slot].request.emplace(std::move(*request));
      } else if (event->kind == Http2Event::Kind::kData) {
        if (const auto credit = detail::EventFlowControlBytes(*event); credit != 0) {
          conn_unreplenished_ = uarch::saturating_add(conn_unreplenished_, static_cast<std::uint32_t>(credit));
        }
        if (const auto slot = FindStream(event->stream_id)) {
          auto& work = (*work_)[*slot];
          if (event->data.size() > config_.max_body_size - work.received) {
            Release(*slot);
            ResetStream(event->stream_id, Http2ErrorCode::kRefusedStream);
            ReplenishWindows(true);
            continue;
          }
          work.received += event->data.size();
          if (!event->end_stream)
            work.unreplenished =
                uarch::saturating_add(work.unreplenished, static_cast<std::uint32_t>(detail::EventFlowControlBytes(*event)));
          else
            work.unreplenished = 0;
        }
        ReplenishWindows();
      } else if (event->kind == Http2Event::Kind::kTrailers) {
        if (const auto slot = FindStream(event->stream_id); slot && (*work_)[*slot].request)
          (*work_)[*slot].request->trailers = std::move(event->headers);
      } else if (event->kind == Http2Event::Kind::kStreamReset) {
        if (const auto slot = FindStream(event->stream_id)) Release(*slot);
        ReplenishWindows(true);
      } else if (event->kind == Http2Event::Kind::kMessageComplete) {
        const auto slot = FindStream(event->stream_id);
        if (!slot || !(*work_)[*slot].request) continue;
        if (event->data.size() > config_.max_body_size) {
          Release(*slot);
          ResetStream(event->stream_id, Http2ErrorCode::kRefusedStream);
          ReplenishWindows(true);
          continue;
        }
        (*work_)[*slot].request->body = Bytes::CopyFromSlice(event->data);
        if (auto dispatched = Dispatch(*slot); !dispatched) {
          Release(*slot);
          ResetStream(event->stream_id, Http2ErrorCode::kInternalError);
        }
      }
    }
    return {};
  }
  [[nodiscard]] Result<void> FlushReplies() noexcept {
    while (auto reply = responses_.Poll()) {
      auto bits = occupied_;
      bool found = false;
      while (const auto slot = bits.pop_lowest_one()) {
        if ((*work_)[*slot].handle == reply->handle) {
          (*work_)[*slot].reply.emplace(std::move(*reply));
          found = true;
          break;
        }
      }
      if (!found) responses_.Complete(reply->handle);
    }
    if (protocol_ == Protocol::kHttp1) {
      while (output_.Empty() && order_count_ != 0) {
        const auto slot = order_[order_head_];
        auto& work = (*work_)[slot];
        if (!work.reply) break;
        auto& resp = work.reply->response;
        if (resp.version != Version::kHttp10) resp.version = work.version;
        const bool handler_close =
            detail::HasHeaderTokenIgnoreCase(resp.headers, "connection", "close") ||
            (resp.version == Version::kHttp10 && !detail::HasHeaderTokenIgnoreCase(resp.headers, "connection", "keep-alive"));
        const bool closing = work.flags.test<^^detail::ServerWorkSpec::close_after>() || handler_close;
        if (closing && !resp.headers.Get("connection")) {
          if (auto set = resp.headers.Set("connection", "close"); !set) return set;
        }
        auto encoded = http1_.EncodeResponse(resp, work.method);
        if (!encoded) return std::unexpected(encoded.error());
        if (auto appended = output_.Append(encoded->ReadableSpan()); !appended) return appended;
        if (closing) {
          flags_ =
              flags_.with<^^detail::ServerDriveSpec::stop_reading>(true).with<^^detail::ServerDriveSpec::close_when_flushed>(
                  true);
        }
        Release(slot);
        order_head_ = uarch::arithmetic::divisor_u32<64>().rem(order_head_ + 1);
        --order_count_;
        if (closing) break;
      }
    } else if (protocol_ == Protocol::kHttp2) {
      ReplenishWindows();
      auto bits = occupied_;
      while (const auto slot = bits.pop_lowest_one()) {
        auto& work = (*work_)[*slot];
        if (!work.reply) continue;
        auto& response = work.reply->response;
        const auto status_code = response.status.AsU16();
        if (status_code < 200 && status_code != 101) {
          const auto sid = work.stream;
          Release(*slot);
          ResetStream(sid, Http2ErrorCode::kInternalError);
          continue;
        }
        const bool omit_body = detail::ResponseOmitsBody(work.method, response.status);
        const std::span<const std::uint8_t> body = omit_body ? std::span<const std::uint8_t>{} : response.body.Span();
        if (!work.flags.test<^^detail::ServerWorkSpec::headers_sent>()) {
          const bool ended = body.empty() && response.trailers.Empty();
          auto headers = http2_->SubmitResponseHeaders(work.stream, response.status, response.headers, ended);
          if (!headers) {
            if (headers.error() == Error::BufferOverflow()) break;
            const auto sid = work.stream;
            Release(*slot);
            if (headers.error() != Error::FromProto(ProtoErrorCode::kHttp2StreamClosed))
              ResetStream(sid, Http2ErrorCode::kInternalError);
            continue;
          }
          work.flags = work.flags.with<^^detail::ServerWorkSpec::headers_sent>(true);
          if (ended) {
            Release(*slot);
            continue;
          }
        }
        while (work.sent < body.size()) {
          auto sent = http2_->SubmitData(work.stream, body.subspan(work.sent), response.trailers.Empty());
          if (!sent) {
            if (sent.error() == Error::BufferOverflow()) return {};
            const auto sid = work.stream;
            Release(*slot);
            if (sent.error() != Error::FromProto(ProtoErrorCode::kHttp2StreamClosed))
              ResetStream(sid, Http2ErrorCode::kInternalError);
            break;
          }
          if (*sent == 0) break;
          work.sent += *sent;
        }
        if (!occupied_.test(*slot) || work.sent < body.size()) continue;
        if (!response.trailers.Empty()) {
          auto trailers = http2_->SubmitTrailers(work.stream, response.trailers);
          if (!trailers) {
            if (trailers.error() == Error::BufferOverflow()) break;
            const auto sid = work.stream;
            Release(*slot);
            if (trailers.error() != Error::FromProto(ProtoErrorCode::kHttp2StreamClosed))
              ResetStream(sid, Http2ErrorCode::kInternalError);
            continue;
          }
        }
        Release(*slot);
      }
    }
    return {};
  }
  template <typename Transport>
  void DrainBrokenOutput(Transport& transport, detail::Deadline deadline) noexcept {
    while (!PendingOutput().empty()) {
      const auto out = PendingOutput();
      if (!transport.WriteAll(out, detail::Remaining(deadline))) break;
      if (!output_.Empty())
        output_.Consume(out.size());
      else if (protocol_ == Protocol::kHttp2 && http2_)
        http2_->ConsumeOutput(out.size());
      else
        break;
    }
  }

 public:
  explicit HttpServer(HttpService service = {}, ServerConfig config = {}) noexcept : config_(config), service_(service) {}
  HttpServer(const HttpServer&) = delete ("server owns response channels and sessions");
  HttpServer& operator=(const HttpServer&) = delete ("server owns response channels and sessions");
  ~HttpServer() noexcept { Close(); }
  void SetPeer(std::optional<cares::Endpoint> peer) noexcept { peer_ = peer; }
  [[nodiscard]] Result<void> SetNegotiatedAlpn(AlpnProtocol alpn) noexcept {
    if (protocol_ != Protocol::kSniff || !input_.Empty())
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    if (alpn == AlpnProtocol::kHttp11)
      protocol_ = Protocol::kHttp1;
    else if (alpn == AlpnProtocol::kHttp2) {
      if (!config_.allow_http2) return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2ProtocolError));
      conn_unreplenished_ = 0;
      http2_ = MakeHttp2();
      if (auto initiated = http2_->InitiateHandshake(); !initiated) return initiated;
      protocol_ = Protocol::kHttp2;
    }
    return {};
  }
  template <typename Adapter>
  void BindWebSocket(Adapter& adapter) noexcept {
    ws_handler_ = decltype(ws_handler_)::template Bind<&Adapter::DispatchWebSocket>(&adapter);
    if constexpr (requires {
                    { adapter.HasWebSocketRoute(std::string_view{}) } -> std::same_as<bool>;
                  })
      ws_route_ = decltype(ws_route_)::template Bind<&Adapter::HasWebSocketRoute>(&adapter);
  }
  [[nodiscard]] Result<void> Feed(std::span<const std::uint8_t> bytes) noexcept {
    if (protocol_ == Protocol::kClosed) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    if (protocol_ == Protocol::kWebSocket) {
      if (auto fed = websocket_->Feed(bytes); !fed) return fed;
      return PumpImpl({});
    }
    if (protocol_ == Protocol::kHttp2) return PumpImpl(bytes);
    if (auto appended = input_.Append(bytes); !appended) return appended;
    return PumpImpl({});
  }
  [[nodiscard]] Result<void> Pump() noexcept { return PumpImpl({}); }

 private:
  [[nodiscard]] Result<void> StepHttp2() noexcept {
    if (auto read = ReadHttp2(); !read) return read;
    return FlushReplies();
  }
  [[nodiscard]] Result<void> PumpImpl(std::span<const std::uint8_t> h2_incoming) noexcept {
    if (config_.max_inflight == 0 || config_.max_inflight > 64) return std::unexpected(Error::InvalidArgument());
    if (flags_.test<^^detail::ServerDriveSpec::driving>())
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    struct Guard {
      uarch::BitWord<detail::ServerDriveSpec>& flags;
      explicit Guard(uarch::BitWord<detail::ServerDriveSpec>& value) noexcept : flags(value) {
        flags = flags.with<^^detail::ServerDriveSpec::driving>(true);
      }
      // NOLINTNEXTLINE(modernize-use-equals-default) -- stock clang-tidy lacks <meta> for BitWord Guard reset.
      ~Guard() { flags = flags.with<^^detail::ServerDriveSpec::driving>(false); }
    } guard(flags_);
    if (protocol_ == Protocol::kSniff && !input_.Empty()) {
      const auto bytes = input_.ReadableSpan();
      const auto prefix = std::min(bytes.size(), kHttp2ClientPreface.size());
      const bool h2_prefix =
          std::equal(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(prefix), kHttp2ClientPreface.begin());
      if (h2_prefix && bytes.size() < kHttp2ClientPreface.size()) return {};
      if (h2_prefix) {
        if (!config_.allow_http2) return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2ProtocolError));
        conn_unreplenished_ = 0;
        http2_ = MakeHttp2();
        if (auto handshake = http2_->InitiateHandshake(); !handshake) return handshake;
        std::array<std::uint8_t, 65536> initial{};
        const std::size_t n = bytes.size();
        std::memcpy(initial.data(), bytes.data(), n);
        input_.Clear();
        protocol_ = Protocol::kHttp2;
        return detail::DrainHttp2Ingress(*http2_, input_, std::span<const std::uint8_t>(initial.data(), n),
                                         [this]() noexcept { return StepHttp2(); });
      }
      protocol_ = Protocol::kHttp1;
    }
    if (protocol_ == Protocol::kHttp2) {
      return detail::DrainHttp2Ingress(*http2_, input_, h2_incoming, [this]() noexcept { return StepHttp2(); });
    }
    if (protocol_ == Protocol::kHttp1) {
      if (auto read = ReadHttp1(); !read) return read;
    }
    if (protocol_ == Protocol::kWebSocket && ws_handler_) {
      for (;;) {
        auto message = websocket_->PollMessage();
        if (!message) return std::unexpected(message.error());
        if (!*message) break;
        if (auto handled = ws_handler_(websocket_path_, *websocket_, std::move(**message)); !handled) return handled;
      }
    }
    return FlushReplies();
  }

 public:
  [[nodiscard]] std::span<const std::uint8_t> PendingOutput() const noexcept {
    if (!output_.Empty()) return output_.ReadableSpan();
    if (protocol_ == Protocol::kHttp2) return http2_->PendingOutput();
    if (protocol_ == Protocol::kWebSocket) return websocket_->PendingOutput();
    return {};
  }
  [[nodiscard]] Result<void> ConsumeOutput(std::size_t bytes) noexcept {
    if (bytes > PendingOutput().size()) return std::unexpected(Error::InvalidArgument());
    if (!output_.Empty())
      output_.Consume(bytes);
    else if (protocol_ == Protocol::kHttp2)
      http2_->ConsumeOutput(bytes);
    else if (protocol_ == Protocol::kWebSocket) {
      if (auto consumed = websocket_->ConsumeOutput(bytes); !consumed) return consumed;
    }
    return Pump();
  }
  [[nodiscard]] WebSocketServerSession* WebSocket() noexcept { return websocket_ ? &*websocket_ : nullptr; }
  template <typename Transport>
  [[nodiscard]] Result<void> ServeOnce(Transport& transport, std::uint32_t timeout_ms = 2000) noexcept {
    const auto deadline = detail::After(timeout_ms);
    if (auto pumped = Pump(); !pumped) {
      DrainBrokenOutput(transport, deadline);
      return pumped;
    }
    bool wrote = false;
    while (!PendingOutput().empty()) {
      const auto bytes = PendingOutput();
      if (auto sent = transport.WriteAll(bytes, detail::Remaining(deadline)); !sent) return sent;
      if (auto consumed = ConsumeOutput(bytes.size()); !consumed) return consumed;
      wrote = true;
    }
    if (flags_.test<^^detail::ServerDriveSpec::close_when_flushed>())
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    if (wrote) return {};
    std::array<std::uint8_t, 32768> bytes{};
    auto read = transport.ReadSome(bytes, detail::Remaining(deadline));
    if (!read) return std::unexpected(read.error());
    if (*read == 0) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    if (auto fed = Feed(std::span(bytes).first(*read)); !fed) {
      DrainBrokenOutput(transport, deadline);
      return fed;
    }
    while (!PendingOutput().empty()) {
      const auto output = PendingOutput();
      if (auto sent = transport.WriteAll(output, detail::Remaining(deadline)); !sent) return sent;
      if (auto consumed = ConsumeOutput(output.size()); !consumed) return consumed;
    }
    if (flags_.test<^^detail::ServerDriveSpec::close_when_flushed>())
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    return {};
  }
  [[nodiscard]] Result<void> ServeHttp1Once(MemoryPipe& pipe) noexcept { return ServeOnce(pipe); }
  [[nodiscard]] Result<void> ServeHttp2Once(MemoryPipe& pipe) noexcept { return ServeOnce(pipe); }
  // The caller owns the listening descriptor and chooses the connection lifetime.
  [[nodiscard]] Result<void> ListenAndServeLoopback(LoopbackListener& listener, std::size_t steps,
                                                    const TlsServerConfig* tls = nullptr,
                                                    std::uint32_t timeout_ms = 2000) noexcept {
    auto proactor = uring::Proactor::Create();
    if (!proactor) return std::unexpected(Error::UringFailed(static_cast<std::int32_t>(std::to_underlying(proactor.error()))));
    Result<void> outcome{};
    {
      SecureStream stream(*proactor);
      if (auto accepted = stream.Accept(listener.RawFd(), timeout_ms); !accepted)
        outcome = accepted;
      else {
        SetPeer(stream.Peer());
        if (tls) {
          if (auto secured = stream.StartServer(*tls, timeout_ms); !secured)
            outcome = secured;
          else if (auto selected = SetNegotiatedAlpn(stream.Alpn()); !selected)
            outcome = selected;
        }
        if (outcome) {
          const auto deadline = detail::After(timeout_ms);
          for (std::size_t step = 0; step < steps; ++step) {
            if (auto served = ServeOnce(stream, detail::Remaining(deadline)); !served) {
              outcome = served;
              break;
            }
          }
        }
      }
      stream.Close();
      if (stream.ParkedCount() != 0) {
        detail::DrainParkedOnProactor(
            *proactor, nullptr, +[](const void* p) noexcept { return static_cast<const SecureStream*>(p)->ParkedCount(); },
            &stream);
      }
    }
    return outcome;
  }
  void Close() noexcept {
    protocol_ = Protocol::kClosed;
    responses_.Close();
    auto bits = occupied_;
    while (const auto slot = bits.pop_lowest_one()) Release(*slot);
    order_count_ = 0;
    conn_unreplenished_ = 0;
    input_.Clear();
    output_.Clear();
  }
};
}  // namespace nexora
