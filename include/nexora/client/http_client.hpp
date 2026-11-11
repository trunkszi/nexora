#pragma once
#include <algorithm>
#include <array>
#include <cares/cares.hpp>
#include <chrono>
#include <cstdint>
#include <memory>
#include <nexora/client/config.hpp>
#include <nexora/client/detail/http_connection.hpp>
#include <nexora/client/detail/private_ring_route.hpp>
#include <nexora/client/detail/resolve.hpp>
#include <nexora/socket/memory_pipe.hpp>
#include <nexora/tls/secure_stream.hpp>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace nexora {
class HttpClient {
  unsigned publication_depth_{0};
  struct PublicationScope {
    HttpClient& client;
    explicit PublicationScope(HttpClient& owner) noexcept : client(owner) { ++client.publication_depth_; }
    ~PublicationScope() {
      if (--client.publication_depth_ == 0) client.PublishCallbacks();
    }
  };
  void CollectCallbacks() noexcept {
    auto callbacks = core_->TakeCallbacks();
    if (!callbacks) return;
    auto* tail = callbacks.get();
    while (tail->next) tail = tail->next.get();
    if (ready_callback_tail_)
      ready_callback_tail_->next = std::move(callbacks);
    else
      ready_callbacks_ = std::move(callbacks);
    ready_callback_tail_ = tail;
  }
  void PublishCallbacks() noexcept {
    CollectCallbacks();
    auto callbacks = std::move(ready_callbacks_);
    ready_callback_tail_ = nullptr;
    while (callbacks) {
      auto completion = std::move(callbacks);
      callbacks = std::move(completion->next);
      completion->callback(std::move(completion->response));
    }
  }
  std::unique_ptr<detail::HttpClientConnection::Completion> ready_callbacks_{};
  detail::HttpClientConnection::Completion* ready_callback_tail_{nullptr};
  ClientConfig config_{};
  uring::Proactor* proactor_{nullptr};
  cares::Resolver<>* resolver_{nullptr};
  CompletionRoute fallback_{};
  OriginPool<> pool_;
  detail::ParkedOperations parked_{};
  std::optional<SecureStream> stream_{};
  std::unique_ptr<detail::HttpClientConnection> core_{};
  std::optional<OriginKey> origin_{};
  std::uint64_t connection_id_{0};
  std::uint64_t next_id_{1};
  uarch::inplace_vector<RequestId, 64> admitted_{};
  std::optional<RequestId> exchange_{};
  std::optional<Result<Response>> exchange_result_{};
  detail::Deadline exchange_deadline_{};
  bool executing_{false};
  cares::Delegate<void(RequestId, const Http2Event&)> stream_hook_{};

  void Completed(RequestId id) noexcept {
    const auto found = std::find(admitted_.begin(), admitted_.end(), id);
    if (found == admitted_.end()) return;
    admitted_.erase(found);
    if (core_->IsHttp2())
      pool_.ReleaseHttp2Stream(*origin_, connection_id_);
    else
      pool_.MarkIdle(*origin_, connection_id_);
  }
  void ResetCore(bool http2 = false) noexcept {
    if (core_) CollectCallbacks();
    core_ = std::make_unique<detail::HttpClientConnection>(config_);
    core_->SetCompletionHook(cares::Delegate<void(RequestId)>::Bind<&HttpClient::Completed>(this));
    core_->SetStreamHook(stream_hook_);
    if (http2) {
      [[maybe_unused]] const auto upgraded = core_->UseHttp2();
    }
  }
  [[nodiscard]] Result<void> ConnectUri(const Uri& uri, detail::Deadline deadline) noexcept {
    if (!proactor_ || !resolver_) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    if (!detail::HasRoute(fallback_)) return std::unexpected(Error::InvalidArgument());
    if (uri.Scheme() != Scheme::kHttp && uri.Scheme() != Scheme::kHttps) return std::unexpected(Error::InvalidArgument());
    const auto key = OriginKey::FromUri(uri);
    for (const auto expired : pool_.Expired(std::chrono::steady_clock::now())) {
      if (expired == connection_id_) CloseConnection();
    }
    if (origin_ == key && stream_ && stream_->IsOpen() && core_->Reusable()) return {};
    if (core_->ActiveCount() != 0) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kPoolExhausted));
    CloseConnection();
    if (uri.IsTls() && !config_.enable_tls) return std::unexpected(Error::InvalidArgument());
    auto endpoints =
        detail::ResolveEndpoints(*proactor_, *resolver_, uri.Authority(), uri.EffectivePort(), deadline, fallback_);
    if (!endpoints) return std::unexpected(endpoints.error());
    if (!pool_.SetResolvedEndpoints(key, *endpoints)) return std::unexpected(Error::InvalidArgument());
    stream_.emplace(*proactor_, resolver_, kDefaultSocketIoSubsystemId, fallback_, &parked_);
    std::optional<Error> failure;
    for (std::size_t attempt = 0; attempt < endpoints->size(); ++attempt) {
      auto endpoint = pool_.SelectEndpoint(key, detail::SteadyNowNs());
      if (!endpoint) break;
      const auto remaining = std::min(config_.connect_timeout_ms, detail::Remaining(deadline));
      if (remaining == 0) return std::unexpected(Error::Timeout());
      auto connected = stream_->Connect(*endpoint, remaining);
      if (connected) {
        pool_.MarkEndpointSuccess(key, *endpoint);
        failure.reset();
        break;
      }
      failure = connected.error();
      pool_.MarkEndpointFailure(key, *endpoint, detail::SteadyNowNs());
    }
    if (!stream_->IsOpen())
      return std::unexpected(failure.value_or(Error::FromRuntime(RuntimeErrorCode::kAllEndpointsUnhealthy)));
    bool http2 = config_.http2_prior_knowledge;
    if (uri.IsTls()) {
      auto defaults = TlsClientConfig::CreateDefault();
      if (!config_.tls_config && !defaults) return std::unexpected(defaults.error());
      if (!config_.tls_config && !config_.prefer_http2) {
        constexpr std::array protocols{AlpnProtocol::kHttp11};
        if (auto set = defaults->SetAlpn(protocols); !set) return set;
      }
      const auto& tls = config_.tls_config ? *config_.tls_config : *defaults;
      const auto name = config_.tls_server_name.empty() ? uri.Host() : std::string_view(config_.tls_server_name);
      auto secured = stream_->StartClient(tls, name, detail::Remaining(deadline));
      if (!secured) {
        stream_->Close();
        return secured;
      }
      http2 = stream_->Alpn() == AlpnProtocol::kHttp2;
    }
    ResetCore(http2);
    origin_ = key;
    if (connection_id_ == UINT64_MAX) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kPoolExhausted));
    ++connection_id_;
    if (!pool_.RegisterConnection(
            key, PooledConnection{.connection_id = connection_id_, .version = http2 ? Version::kHttp2 : Version::kHttp11})) {
      CloseConnection();
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kPoolExhausted));
    }
    return {};
  }
  [[nodiscard]] Result<RequestId> SubmitWithPolicy(Request request, ResponseCallback callback, detail::Deadline deadline,
                                                   bool internal = false) noexcept {
    if (core_->ActiveCount() >= 64 || next_id_ == UINT64_MAX)
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kPoolExhausted));
    if (stream_) {
      if (origin_ != OriginKey::FromUri(request.uri) || !core_->Reusable())
        return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
      const auto acquired = core_->IsHttp2() ? pool_.AcquireHttp2Stream(*origin_) : pool_.AcquireHttp1(*origin_);
      if (!acquired) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kPoolExhausted));
    }
    const RequestId id{next_id_++};
    if (stream_) admitted_.push_back(id);
    auto submitted = core_->Submit(id, std::move(request), std::move(callback), deadline, internal);
    if (!submitted) {
      Completed(id);
      return std::unexpected(submitted.error());
    }
    return id;
  }
  [[nodiscard]] Result<void> BeginExchange(const Request& request, detail::Deadline deadline) noexcept {
    if (exchange_) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    exchange_result_.reset();
    auto id = SubmitWithPolicy(request, ResponseCallback([this](Result<Response> response) noexcept {
                                 exchange_result_.emplace(std::move(response));
                               }),
                               deadline, true);
    if (!id) return std::unexpected(id.error());
    exchange_ = *id;
    exchange_deadline_ = deadline;
    return {};
  }
  [[nodiscard]] Result<Response> TakeExchange() noexcept {
    exchange_.reset();
    auto result = std::move(*exchange_result_);
    exchange_result_.reset();
    return result;
  }
  [[nodiscard]] Result<Response> ExchangePipe(const Request& request, MemoryPipe& pipe, bool http2) noexcept {
    if (stream_) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    if (!exchange_) {
      if (core_->IsHttp2() != http2) {
        if (core_->ActiveCount() != 0) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
        ResetCore(http2);
      }
      if (auto began = BeginExchange(request, detail::After(config_.default_timeout_ms)); !began)
        return std::unexpected(began.error());
    }
    if (exchange_result_) return TakeExchange();
    auto driven = DriveOnce(pipe, detail::Remaining(exchange_deadline_));
    if (!driven && driven.error() != Error::Incomplete()) {
      static_cast<void>(core_->Cancel(*exchange_, driven.error()));
      exchange_.reset();
      exchange_result_.reset();
      return std::unexpected(driven.error());
    }
    if (exchange_result_) return TakeExchange();
    return std::unexpected(Error::Incomplete());
  }

 public:
  explicit HttpClient(ClientConfig config = {}) noexcept : config_(std::move(config)), pool_(config_.pool) { ResetCore(); }
  HttpClient(uring::Proactor& proactor, cares::Resolver<>& resolver, ClientConfig config, CompletionRoute fallback) noexcept
      : config_(std::move(config)), proactor_(&proactor), resolver_(&resolver), fallback_(fallback), pool_(config_.pool) {
    ResetCore();
  }
  template <std::size_t N>
  HttpClient(uring::Proactor& proactor, cares::Resolver<>& resolver, CompletionRoutes<N>& routes,
             ClientConfig config = {}) noexcept
      : HttpClient(proactor, resolver, std::move(config), CompletionRoute::Bind(routes)) {}
  HttpClient(const HttpClient&) = delete ("client owns its transport and pending callbacks");
  HttpClient& operator=(const HttpClient&) = delete ("client owns its transport and pending callbacks");
  ~HttpClient() noexcept { CloseConnection(); }
  [[nodiscard]] bool IsHttp2() const noexcept { return core_->IsHttp2(); }
  [[nodiscard]] std::size_t ActiveCount() const noexcept { return core_->ActiveCount(); }
  [[nodiscard]] std::size_t ParkedCount() const noexcept { return parked_.Count(); }
  [[nodiscard]] const OriginPool<>& Pool() const noexcept { return pool_; }
  [[nodiscard]] Result<void> UseHttp2() noexcept { return core_->UseHttp2(); }
  void SetStreamHook(cares::Delegate<void(RequestId, const Http2Event&)> hook) noexcept {
    stream_hook_ = hook;
    core_->SetStreamHook(hook);
  }
  [[nodiscard]] Result<RequestId> Submit(Request request, ResponseCallback callback, detail::Deadline deadline) noexcept {
    return SubmitWithPolicy(std::move(request), std::move(callback), deadline);
  }
  [[nodiscard]] Result<RequestId> Submit(Request request, ResponseCallback callback) noexcept {
    return Submit(std::move(request), std::move(callback), detail::After(config_.default_timeout_ms));
  }
  [[nodiscard]] Result<void> Feed(std::span<const std::uint8_t> bytes) noexcept {
    PublicationScope publish(*this);
    return core_->Feed(bytes);
  }
  [[nodiscard]] auto PendingOutput() const noexcept { return core_->PendingOutput(); }
  [[nodiscard]] Result<void> ConsumeOutput(std::size_t count) noexcept {
    PublicationScope publish(*this);
    return core_->ConsumeOutput(count);
  }
  [[nodiscard]] bool Cancel(RequestId id) noexcept {
    PublicationScope publish(*this);
    const bool canceled = core_->Cancel(id);
    if (canceled && stream_ && !core_->IsHttp2()) stream_->Close();
    return canceled;
  }
  void Tick() noexcept {
    PublicationScope publish(*this);
    core_->Tick();
    if (stream_ && !core_->IsHttp2() && !core_->Reusable()) stream_->Close();
  }
  template <typename Transport>
  [[nodiscard]] Result<void> DriveOnce(Transport& transport, std::uint32_t timeout_ms = 2000) noexcept {
    PublicationScope publish(*this);
    core_->Tick();
    if (timeout_ms == 0) return {};
    auto deadline = detail::After(timeout_ms);
    if (const auto request_deadline = core_->NextDeadline(); request_deadline && *request_deadline < deadline)
      deadline = *request_deadline;
    while (!core_->PendingOutput().empty()) {
      const auto output = core_->PendingOutput();
      if (auto wrote = transport.WriteAll(output, detail::Remaining(deadline)); !wrote) return wrote;
      if (auto consumed = core_->ConsumeOutput(output.size()); !consumed) return consumed;
    }
    if (core_->ActiveCount() == 0) return {};
    std::array<std::uint8_t, 32768> bytes{};
    auto read = transport.ReadSome(bytes, detail::Remaining(deadline));
    if (!read) {
      if (read.error() == Error::Timeout()) {
        core_->Tick();
        return {};
      }
      return std::unexpected(read.error());
    }
    if (*read == 0) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    auto fed = core_->Feed(std::span(bytes).first(*read));
    if (!fed) {
      while (!core_->PendingOutput().empty()) {
        const auto output = core_->PendingOutput();
        if (!transport.WriteAll(output, detail::Remaining(deadline))) break;
        if (!core_->ConsumeOutput(output.size())) break;
      }
    }
    return fed;
  }
  [[nodiscard]] Result<void> DriveOnce(std::uint32_t timeout_ms = 2000) noexcept {
    PublicationScope publish(*this);
    if (!stream_) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    auto drove = DriveOnce(*stream_, timeout_ms);
    if (!drove) {
      core_->CancelAll(drove.error());
      stream_->Close();
    } else if (!core_->IsHttp2() && !core_->Reusable())
      stream_->Close();
    return drove;
  }
  [[nodiscard]] Result<void> ResolveAndConnect(std::string_view host_port, std::uint16_t default_port,
                                               cares::Resolver<>& resolver, std::uint32_t timeout_ms) noexcept {
    if (!proactor_) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    resolver_ = &resolver;
    auto parsed = cares::ParseEndpoint(host_port, default_port);
    if (!parsed) return std::unexpected(Error::InvalidArgument());
    const bool tls = parsed->scheme == cares::EndpointScheme::Https || parsed->scheme == cares::EndpointScheme::Wss ||
                     parsed->scheme == cares::EndpointScheme::Grpcs;
    std::string address = tls ? "https://" : "http://";
    if (parsed->is_ipv6_bracketed) address.append("[");
    address.append(parsed->host);
    if (parsed->is_ipv6_bracketed) address.append("]");
    address.append(":" + std::to_string(parsed->port));
    auto uri = Uri::Parse(address);
    if (!uri) return std::unexpected(uri.error());
    return ConnectUri(*uri, detail::After(timeout_ms));
  }
  [[nodiscard]] Result<void> Connect(const Uri& uri, std::uint32_t timeout_ms = 2000) noexcept {
    return ConnectUri(uri, detail::After(timeout_ms));
  }
  [[nodiscard]] Result<Response> ExchangeOverPipe(const Request& request, MemoryPipe& pipe) noexcept {
    PublicationScope publish(*this);
    return ExchangePipe(request, pipe, false);
  }
  [[nodiscard]] Result<Response> ExchangeH2OverPipe(const Request& request, MemoryPipe& pipe) noexcept {
    PublicationScope publish(*this);
    return ExchangePipe(request, pipe, true);
  }
  [[nodiscard]] Result<Response> Execute(const Request& original, std::uint32_t timeout_ms = 2000) noexcept {
    PublicationScope publish(*this);
    if (executing_ || exchange_) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
    if (!proactor_) {
      const auto deadline = detail::After(timeout_ms);
      auto proactor = uring::Proactor::Create();
      if (!proactor)
        return std::unexpected(Error::UringFailed(static_cast<std::int32_t>(std::to_underlying(proactor.error()))));
      auto resolver = cares::Resolver<>::FromSystem(*proactor);
      if (!resolver) return std::unexpected(Error::DnsFailed(resolver.error().raw_code));
      std::optional<Result<Response>> response{};
      {
        HttpClient client(*proactor, *resolver, config_, detail::PrivateRingRoute());
        response.emplace(client.Execute(original, detail::Remaining(deadline)));
        [[maybe_unused]] const auto stopped = client.Shutdown(detail::Remaining(deadline));
        client.CloseConnection();
        if (client.ParkedCount() != 0) {
          detail::DrainParkedOnProactor(
              *proactor, &*resolver, +[](const void* p) noexcept { return static_cast<const HttpClient*>(p)->ParkedCount(); },
              &client);
        }
      }
      return std::move(*response);
    }
    struct Guard {
      bool& flag;
      explicit Guard(bool& value) noexcept : flag(value) { flag = true; }
      ~Guard() { flag = false; }
    } guard(executing_);
    const auto deadline = detail::After(timeout_ms);
    Request request = original;
    for (std::uint32_t redirects = 0;; ++redirects) {
      if (detail::Remaining(deadline) == 0) return std::unexpected(Error::Timeout());
      if (auto connected = ConnectUri(request.uri, deadline); !connected) return std::unexpected(connected.error());
      if (auto began = BeginExchange(request, deadline); !began) return std::unexpected(began.error());
      while (!exchange_result_) {
        if (auto drove = DriveOnce(detail::Remaining(deadline)); !drove) {
          exchange_.reset();
          exchange_result_.reset();
          return std::unexpected(drove.error());
        }
      }
      auto response = TakeExchange();
      if (!response) return response;
      const auto status = response->status.AsU16();
      const bool redirect = status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
      const auto location = response->headers.Get("location");
      if (!config_.follow_redirects || !redirect || !location) return response;
      if (redirects >= config_.max_redirects) return std::unexpected(Error::InvalidArgument());
      auto uri = request.uri.ResolveRedirect(*location);
      if (!uri) return std::unexpected(uri.error());
      if (request.uri.IsTls() && !uri->IsTls()) return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
      if (OriginKey::FromUri(request.uri) != OriginKey::FromUri(*uri)) {
        static_cast<void>(request.headers.Remove("authorization"));
        static_cast<void>(request.headers.Remove("cookie"));
        static_cast<void>(request.headers.Remove("proxy-authorization"));
      }
      if (status == 303 || ((status == 301 || status == 302) && request.method == Method::kPost)) {
        request.method = Method::kGet;
        request.body = Bytes{};
        request.trailers = {};
        static_cast<void>(request.headers.Remove("content-length"));
        static_cast<void>(request.headers.Remove("transfer-encoding"));
      }
      static_cast<void>(request.headers.Remove("host"));
      request.uri = std::move(*uri);
    }
  }
  [[nodiscard]] Result<void> Shutdown(std::uint32_t timeout_ms = 2000) noexcept {
    PublicationScope publish(*this);
    Result<void> notified;
    if (stream_) notified = stream_->SendCloseNotify(timeout_ms);
    CloseConnection();
    return notified;
  }
  void CloseConnection() noexcept {
    PublicationScope publish(*this);
    if (core_) core_->CancelAll();
    if (stream_) stream_->Close();
    stream_.reset();
    pool_.RemoveConnection(connection_id_);
    origin_.reset();
  }
};
}  // namespace nexora
