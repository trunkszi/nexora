#pragma once

#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <nexora/nexora.hpp>

namespace example {
inline void Check(bool condition) noexcept {
  if (!condition) std::abort();
}
class Timer {
  uring::Proactor* proactor_;
  std::optional<uring::UserDataToken> token_{};
  std::int32_t result_{0};

 public:
  explicit Timer(uring::Proactor& proactor) noexcept : proactor_(&proactor) {}
  [[nodiscard]] static bool CanRoute(std::uint8_t id) noexcept { return id == 6; }
  [[nodiscard]] uring::Result<void> DispatchBatch(std::span<const uring::Delivery> deliveries) noexcept {
    for (const auto& delivery : deliveries) {
      if (token_ && delivery.completion.token == *token_) {
        result_ = delivery.completion.result;
        token_.reset();
      }
    }
    return {};
  }
  [[nodiscard]] nexora::Result<void> Wait(std::uint32_t millis) noexcept {
    const uring::abi::KernelTimespec time{millis / 1000, std::int64_t{millis % 1000} * 1000000};
    auto armed = proactor_->Arm(6, uring::ops::PrepareTimeout(uring::ops::UserAddress(&time), 0));
    if (!armed) return std::unexpected(nexora::Error::FromRuntime(nexora::RuntimeErrorCode::kUringError));
    token_ = *armed;
    while (token_) {
      auto waited = proactor_->WaitCompletions(1, std::chrono::milliseconds(millis + 100), *this);
      if (!waited && token_) static_cast<void>(proactor_->Cancel(*token_));
    }
    return result_ == -ETIME ? nexora::Result<void>{} : std::unexpected(nexora::Error::FromErrno(result_ < 0 ? -result_ : EIO));
  }
};

template <typename Service>
[[nodiscard]] int Serve(nexora::LoopbackListener& listener, Service& service, const nexora::TlsServerConfig* tls) noexcept {
  auto proactor = uring::Proactor::Create();
  if (!proactor) return 11;
  nexora::SecureStream transport(*proactor);
  if (!transport.Accept(listener.RawFd(), 4000)) return 12;
  if (tls && !transport.StartServer(*tls, 4000)) return 13;
  nexora::HttpServer server(nexora::HttpService::Bind<&Service::Call>(service));
  server.SetPeer(transport.Peer());
  if (tls && !server.SetNegotiatedAlpn(transport.Alpn())) return 17;
  if constexpr (requires { service.DispatchWebSocket(std::string_view{}, *server.WebSocket(), nexora::WebSocketMessage{}); })
    server.BindWebSocket(service);
  for (unsigned step = 0; step < 256; ++step) {
    if constexpr (requires { service.Maintenance(*proactor, server); }) {
      if (!service.Maintenance(*proactor, server)) return 14;
    }
    auto served = server.ServeOnce(transport, 4000);
    if (!served) {
      if (served.error() == nexora::Error::FromRuntime(nexora::RuntimeErrorCode::kConnectionClosed)) return 0;
      std::fprintf(stderr, "server: %.*s (%d)\n", static_cast<int>(served.error().Message().size()),
                   served.error().Message().data(), served.error().code);
      return 15;
    }
  }
  return 16;
}
template <typename Service, typename Client>
[[nodiscard]] int Loopback(Service& service, Client client, const nexora::TlsServerConfig* tls = nullptr) noexcept {
  auto listener = nexora::LoopbackListener::Bind();
  if (!listener) return 1;
  const auto child = ::fork();
  if (child < 0) return 2;
  if (child == 0) std::_Exit(Serve(*listener, service, tls));
  const int client_status = client(listener->Port());
  int child_status = 0;
  while (::waitpid(child, &child_status, 0) < 0)
    if (errno != EINTR) return 3;
  if (client_status != 0) return client_status;
  return WIFEXITED(child_status) ? WEXITSTATUS(child_status) : 4;
}
struct Echo {
  unsigned calls{0};
  nexora::Result<void> Call(nexora::RequestContext&, nexora::Request request, nexora::Responder responder) noexcept {
    ++calls;
    const auto owned = std::move(request);
    return responder.Respond(nexora::Response::Ok(owned.uri.PathAndQuery()));
  }
};
}  // namespace example
