#include "support.hpp"

struct Service : example::Echo {
  bool push_due{false};
  nexora::Result<void> DispatchWebSocket(std::string_view, nexora::WebSocketServerSession& session,
                                         nexora::WebSocketMessage message) noexcept {
    const auto owned = std::move(message);
    if (owned.kind == nexora::WebSocketMessageKind::kText) {
      push_due = true;
      return session.Send(owned);
    }
    return {};
  }
  nexora::Result<void> Maintenance(uring::Proactor& proactor, nexora::HttpServer& server) noexcept {
    if (!push_due) return {};
    push_due = false;
    example::Timer timer(proactor);
    if (auto waited = timer.Wait(10); !waited) return waited;
    return server.WebSocket()->Send(nexora::WebSocketMessage{.kind = nexora::WebSocketMessageKind::kText,
                                                             .payload = nexora::Bytes::CopyFromString("timer push")});
  }
};
int main() {
  Service service;
  return example::Loopback(service, [](std::uint16_t port) noexcept {
    nexora::WebSocketClient client;
    auto uri = nexora::Uri::Parse("ws://localhost:" + std::to_string(port) + "/echo");
    if (!uri || !client.Connect(*uri) || !client.SendText("hello")) return 20;
    auto echo = client.Receive();
    auto push = client.Receive();
    if (!echo || !push || echo->payload.AsStringView() != "hello" || push->payload.AsStringView() != "timer push") return 21;
    if (!client.Close()) return 22;
    auto closed = client.Receive();
    if (!closed || closed->kind != nexora::WebSocketMessageKind::kClose) return 23;
    std::puts("WebSocket echo and io_uring timer push");
    return 0;
  });
}
