#include <nexora/client/ws_client.hpp>

#include "../integration/support.hpp"

int main() {
  nexora::HttpServer server;
  nexora::WebSocketClient client;
  auto uri = nexora::Uri::Parse("ws://localhost/echo");
  test::Check(uri.has_value() && client.Start(*uri).has_value());
  test::Check(test::Transfer(client, server, 65536));
  auto* websocket = server.WebSocket();
  test::Check(websocket != nullptr);
  test::Check(websocket
                  ->Send(nexora::WebSocketMessage{.kind = nexora::WebSocketMessageKind::kText,
                                                  .payload = nexora::Bytes::CopyFromString("push")})
                  .has_value());
  std::vector<std::uint8_t> coalesced;
  while (!server.PendingOutput().empty()) {
    const auto bytes = server.PendingOutput();
    coalesced.insert(coalesced.end(), bytes.begin(), bytes.end());
    test::Check(server.ConsumeOutput(bytes.size()).has_value());
  }
  test::Check(client.Feed(coalesced).has_value());
  test::Check(client.IsOpen());
  auto message = client.PollMessage();
  test::Check(message.has_value() && message->has_value() && (**message).payload.AsStringView() == "push");
  test::Check(client.SendText("echo").has_value());
  while (test::Transfer(client, server, 3)) {
  }
  auto incoming = websocket->PollMessage();
  test::Check(incoming.has_value() && incoming->has_value());
  test::Check(websocket->Send(**incoming).has_value());
  while (test::Transfer(server, client, 2)) {
  }
  message = client.PollMessage();
  test::Check(message.has_value() && message->has_value() && (**message).payload.AsStringView() == "echo");
  test::Check(client.Close().has_value());
  while (test::Transfer(client, server)) {
  }
  while (test::Transfer(server, client)) {
  }
}
