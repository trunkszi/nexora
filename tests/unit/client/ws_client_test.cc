#include <cstdlib>
#include <nexora/client/ws_client.hpp>
#include <nexora/server/ws_server.hpp>

namespace {
void Check(bool condition) noexcept {
  if (!condition) std::abort();
}
}  // namespace
int main() {
  nexora::WebSocketClient client;
  nexora::WebSocketServerSession server;
  nexora::Http1ServerCodec<> http1;
  nexora::BytesMut<65536> input;
  nexora::BytesMut<65536> response;
  auto uri = nexora::Uri::Parse("ws://localhost/echo");
  Check(uri.has_value() && client.Start(*uri).has_value());
  Check(input.Append(client.PendingOutput()).has_value());
  Check(client.ConsumeOutput(client.PendingOutput().size()).has_value());
  auto request = http1.DecodeRequest(input.ReadableSpan());
  Check(request.has_value() && request->has_value());
  auto upgrade = server.AcceptUpgrade((**request).message);
  Check(upgrade.has_value());
  auto encoded = http1.EncodeResponse(*upgrade);
  Check(encoded.has_value() && response.Append(encoded->ReadableSpan()).has_value());
  Check(server
            .Send(nexora::WebSocketMessage{.kind = nexora::WebSocketMessageKind::kText,
                                           .payload = nexora::Bytes::CopyFromString("push")})
            .has_value());
  Check(response.Append(server.PendingOutput()).has_value());
  Check(server.ConsumeOutput(server.PendingOutput().size()).has_value());
  Check(client.Feed(response.ReadableSpan()).has_value() && client.IsOpen());
  auto message = client.PollMessage();
  Check(message.has_value() && message->has_value() && (**message).payload.AsStringView() == "push");
  Check(client.SendText("echo").has_value());
  Check(server.Feed(client.PendingOutput()).has_value());
  Check(client.ConsumeOutput(client.PendingOutput().size()).has_value());
  message = server.PollMessage();
  Check(message.has_value() && message->has_value() && (**message).payload.AsStringView() == "echo");
  Check(client.Close().has_value() && !client.IsOpen());
  Check(!client.SendText("late"));
  Check(server.Feed(client.PendingOutput()).has_value());
  Check(client.ConsumeOutput(client.PendingOutput().size()).has_value());
  Check(client.Feed(server.PendingOutput()).has_value());
  message = client.PollMessage();
  Check(message.has_value() && message->has_value() && (**message).kind == nexora::WebSocketMessageKind::kClose);
}
