#include <nexora/server/reflect_service.hpp>
#include <nexora/server/ws_server.hpp>
struct Service {
  unsigned calls{0};
  [[= nexora::HttpRoute{nexora::Method::kGet, "/health"}]] nexora::Result<void> Health(nexora::RequestContext&,
                                                                                       nexora::Request req,
                                                                                       nexora::Responder responder) noexcept {
    ++calls;
    const auto owned = std::move(req);
    static_cast<void>(owned);
    return responder.Respond(nexora::Response::Ok("healthy"));
  }
  [[= nexora::WebSocketRoute{"/events"}]] nexora::Result<void> Events(nexora::WebSocketServerSession& session,
                                                                      nexora::WebSocketMessage message) noexcept {
    ++calls;
    const auto owned = std::move(message);
    return session.Send(owned);
  }
};
int main() {
  Service service;
  nexora::ReflectService reflected(service);
  auto bound = reflected.Bind();
  if (!reflected.HasWebSocketRoute("/events") || reflected.HasWebSocketRoute("/missing")) return 5;
  nexora::ResponseChannel channel;
  auto responder = channel.Open();
  auto request = nexora::Request::Get("http://localhost/health?ready=1");
  nexora::RequestContext context;
  if (!request || !responder || !bound.Call(context, std::move(*request), std::move(*responder))) return 1;
  auto reply = channel.Poll();
  if (!reply || reply->response.status.AsU16() != 200) return 2;
  responder = channel.Open();
  request = nexora::Request::Get("http://localhost/missing");
  if (!request || !responder || !bound.Call(context, std::move(*request), std::move(*responder))) return 3;
  reply = channel.Poll();
  return reply && reply->response.status.AsU16() == 404 ? 0 : 4;
}
