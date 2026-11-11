#pragma once
#include <array>
#include <concepts>
#include <cstddef>
#include <meta>
#include <nexora/server/service.hpp>
#include <nexora/websocket/codec.hpp>
#include <optional>
#include <string_view>
#include <utility>

namespace nexora {
class WebSocketServerSession;
struct RoutePath {
  std::array<char, 256> bytes{};
  std::size_t length{0};
  constexpr RoutePath() noexcept = default;
  template <std::size_t N>
  consteval RoutePath(const char (&text)[N]) noexcept : length(N - 1) {
    static_assert(N <= 256, "route path exceeds 255 bytes");
    for (std::size_t i = 0; i < N - 1; ++i) bytes[i] = text[i];
  }
  [[nodiscard]] constexpr std::string_view View() const noexcept { return {bytes.data(), length}; }
};
struct HttpRoute {
  Method method{Method::kGet};
  RoutePath path{};
};
struct WebSocketRoute {
  RoutePath path{};
};
namespace detail {
[[nodiscard]] consteval bool ValidRoutePath(const RoutePath& path) noexcept {
  if (path.length == 0 || path.length > path.bytes.size() || path.bytes[0] != '/') return false;
  for (std::size_t i = 0; i < path.length; ++i) {
    const auto byte = static_cast<unsigned char>(path.bytes[i]);
    if (byte <= 32 || byte == 127 || byte == '?' || byte == '#') return false;
  }
  return true;
}
template <typename Note, std::meta::info Entity>
[[nodiscard]] consteval std::optional<Note> RouteAnnotation() {
  std::optional<Note> result;
  template for (constexpr auto annotation : std::define_static_array(std::meta::annotations_of(Entity))) {
    constexpr auto value = std::meta::constant_of(annotation);
    if constexpr (std::meta::remove_cv(std::meta::type_of(value)) == ^^Note) result = std::meta::extract<Note>(value);
  }
  return result;
}

template <typename Service>
[[nodiscard]] consteval bool ValidServiceRoutes() {
  std::array<HttpRoute, 64> http{};
  std::array<WebSocketRoute, 64> websocket{};
  std::size_t http_count = 0;
  std::size_t ws_count = 0;
  template for (constexpr auto member :
                std::define_static_array(std::meta::members_of(^^Service, std::meta::access_context::current()))) {
    if constexpr (std::meta::is_function(member)) {
      if constexpr (constexpr auto route = RouteAnnotation<HttpRoute, member>(); route.has_value()) {
        if (!ValidRoutePath(route->path)) return false;
        if (http_count == http.size()) return false;
        for (std::size_t i = 0; i < http_count; ++i)
          if (http[i].method == route->method && http[i].path.View() == route->path.View()) return false;
        http[http_count++] = *route;
      }
      if constexpr (constexpr auto route = RouteAnnotation<WebSocketRoute, member>(); route.has_value()) {
        if (!ValidRoutePath(route->path)) return false;
        if (ws_count == websocket.size()) return false;
        for (std::size_t i = 0; i < ws_count; ++i)
          if (websocket[i].path.View() == route->path.View()) return false;
        websocket[ws_count++] = *route;
      }
    }
  }
  return true;
}
}  // namespace detail

template <typename Service>
class ReflectService {
  static_assert(detail::ValidServiceRoutes<Service>(), "duplicate or invalid service route");
  Service* service_;

 public:
  explicit ReflectService(Service& service) noexcept : service_(&service) {}
  /// @pre This adapter and its service outlive every bound HttpService invocation.
  [[nodiscard]] HttpService Bind() & noexcept { return HttpService::Bind<&ReflectService::Call>(*this); }
  HttpService Bind() && = delete ("retain the reflection adapter while the server uses its binding");
  // NOLINTNEXTLINE(performance-unnecessary-value-param) -- stock clang-tidy lacks template-for/<meta> for splice move.
  [[nodiscard]] Result<void> Call(RequestContext& context, Request request, Responder responder) noexcept {
    const auto target = request.uri.PathAndQuery();
    const auto path = target.substr(0, target.find('?'));
    template for (constexpr auto member :
                  std::define_static_array(std::meta::members_of(^^Service, std::meta::access_context::current()))) {
      if constexpr (std::meta::is_function(member)) {
        if constexpr (constexpr auto route = detail::RouteAnnotation<HttpRoute, member>(); route.has_value()) {
          static_assert(noexcept((*service_).[:member:](context, std::move(request), std::move(responder))));
          if (request.method == route->method && path == route->path.View())
            return (*service_).[:member:](context, std::move(request), std::move(responder));
        }
      }
    }
    return responder.Respond(Response::WithStatus(StatusCode{404}));
  }
  [[nodiscard]] bool HasWebSocketRoute(std::string_view path) const noexcept {
    template for (constexpr auto member :
                  std::define_static_array(std::meta::members_of(^^Service, std::meta::access_context::current()))) {
      if constexpr (std::meta::is_function(member)) {
        if constexpr (constexpr auto route = detail::RouteAnnotation<WebSocketRoute, member>(); route.has_value()) {
          if (path == route->path.View()) return true;
        }
      }
    }
    return false;
  }
  // Stock clang-tidy lacks template-for/<meta> for splice move.
  [[nodiscard]] Result<void> DispatchWebSocket(std::string_view path, WebSocketServerSession& session,
                                               // NOLINTNEXTLINE(performance-unnecessary-value-param)
                                               WebSocketMessage message) noexcept {
    template for (constexpr auto member :
                  std::define_static_array(std::meta::members_of(^^Service, std::meta::access_context::current()))) {
      if constexpr (std::meta::is_function(member)) {
        if constexpr (constexpr auto route = detail::RouteAnnotation<WebSocketRoute, member>(); route.has_value()) {
          static_assert(noexcept((*service_).[:member:](session, std::move(message))));
          if (path == route->path.View()) return (*service_).[:member:](session, std::move(message));
        }
      }
    }
    return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketHandshakeFailed));
  }
};
}  // namespace nexora
