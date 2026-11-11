// expected-error: static assertion failed.*duplicate or invalid service route
#include <nexora/server/reflect_service.hpp>
struct Service {
  [[= nexora::HttpRoute{nexora::Method::kGet, "/invalid?query"}]] nexora::Result<void> Route(nexora::RequestContext&,
                                                                                             nexora::Request,
                                                                                             nexora::Responder) noexcept {
    return {};
  }
};
Service service;
nexora::ReflectService<Service> invalid(service);
