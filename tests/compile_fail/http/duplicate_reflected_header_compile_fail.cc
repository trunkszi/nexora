// expected-error: constant expression|DuplicateReflectedHeader
#include <nexora/http/reflect_decl.hpp>
#include <string>

struct BadReflectedStruct {
  [[= nexora::HeaderName("X-Custom")]] std::string first{};
  [[= nexora::HeaderName("x-custom")]] std::string second{};
};

constexpr bool kBadCase = nexora::detail::ValidateHeaderStructShape<BadReflectedStruct>();
