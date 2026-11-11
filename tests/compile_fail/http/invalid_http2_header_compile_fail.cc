// expected-error: constant expression|InvalidHttp2HeaderName
#include <nexora/http/headers.hpp>

constexpr auto kBadCase = nexora::ValidateHttp2HeaderNameLiteral("Upper-Case-Forbidden");
