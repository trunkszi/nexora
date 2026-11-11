// expected-error: constant expression|InvalidHeaderValue
#include <nexora/http/headers.hpp>

constexpr auto kBadCase = nexora::ValidateHeaderValueLiteral("bad\x07value");
