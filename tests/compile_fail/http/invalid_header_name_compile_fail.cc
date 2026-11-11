// expected-error: constant expression|InvalidHeaderName
#include <nexora/http/headers.hpp>

constexpr auto kBadCase = nexora::ValidateHeaderNameLiteral("Invalid\r\nHeader");
