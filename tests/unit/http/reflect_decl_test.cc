#include <cstdint>
#include <cstdlib>
#include <nexora/http/reflect_decl.hpp>
#include <optional>
#include <string>
#include <utility>

namespace {

void Check(bool condition) noexcept {
  if (!condition) {
    std::abort();
  }
}

struct TraceHeaders {
  [[= nexora::HeaderName("x-trace-id")]] std::string trace_id{};
  std::optional<std::string> x_span_id{};
  [[= nexora::HeaderName("x-required-opt", true)]] std::optional<std::uint64_t> required_seq{};
  [[= nexora::HeaderWithDefault("x-retry-limit", "3")]] std::uint16_t retry_limit{0};
  bool x_debug_enabled{false};
};

struct[[= nexora::Route(nexora::Method::kPost, "/v1/items/{category}/entry/{item_id}")]] CreateItemRequest;

struct CreateItemRequest {
  [[= nexora::kPathParam]] std::string category{};
  [[= nexora::kPathParam]] std::uint64_t item_id{0};
  [[= nexora::QueryField("filter name")]] std::optional<std::string> filter{};
  [[= nexora::QueryField()]] std::uint32_t limit{10};
  [[= nexora::HeaderFieldAttr("x-api-token")]] std::optional<std::string> token{};
  [[= nexora::kBodyParam]] std::string payload{};
};

static_assert(nexora::detail::ValidateRoutePlaceholders<CreateItemRequest>("/v1/items/{category}/entry/{item_id}"));
static_assert(!nexora::detail::ValidateRoutePlaceholders<CreateItemRequest>("/v1/items/{category}/entry/{unknown_id}"));
static_assert(!nexora::detail::ValidateRoutePlaceholders<CreateItemRequest>("/v1/items/{category}"));
static_assert(!nexora::detail::ValidateRoutePlaceholders<CreateItemRequest>("/v1/items/{category}/entry/{category}"));

void TestHeaderReflectionRoundTrip() noexcept {
  TraceHeaders input{
      .trace_id = "abc-123",
      .x_span_id = std::nullopt,
      .required_seq = 99ULL,
      .retry_limit = 5U,
      .x_debug_enabled = true,
  };

  auto encoded_res = nexora::ReflectToHeaders(input);
  Check(encoded_res.has_value());
  const auto& headers = *encoded_res;
  Check(headers.Get("x-trace-id") == "abc-123");
  Check(!headers.Contains("x-span-id"));
  Check(headers.Get("x-required-opt") == "99");
  Check(headers.Get("x-retry-limit") == "5");
  Check(headers.Get("x-debug-enabled") == "true");

  auto decoded_res = nexora::ReflectFromHeaders<TraceHeaders>(headers);
  Check(decoded_res.has_value());
  Check(decoded_res->trace_id == "abc-123");
  Check(!decoded_res->x_span_id.has_value());
  Check(decoded_res->required_seq == 99ULL);
  Check(decoded_res->retry_limit == 5U);
  Check(decoded_res->x_debug_enabled);

  // Test fallback default when x-retry-limit is omitted.
  nexora::Headers<> partial;
  Check(partial.Set("x-trace-id", "t-1").has_value());
  Check(partial.Set("x-required-opt", "7").has_value());
  Check(partial.Set("x-debug-enabled", "false").has_value());
  auto with_default = nexora::ReflectFromHeaders<TraceHeaders>(partial);
  Check(with_default.has_value());
  Check(with_default->retry_limit == 3U);
  Check(!with_default->x_debug_enabled);

  // Missing required field must fail.
  nexora::Headers<> missing_req;
  Check(missing_req.Set("x-trace-id", "t-1").has_value());
  Check(!nexora::ReflectFromHeaders<TraceHeaders>(missing_req).has_value());

  // Malformed integer field must fail.
  nexora::Headers<> bad_int = partial;
  Check(bad_int.Set("x-required-opt", "not-a-number").has_value());
  Check(!nexora::ReflectFromHeaders<TraceHeaders>(bad_int).has_value());
}

void TestRestRequestReflection() noexcept {
  CreateItemRequest create_req{
      .category = "metrics/cpu load",
      .item_id = 42ULL,
      .filter = "host=node 1",
      .limit = 100U,
      .token = "secret-token",
      .payload = "{\"ts\":1}",
  };

  const auto path_query = nexora::BuildRestPathAndQuery(create_req);
  Check(path_query.has_value());
  Check(*path_query == "/v1/items/metrics%2Fcpu%20load/entry/42?filter%20name=host%3Dnode%201&limit=100");

  auto http_req = nexora::BuildRestRequest(create_req, "https://api.example.test:8443/");
  Check(http_req.has_value());
  Check(http_req->method == nexora::Method::kPost);
  Check(http_req->uri.AsStr() ==
        "https://api.example.test:8443/v1/items/metrics%2Fcpu%20load/entry/42"
        "?filter%20name=host%3Dnode%201&limit=100");
  Check(http_req->headers.Get("x-api-token") == "secret-token");
  Check(http_req->body.AsStringView() == "{\"ts\":1}");

  // Omit optional query & header parameters.
  CreateItemRequest minimal{
      .category = "logs",
      .item_id = 7ULL,
      .filter = std::nullopt,
      .limit = 25U,
      .token = std::nullopt,
      .payload = "raw",
  };
  auto min_req = nexora::ReflectToRequest(minimal, "http://example.test");
  Check(min_req.has_value());
  Check(min_req->uri.PathAndQuery() == "/v1/items/logs/entry/7?limit=25");
  Check(!min_req->headers.Contains("x-api-token"));

  // Base URL with query or fragment must be rejected.
  Check(!nexora::BuildRestRequest(minimal, "http://example.test?bad=1").has_value());
  Check(!nexora::BuildRestRequest(minimal, "http://example.test#frag").has_value());

  // Oversize path parameter must return kBufferOverflow rather than silently truncating.
  CreateItemRequest oversize = minimal;
  oversize.category = std::string(2100, 'a');
  const auto over_pq = nexora::BuildRestPathAndQuery(oversize);
  Check(!over_pq.has_value());
  Check(over_pq.error().code == static_cast<std::int32_t>(std::to_underlying(nexora::ProtoErrorCode::kBufferOverflow)));
}

}  // namespace

int main() {
  TestHeaderReflectionRoundTrip();
  TestRestRequestReflection();
  return 0;
}
