#include <array>
#include <cstdlib>
#include <nexora/http/uri.hpp>
#include <string>
#include <string_view>
#include <utility>

namespace {

void Check(bool condition) noexcept {
  if (!condition) {
    std::abort();
  }
}

void TestUriParsingAndNormalization() noexcept {
  auto uri_res = nexora::Uri::Parse("HtTpS://EXAMPLE.test:8443/path/to?x=1?y=2#ignored");
  Check(uri_res.has_value());
  const nexora::Uri& uri = *uri_res;
  Check(uri.Scheme() == nexora::Scheme::kHttps);
  Check(uri.Host() == "example.test");
  Check(uri.Port() == 8443);
  Check(uri.EffectivePort() == 8443);
  Check(uri.Authority() == "example.test:8443");
  Check(uri.Path() == "/path/to");
  Check(uri.Query().has_value() && *uri.Query() == "x=1?y=2");
  Check(uri.PathAndQuery() == "/path/to?x=1?y=2");
  Check(uri.AsStr() == "https://example.test:8443/path/to?x=1?y=2");
  Check(uri.IsTls());
  Check(!uri.IsWebSocket());

  auto max_port = nexora::Uri::Parse("http://example.test:65535/ok");
  Check(max_port.has_value() && max_port->Port() == 65535);

  struct Case {
    std::string_view raw;
    nexora::Scheme scheme;
    std::uint16_t port;
    bool tls;
    bool ws;
  };
  constexpr std::array<Case, 4> defaults{{
      {"http://example.test", nexora::Scheme::kHttp, 80, false, false},
      {"https://example.test?x", nexora::Scheme::kHttps, 443, true, false},
      {"ws://example.test", nexora::Scheme::kWs, 80, false, true},
      {"wss://example.test", nexora::Scheme::kWss, 443, true, true},
  }};
  for (const auto& c : defaults) {
    auto parsed = nexora::Uri::Parse(c.raw);
    Check(parsed.has_value());
    Check(parsed->Scheme() == c.scheme);
    Check(parsed->Port() == c.port);
    Check(parsed->Path() == "/");
    Check(parsed->IsTls() == c.tls);
    Check(parsed->IsWebSocket() == c.ws);
  }

  auto ipv6 = nexora::Uri::Parse("https://[2001:DB8::1]:443/a");
  Check(ipv6.has_value());
  Check(ipv6->Host() == "2001:db8::1");
  Check(ipv6->Scheme() == nexora::Scheme::kHttps);
  Check(ipv6->Port() == 443);
  Check(ipv6->Authority() == "[2001:db8::1]:443");
  Check(ipv6->PathAndQuery() == "/a");

  auto ipv6_default = nexora::Uri::Parse("http://[::1]");
  Check(ipv6_default.has_value());
  Check(ipv6_default->Authority() == "[::1]");
  Check(ipv6_default->Port() == 80);
}

void TestRedirectResolution() noexcept {
  auto base_res = nexora::Uri::Parse("http://example.test/a/b/c?old=1");
  Check(base_res.has_value());
  const nexora::Uri& base = *base_res;

  constexpr std::array<std::pair<std::string_view, std::string_view>, 17> redirects{{
      {"../d?new=2", "http://example.test/a/d?new=2"},
      {"./d", "http://example.test/a/b/d"},
      {"/d/./e/../", "http://example.test/d/"},
      {"/a/b/.", "http://example.test/a/b/"},
      {"/a/b/..", "http://example.test/a/"},
      {"../../../d", "http://example.test/d"},
      {"?new=2", "http://example.test/a/b/c?new=2"},
      {"#part", "http://example.test/a/b/c?old=1"},
      {"", "http://example.test/a/b/c?old=1"},
      {"//OTHER.test:81/x", "http://other.test:81/x"},
      {"https://other.test/x/../y#part", "https://other.test/y"},
      {"%2e%2e/d", "http://example.test/a/b/%2e%2e/d"},
      {"g//h/../i", "http://example.test/a/b/g//i"},
      {"/login?next=https://example.com", "http://example.test/login?next=https://example.com"},
      {"?u=http://x", "http://example.test/a/b/c?u=http://x"},
      {"../a?u=http://b", "http://example.test/a/a?u=http://b"},
      {"#a://b", "http://example.test/a/b/c?old=1"},
  }};

  for (const auto& [reference, expected] : redirects) {
    auto resolved = base.ResolveRedirect(reference);
    Check(resolved.has_value());
    Check(resolved->AsStr() == expected);
  }

  auto https_base = nexora::Uri::Parse("https://example.test/dir/page");
  Check(https_base.has_value());
  auto https_rel = https_base->ResolveRedirect("//cdn.example.test/app.js?ref=http://old");
  Check(https_rel.has_value());
  Check(https_rel->AsStr() == "https://cdn.example.test/app.js?ref=http://old");

  // Long URI (> 512 bytes, 1200 bytes total) parse and redirect resolution.
  const std::string long_query(1150, 'q');
  const std::string long_url = "https://api.example.test/v1/resource/items?" + long_query;
  Check(long_url.size() > 1190 && long_url.size() <= nexora::kMaxUriLength);
  auto long_parsed = nexora::Uri::Parse(long_url);
  Check(long_parsed.has_value());
  Check(long_parsed->AsStr() == long_url);
  Check(long_parsed->Query().has_value() && *long_parsed->Query() == long_query);

  const std::string long_rel = "/v2/redirected?" + long_query;
  auto long_resolved = https_base->ResolveRedirect(long_rel);
  Check(long_resolved.has_value());
  Check(long_resolved->Path() == "/v2/redirected");
  Check(long_resolved->Query().has_value() && *long_resolved->Query() == long_query);
}

void TestMalformedUriRejection() noexcept {
  constexpr std::array<std::string_view, 22> invalid_uris{{
      "",
      "/path",
      "ftp://example.test/a",
      "http:///path",
      "http://user@example.test/",
      "http://example.test:",
      "http://example.test:0",
      "http://example.test:65536",
      "http://example.test:-1",
      "http://example.test:+80",
      "http://example.test:80:90",
      "http://::1/",
      "http://[::1",
      "http://[]/",
      "http://[:.:]/",
      "http://[example.test]/",
      "http://[::1]junk/",
      "http://[::1]:80junk/",
      "http://exa mple.test/",
      "http://example.test/\r\nInjected:yes",
      "http://example.test/\\other",
      "http://example.test/%GG",
  }};

  for (std::string_view raw : invalid_uris) {
    auto res = nexora::Uri::Parse(raw);
    Check(!res.has_value());
    Check(res.error().domain == nexora::ErrorDomain::kProto);
    Check(res.error().code == static_cast<std::int32_t>(std::to_underlying(nexora::ProtoErrorCode::kInvalidUri)));
  }
}

}  // namespace

static_assert(nexora::detail::IsValidIpv6Literal("::"));
static_assert(nexora::detail::IsValidIpv6Literal("::1"));
static_assert(nexora::detail::IsValidIpv6Literal("2001:db8::"));
static_assert(nexora::detail::IsValidIpv6Literal("2001:db8::1"));
static_assert(nexora::detail::IsValidIpv6Literal("2001:DB8::1"));
static_assert(nexora::detail::IsValidIpv6Literal("2001:db8::1.2.3.4"));
static_assert(nexora::detail::IsValidIpv6Literal("::ffff:192.0.2.1"));
static_assert(nexora::detail::IsValidIpv6Literal("::ffff:192.0.2.128"));
static_assert(nexora::detail::IsValidIpv6Literal("::192.0.2.1"));
static_assert(nexora::detail::IsValidIpv6Literal("1:2:3:4:5:6:7::"));
static_assert(nexora::detail::IsValidIpv6Literal("1:2:3:4:5:6:7:8"));
static_assert(nexora::detail::IsValidIpv6Literal("1:2:3:4:5:6:1.2.3.4"));
static_assert(nexora::detail::IsValidIpv6Literal("1:2:3:4:5::1.2.3.4"));
static_assert(!nexora::detail::IsValidIpv6Literal("2001:db8"));
static_assert(!nexora::detail::IsValidIpv6Literal(":::"));
static_assert(!nexora::detail::IsValidIpv6Literal(":::1"));
static_assert(!nexora::detail::IsValidIpv6Literal("1:::"));
static_assert(!nexora::detail::IsValidIpv6Literal("1::Z"));
static_assert(!nexora::detail::IsValidIpv6Literal("1::12345"));
static_assert(!nexora::detail::IsValidIpv6Literal("1::2::3"));
static_assert(!nexora::detail::IsValidIpv6Literal("1:2:3:4:5:6:7:8:9"));
static_assert(!nexora::detail::IsValidIpv6Literal("1:2:3:4:5:6:7::8"));
static_assert(!nexora::detail::IsValidIpv6Literal("1:2:3:4:5:6:7:1.2.3.4"));
static_assert(!nexora::detail::IsValidIpv6Literal("1:2:3:4:5:6::1.2.3.4"));
static_assert(!nexora::detail::IsValidIpv6Literal("::001.2.3.4"));
static_assert(!nexora::detail::IsValidIpv6Literal("12345::"));
static_assert(!nexora::detail::IsValidIpv6Literal("1:2:3:4:5:6:7:8::"));
static_assert(!nexora::detail::IsValidIpv6Literal("fe80::1%eth0"));
static_assert(nexora::Uri::Parse("https://[2001:db8::1.2.3.4]:8443/v1").has_value());
static_assert(!nexora::Uri::Parse("https://[1::Z]/v1").has_value());

void TestIpv6Literals() noexcept {
  constexpr std::array<std::pair<std::string_view, std::string_view>, 4> accepted{{
      {"https://[2001:db8::1.2.3.4]/x", "2001:db8::1.2.3.4"},
      {"https://[::ffff:192.0.2.128]/x", "::ffff:192.0.2.128"},
      {"http://[::1]/x", "::1"},
      {"https://[2001:db8::]:8443/x", "2001:db8::"},
  }};
  for (const auto& [raw, expected_host] : accepted) {
    auto parsed = nexora::Uri::Parse(raw);
    Check(parsed.has_value());
    Check(parsed->Host() == expected_host);
    Check(parsed->PathAndQuery() == "/x");
  }

  constexpr std::array<std::string_view, 12> rejected{{
      "http://[2001:db8]/",
      "http://[:::1]/",
      "http://[1:::]/",
      "http://[1::Z]/",
      "http://[1::12345]/",
      "http://[1::2::3]/",
      "http://[1:2:3:4:5:6:7:8:9]/",
      "http://[1:2:3:4:5:6:7::8]/",
      "http://[1:2:3:4:5:6:7:1.2.3.4]/",
      "http://[::001.2.3.4]/",
      "http://[12345::]/",
      "http://[fe80::1%eth0]/",
  }};
  for (const auto raw : rejected) {
    Check(!nexora::Uri::Parse(raw).has_value());
  }
}

int main() {
  TestUriParsingAndNormalization();
  TestRedirectResolution();
  TestMalformedUriRejection();
  TestIpv6Literals();
  return 0;
}
