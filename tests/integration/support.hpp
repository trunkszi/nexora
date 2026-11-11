#pragma once
#include <cstdio>
#include <cstdlib>
#include <nexora/client/http_client.hpp>
#include <nexora/server/http_server.hpp>
#include <source_location>
#include <vector>

namespace test {
[[noreturn]] inline void FailCheck(std::source_location location) noexcept {
  std::fprintf(stderr, "%s:%u: check failed\n", location.file_name(), location.line());
  std::abort();
}
inline void Check(bool ok, std::source_location location = std::source_location::current()) noexcept {
  if (!ok) FailCheck(location);
}
template <typename Source, typename Sink>
[[nodiscard]] bool Transfer(Source& source, Sink& sink, std::size_t fragment = 65536) noexcept {
  const auto output = source.PendingOutput();
  if (output.empty()) return false;
  const auto size = std::min(fragment, output.size());
  std::vector<std::uint8_t> copy(output.begin(), output.begin() + static_cast<std::ptrdiff_t>(size));
  Check(source.ConsumeOutput(size).has_value());
  auto fed = sink.Feed(copy);
  if (!fed)
    std::fprintf(stderr, "transfer feed error: %d %.*s, fragment=%zu\n", fed.error().code,
                 static_cast<int>(fed.error().Message().size()), fed.error().Message().data(), copy.size());
  Check(fed.has_value());
  return true;
}
inline void Drive(nexora::HttpClient& client, nexora::HttpServer& server, std::size_t fragment = 65536) noexcept {
  for (unsigned step = 0; step < 1024; ++step) {
    Check(server.Pump().has_value());
    const bool request = Transfer(client, server, fragment);
    const bool response = Transfer(server, client, fragment);
    if (!request && !response) return;
  }
  Check(false);
}
struct EchoService {
  unsigned calls{0};
  nexora::Result<void> Call(nexora::RequestContext&, nexora::Request request, nexora::Responder responder) noexcept {
    ++calls;
    auto response =
        nexora::Response::Ok(request.body.Empty() ? nexora::Bytes::CopyFromString("hello") : std::move(request.body));
    return responder.Respond(std::move(response));
  }
};
}  // namespace test
