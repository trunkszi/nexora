/** @file @brief In-memory HTTP/2 client/server pump for unit tests. */
#pragma once

#include <cstdint>
#include <cstdio>
#include <nexora/http2/connection.hpp>
#include <optional>
#include <utility>
#include <vector>

namespace nexora::test {

struct Link {
  Http2Connection client{Http2Role::kClient};
  Http2Connection server{Http2Role::kServer};
  std::vector<Http2Event> client_events{};
  std::vector<Http2Event> server_events{};

  static void Drain(Http2Connection& connection, std::vector<Http2Event>& out) {
    while (auto event = connection.PollEvent()) out.push_back(std::move(*event));
  }

  [[nodiscard]] int Pump() {
    for (int turn = 0; turn < 32; ++turn) {
      bool moved = false;
      const auto from_client = client.PendingOutput();
      if (!from_client.empty() || server.IsIngressPaused()) {
        const auto fed = server.FeedBytes(from_client);
        if (!fed.Ok()) {
          std::printf("server feed: %s\n", fed.ErrorValue().Message().data());
          return __LINE__;
        }
        if (fed.Consumed() > 0) {
          client.ConsumeOutput(fed.Consumed());
          moved = true;
        }
      }
      const auto from_server = server.PendingOutput();
      if (!from_server.empty() || client.IsIngressPaused()) {
        const auto fed = client.FeedBytes(from_server);
        if (!fed.Ok()) {
          std::printf("client feed: %s\n", fed.ErrorValue().Message().data());
          return __LINE__;
        }
        if (fed.Consumed() > 0) {
          server.ConsumeOutput(fed.Consumed());
          moved = true;
        }
      }
      const auto client_before = client_events.size();
      const auto server_before = server_events.size();
      Drain(client, client_events);
      Drain(server, server_events);
      if (client_events.size() != client_before || server_events.size() != server_before) {
        moved = true;
      }
      if (!moved && !client.IsIngressPaused() && !server.IsIngressPaused()) return 0;
    }
    return __LINE__;
  }

  [[nodiscard]] int Handshake() {
    if (!client.InitiateHandshake() || !server.InitiateHandshake()) return __LINE__;
    return Pump();
  }
};

[[nodiscard]] inline int Fail(int line) {
  std::printf("fail line %d\n", line);
  return line;
}

/** @brief Error code of the first GOAWAY (payload + 4) or RST_STREAM (payload + 0). */
[[nodiscard]] inline std::optional<std::uint32_t> PayloadCode(const Http2Connection& connection, Http2FrameType type) {
  const auto out = connection.PendingOutput();
  std::size_t cursor = 0;
  while (cursor + kHttp2FrameHeaderSize <= out.size()) {
    const auto len =
        (std::uint32_t{out[cursor]} << 16) | (std::uint32_t{out[cursor + 1]} << 8) | std::uint32_t{out[cursor + 2]};
    if (cursor + kHttp2FrameHeaderSize + len > out.size()) {
      return std::nullopt;
    }
    if (out[cursor + 3] == std::to_underlying(type) && len >= 4) {
      const auto at = cursor + kHttp2FrameHeaderSize + (type == Http2FrameType::kGoaway ? 4U : 0U);
      return nexora::ReadU32(out.subspan(at, 4));
    }
    cursor += kHttp2FrameHeaderSize + len;
  }
  return std::nullopt;
}

}  // namespace nexora::test
