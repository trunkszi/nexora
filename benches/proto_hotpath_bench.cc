#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <nexora/http2/frame.hpp>
#include <nexora/http2/huffman.hpp>
#include <span>

namespace {

[[nodiscard]] std::int64_t NowNs() noexcept {
  timespec ts{};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<std::int64_t>(ts.tv_sec) * 1000000000LL + static_cast<std::int64_t>(ts.tv_nsec);
}

}  // namespace

int main() {
  constexpr int iters = 20000;
  std::array<std::uint8_t, 64> raw{};
  for (std::size_t i = 0; i < raw.size(); ++i) raw[i] = static_cast<std::uint8_t>('a' + (i % 26));
  std::array<std::uint8_t, 256> encoded{};
  std::array<std::uint8_t, nexora::kHttp2FrameHeaderSize> header{};
  const auto start = NowNs();
  std::size_t sink = 0;
  for (int i = 0; i < iters; ++i) {
    auto size = nexora::HuffmanEncode(raw, encoded);
    nexora::Http2FrameHeader fields{static_cast<std::uint32_t>(i & 0xffffff), nexora::Http2FrameType::kData, 0, 1};
    nexora::EncodeFrameHeader(fields, std::span<std::uint8_t, nexora::kHttp2FrameHeaderSize>{header});
    sink += *size + header[0];
  }
  const auto elapsed = NowNs() - start;
  std::printf("proto_hotpath iters=%d ns=%lld sink=%zu\n", iters, static_cast<long long>(elapsed), sink);
  return sink == 0 ? 1 : 0;
}
