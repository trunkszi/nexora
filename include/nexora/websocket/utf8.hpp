#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <uarch/detect/detect.hpp>
#include <uarch/primitives.hpp>

namespace nexora::ws_detail {

struct Utf8Cut {
  bool ok{false};
  bool incomplete{false};
  std::size_t valid_up_to{0};
};

struct Utf8State {
  std::array<std::uint8_t, 4> tail{};
  std::uint8_t len{0};
  bool ok{true};
};

struct Utf8AsciiKernel {
  template <typename Token>
  [[nodiscard]] static constexpr std::size_t operator()(Token, std::span<const std::uint8_t> data) noexcept {
    constexpr int width = Token::vector_bytes >= 64 ? 64 : Token::vector_bytes >= 32 ? 32 : 16;
    using Vec = uarch::vec<std::uint8_t, width>;
    const Vec high{static_cast<std::uint8_t>(0x80)};
    std::size_t index = 0;
    while (index + static_cast<std::size_t>(width) <= data.size()) {
      const auto chunk = uarch::simd::unchecked_load<Vec>(data.data() + index);
      const auto bits = chunk & high;
      const auto any = uarch::simd::reduce(
          bits, [](std::uint8_t lhs, std::uint8_t rhs) noexcept { return static_cast<std::uint8_t>(lhs | rhs); });
      if (any != 0) {
        return index;
      }
      index += static_cast<std::size_t>(width);
    }
    return index;
  }
};

[[nodiscard]] inline std::size_t AsciiPrefix(std::span<const std::uint8_t> data) noexcept {
  if consteval {
    return uarch::run<Utf8AsciiKernel{}>(uarch::Scalar::assume_supported(), data);
  } else {
    constexpr uarch::detect::DetectPolicy policy{
        .wide = uarch::detect::WidePolicy::Allow512,
        .unknown_pdep = uarch::detect::UnknownPdep::Conservative,
        .domain = uarch::detect::ExecutionDomainPolicy::CommonSubset,
    };
    static const auto tier = uarch::detect::detect(policy);
    if (tier.has_value()) {
      return uarch::dispatch_kernel<Utf8AsciiKernel{}>(*tier, data);
    }
    return uarch::run<Utf8AsciiKernel{}>(uarch::Scalar::assume_supported(), data);
  }
}

[[nodiscard]] inline Utf8Cut ClassifyUtf8(std::span<const std::uint8_t> data) noexcept {
  std::size_t i = AsciiPrefix(data);
  while (i < data.size()) {
    const auto lead = data[i];
    if (lead < 0x80U) {
      ++i;
      continue;
    }
    std::size_t width = 0;
    if (lead >= 0xc2U && lead <= 0xdfU) {
      width = 2;
    } else if (lead >= 0xe0U && lead <= 0xefU) {
      width = 3;
    } else if (lead >= 0xf0U && lead <= 0xf4U) {
      width = 4;
    } else {
      return Utf8Cut{false, false, i};
    }
    if (i + width > data.size()) {
      return Utf8Cut{false, true, i};
    }
    for (std::size_t j = 1; j < width; ++j) {
      if ((data[i + j] & 0xc0U) != 0x80U) {
        return Utf8Cut{false, false, i};
      }
    }
    const auto second = data[i + 1];
    const bool ranged = (width != 3 || ((lead != 0xe0U || second >= 0xa0U) && (lead != 0xedU || second <= 0x9fU))) &&
                        (width != 4 || ((lead != 0xf0U || second >= 0x90U) && (lead != 0xf4U || second <= 0x8fU)));
    if (!ranged) {
      return Utf8Cut{false, false, i};
    }
    i += width;
  }
  return Utf8Cut{true, false, data.size()};
}

[[nodiscard]] inline Utf8State FeedUtf8(Utf8State prev, std::span<const std::uint8_t> chunk, bool fin) noexcept {
  if (!prev.ok) {
    return Utf8State{.ok = false};
  }
  std::span<const std::uint8_t> rest = chunk;
  if (prev.len > 0) {
    const auto lead = prev.tail[0];
    std::size_t width = 0;
    if (lead >= 0xc2U && lead <= 0xdfU) {
      width = 2;
    } else if (lead >= 0xe0U && lead <= 0xefU) {
      width = 3;
    } else if (lead >= 0xf0U && lead <= 0xf4U) {
      width = 4;
    } else {
      return Utf8State{.ok = false};
    }
    if (width < prev.len) {
      return Utf8State{.ok = false};
    }
    const std::size_t need = width - prev.len;
    const std::size_t take = need < chunk.size() ? need : chunk.size();
    std::array<std::uint8_t, 4> combined{};
    std::memcpy(combined.data(), prev.tail.data(), prev.len);
    if (take > 0) {
      std::memcpy(combined.data() + prev.len, chunk.data(), take);
    }
    const auto cut = ClassifyUtf8(std::span<const std::uint8_t>(combined.data(), static_cast<std::size_t>(prev.len) + take));
    if (!cut.ok) {
      if (fin || !cut.incomplete) {
        return Utf8State{.ok = false};
      }
      Utf8State held;
      std::memcpy(held.tail.data(), combined.data(), static_cast<std::size_t>(prev.len) + take);
      held.len = static_cast<std::uint8_t>(prev.len + take);
      return held;
    }
    rest = chunk.subspan(take);
  }
  const auto cut = ClassifyUtf8(rest);
  if (cut.ok) {
    return Utf8State{};
  }
  if (!fin && cut.incomplete) {
    const auto suffix = rest.subspan(cut.valid_up_to);
    if (suffix.size() > 4) {
      return Utf8State{.ok = false};
    }
    Utf8State held;
    if (!suffix.empty()) {
      std::memcpy(held.tail.data(), suffix.data(), suffix.size());
    }
    held.len = static_cast<std::uint8_t>(suffix.size());
    return held;
  }
  return Utf8State{.ok = false};
}

}  // namespace nexora::ws_detail
