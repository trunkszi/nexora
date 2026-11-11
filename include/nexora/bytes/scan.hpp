/** @file @brief SIMD/SWAR byte scanners, HTTP token validators, and ASCII case helpers. */
#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <uarch/uarch.hpp>
#include <utility>

namespace nexora::detail {

[[nodiscard]] inline uarch::Tier DetectScanTierOnce() noexcept {
  uarch::DetectPolicy policy{
      .wide = uarch::WidePolicy::Allow512,
      .unknown_pdep = uarch::UnknownPdep::Conservative,
      .domain = uarch::ExecutionDomainPolicy::CommonSubset,
  };
  if (auto detected = uarch::detect::detect(policy); detected.has_value()) {
    return *detected;
  }
  return uarch::Tier{uarch::Scalar{}};
}

[[nodiscard]] inline uarch::Tier ActiveScanTier() noexcept {
  static const uarch::Tier tier = DetectScanTierOnce();
  return tier;
}

[[nodiscard]] constexpr std::uint64_t LoadU64Le(const std::uint8_t* ptr) noexcept {
  if consteval {
    std::uint64_t word = 0;
    for (std::size_t i = 0uz; i < 8uz; ++i) {
      word |= static_cast<std::uint64_t>(ptr[i]) << (i * 8U);
    }
    return word;
  } else {
    std::uint64_t word = 0;
    std::memcpy(&word, ptr, sizeof(word));
    if constexpr (std::endian::native == std::endian::big) {
      word = std::byteswap(word);
    }
    return word;
  }
}

[[nodiscard]] constexpr std::uint64_t LoadU64Le(const char* ptr) noexcept {
  if consteval {
    std::uint64_t word = 0;
    for (std::size_t i = 0uz; i < 8uz; ++i) {
      word |= static_cast<std::uint64_t>(static_cast<std::uint8_t>(ptr[i])) << (i * 8U);
    }
    return word;
  } else {
    std::uint64_t word = 0;
    std::memcpy(&word, ptr, sizeof(word));
    if constexpr (std::endian::native == std::endian::big) {
      word = std::byteswap(word);
    }
    return word;
  }
}

[[nodiscard]] constexpr std::uint64_t ZeroByteHighBits(std::uint64_t word) noexcept {
  constexpr std::uint64_t low_ones = 0x0101010101010101ULL;
  constexpr std::uint64_t high_ones = 0x8080808080808080ULL;
  return (word - low_ones) & (~word) & high_ones;
}

template <class Vec>
[[nodiscard]] constexpr Vec LoadVec(const std::uint8_t* ptr) noexcept {
  std::array<std::uint8_t, static_cast<std::size_t>(Vec::size())> lanes{};
  if consteval {
    for (int i = 0; i < Vec::size(); ++i) {
      lanes[static_cast<std::size_t>(i)] = ptr[static_cast<std::size_t>(i)];
    }
  } else {
    std::memcpy(lanes.data(), ptr, sizeof(lanes));
  }
  return Vec::from_array(lanes);
}

template <class Vec>
[[nodiscard]] constexpr Vec LoadVec(const char* ptr) noexcept {
  std::array<std::uint8_t, static_cast<std::size_t>(Vec::size())> lanes{};
  if consteval {
    for (int i = 0; i < Vec::size(); ++i) {
      lanes[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(ptr[static_cast<std::size_t>(i)]);
    }
  } else {
    std::memcpy(lanes.data(), ptr, sizeof(lanes));
  }
  return Vec::from_array(lanes);
}

struct FindByteKernel {
  template <uarch::Arch Token, typename View>
  [[nodiscard]] static constexpr std::optional<std::size_t> operator()(Token, View haystack, std::uint8_t needle) noexcept {
    using Vec = uarch::simd::native_vec<std::uint8_t, Token>;
    constexpr auto width = static_cast<std::size_t>(Vec::size());

    std::size_t offset = 0uz;
    if (haystack.size() >= width) {
      const Vec target{needle};
      while (offset + width <= haystack.size()) {
        const Vec chunk = LoadVec<Vec>(haystack.data() + offset);
        const auto matches = (chunk == target);
        if (const auto lane = uarch::simd::find_first_set(matches); lane.has_value()) {
          return offset + static_cast<std::size_t>(*lane);
        }
        offset += width;
      }
    }

    const std::uint64_t broadcast = 0x0101010101010101ULL * static_cast<std::uint64_t>(needle);
    while (offset + 8uz <= haystack.size()) {
      const std::uint64_t word = LoadU64Le(haystack.data() + offset);
      const std::uint64_t matches = ZeroByteHighBits(word ^ broadcast);
      if (matches != 0) {
        return offset + static_cast<std::size_t>(std::countr_zero(matches) >> 3U);
      }
      offset += 8uz;
    }

    while (offset < haystack.size()) {
      if (static_cast<std::uint8_t>(haystack[offset]) == needle) {
        return offset;
      }
      ++offset;
    }
    return std::nullopt;
  }
};

struct HeaderValueValidateKernel {
  template <uarch::Arch Token>
  [[nodiscard]] static constexpr bool operator()(Token, std::string_view value) noexcept {
    using Vec = uarch::simd::native_vec<std::uint8_t, Token>;
    constexpr auto width = static_cast<std::size_t>(Vec::size());

    std::size_t offset = 0uz;
    if (value.size() >= width) {
      const Vec min_printable{0x20U};
      const Vec max_printable{0x7EU};
      const Vec htab{0x09U};
      const Vec high_bit{0x80U};
      const Vec zero{0x00U};

      while (offset + width <= value.size()) {
        const Vec chunk = LoadVec<Vec>(value.data() + offset);
        const auto is_printable = (chunk >= min_printable) & (chunk <= max_printable);
        const auto is_obs_text = ((chunk & high_bit) != zero);
        const auto is_htab = (chunk == htab);
        const auto valid = is_printable | is_obs_text | is_htab;
        if (!uarch::simd::all_of(valid)) {
          return false;
        }
        offset += width;
      }
    }

    while (offset < value.size()) {
      const auto b = static_cast<std::uint8_t>(value[offset]);
      const bool ok = (b == 0x09U) || (b >= 0x20U && b <= 0x7EU) || (b >= 0x80U);
      if (!ok) {
        return false;
      }
      ++offset;
    }
    return true;
  }
};

struct AsciiLowerKernel {
  template <uarch::Arch Token>
  static constexpr void operator()(Token, std::span<char> buf) noexcept {
    using Vec = uarch::simd::native_vec<std::uint8_t, Token>;
    constexpr auto width = static_cast<std::size_t>(Vec::size());

    std::size_t offset = 0uz;
    if (buf.size() >= width) {
      const Vec upper_a{static_cast<std::uint8_t>('A')};
      const Vec upper_z{static_cast<std::uint8_t>('Z')};
      const Vec case_bit{0x20U};
      const Vec zero{0x00U};

      while (offset + width <= buf.size()) {
        const Vec chunk = LoadVec<Vec>(buf.data() + offset);
        const auto is_upper = (chunk >= upper_a) & (chunk <= upper_z);
        const Vec delta = uarch::simd::select(is_upper, case_bit, zero);
        const auto lowered = (chunk | delta).to_array();
        if consteval {
          for (std::size_t i = 0uz; i < width; ++i) {
            buf[offset + i] = static_cast<char>(lowered[i]);
          }
        } else {
          std::memcpy(buf.data() + offset, lowered.data(), width);
        }
        offset += width;
      }
    }

    while (offset < buf.size()) {
      const auto c = static_cast<std::uint8_t>(buf[offset]);
      if (c >= static_cast<std::uint8_t>('A') && c <= static_cast<std::uint8_t>('Z')) {
        buf[offset] = static_cast<char>(c | 0x20U);
      }
      ++offset;
    }
  }
};

struct AsciiEqualsIgnoreCaseKernel {
  template <uarch::Arch Token>
  [[nodiscard]] static constexpr bool operator()(Token, std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
      return false;
    }
    using Vec = uarch::simd::native_vec<std::uint8_t, Token>;
    constexpr auto width = static_cast<std::size_t>(Vec::size());

    std::size_t offset = 0uz;
    if (a.size() >= width && b.size() >= width) {
      const Vec upper_a{static_cast<std::uint8_t>('A')};
      const Vec upper_z{static_cast<std::uint8_t>('Z')};
      const Vec case_bit{0x20U};
      const Vec zero{0x00U};

      while (offset + width <= a.size() && offset + width <= b.size()) {
        const Vec va = LoadVec<Vec>(a.data() + offset);
        const Vec vb = LoadVec<Vec>(b.data() + offset);
        const Vec da = uarch::simd::select((va >= upper_a) & (va <= upper_z), case_bit, zero);
        const Vec db = uarch::simd::select((vb >= upper_a) & (vb <= upper_z), case_bit, zero);
        const Vec la = va | da;
        const Vec lb = vb | db;
        if (uarch::simd::any_of(la != lb)) {
          return false;
        }
        offset += width;
      }
    }

    while (offset < a.size()) {
      auto ca = static_cast<std::uint8_t>(a[offset]);
      auto cb = static_cast<std::uint8_t>(b[offset]);
      if (ca >= static_cast<std::uint8_t>('A') && ca <= static_cast<std::uint8_t>('Z')) {
        ca |= 0x20U;
      }
      if (cb >= static_cast<std::uint8_t>('A') && cb <= static_cast<std::uint8_t>('Z')) {
        cb |= 0x20U;
      }
      if (ca != cb) {
        return false;
      }
      ++offset;
    }
    return true;
  }
};

template <typename Kernel>
struct KernelRunner {
  template <typename... Args>
  [[gnu::always_inline]] static constexpr decltype(auto) operator()(uarch::Scalar token, Args... args) noexcept {
    return Kernel::operator()(token, args...);
  }
#if defined(__x86_64__)
  template <typename... Args>
  [[gnu::target("arch=x86-64-v3"), gnu::always_inline]] static decltype(auto) operator()(uarch::X86V3 token,
                                                                                         Args... args) noexcept {
    return Kernel::operator()(token, args...);
  }
  template <typename... Args>
  [[gnu::target("arch=x86-64-v3"), gnu::always_inline]] static decltype(auto) operator()(uarch::X86V3SlowPdep token,
                                                                                         Args... args) noexcept {
    return Kernel::operator()(token, args...);
  }
  template <typename... Args>
  [[gnu::target("arch=x86-64-v4"), gnu::always_inline]] static decltype(auto) operator()(uarch::X86V4 token,
                                                                                         Args... args) noexcept {
    return Kernel::operator()(token, args...);
  }
#endif
#if defined(__aarch64__)
  template <typename... Args>
  [[gnu::always_inline]] static decltype(auto) operator()(uarch::Aarch64Neon token, Args... args) noexcept {
    return Kernel::operator()(token, args...);
  }
#endif
};

[[nodiscard]] consteval std::array<bool, 256> BuildTcharTable() noexcept {
  std::array<bool, 256> table{};
  for (std::uint8_t c = '0'; c <= '9'; ++c) table[c] = true;
  for (std::uint8_t c = 'A'; c <= 'Z'; ++c) table[c] = true;
  for (std::uint8_t c = 'a'; c <= 'z'; ++c) table[c] = true;
  constexpr std::string_view symbols = "!#$%&'*+-.^_`|~";
  for (char ch : symbols) {
    table[static_cast<std::uint8_t>(ch)] = true;
  }
  return table;
}

inline constexpr std::array<bool, 256> kTcharTable = BuildTcharTable();
inline constexpr const auto& kHttpTokenTable = kTcharTable;

[[nodiscard]] consteval std::array<bool, 256> BuildLowerTcharTable() noexcept {
  std::array<bool, 256> table{};
  for (std::uint8_t c = '0'; c <= '9'; ++c) table[c] = true;
  for (std::uint8_t c = 'a'; c <= 'z'; ++c) table[c] = true;
  constexpr std::string_view symbols = "!#$%&'*+-.^_`|~";
  for (char ch : symbols) {
    table[static_cast<std::uint8_t>(ch)] = true;
  }
  return table;
}

inline constexpr std::array<bool, 256> kLowerTcharTable = BuildLowerTcharTable();

struct HeaderNameValidateKernel {
  template <uarch::Arch Token>
  [[nodiscard]] static constexpr bool operator()(Token, std::string_view name) noexcept {
    return !name.empty() &&
           std::ranges::all_of(name, [](char ch) noexcept { return kTcharTable[static_cast<std::uint8_t>(ch)]; });
  }
};

template <typename Kernel, typename... Args>
[[nodiscard]] constexpr decltype(auto) RunScanKernel(Args&&... args) noexcept {
  if consteval {
    return uarch::run<KernelRunner<Kernel>{}>(uarch::Scalar{}, std::forward<Args>(args)...);
  } else {
    return uarch::dispatch_kernel<KernelRunner<Kernel>{}>(ActiveScanTier(), std::forward<Args>(args)...);
  }
}

template <typename Kernel, uarch::Arch Token, typename... Args>
[[nodiscard]] constexpr decltype(auto) RunScanKernelWithToken(Token token, Args&&... args) noexcept {
  return uarch::run<KernelRunner<Kernel>{}>(token, std::forward<Args>(args)...);
}

}  // namespace nexora::detail

namespace nexora {

[[nodiscard]] constexpr std::optional<std::size_t> FindByte(std::span<const std::uint8_t> haystack,
                                                            std::uint8_t needle) noexcept {
  return detail::RunScanKernel<detail::FindByteKernel>(haystack, needle);
}

[[nodiscard]] constexpr std::optional<std::size_t> FindByte(std::string_view haystack, char needle) noexcept {
  return detail::RunScanKernel<detail::FindByteKernel>(haystack, static_cast<std::uint8_t>(needle));
}

[[nodiscard]] constexpr std::optional<std::size_t> FindCrLf(std::span<const std::uint8_t> buf) noexcept {
  if (buf.size() < 2uz) {
    return std::nullopt;
  }
  std::size_t pos = 0uz;
  const std::size_t search_limit = buf.size() - 1uz;
  while (pos < search_limit) {
    const auto rel = FindByte(buf.subspan(pos, search_limit - pos), static_cast<std::uint8_t>('\r'));
    if (!rel.has_value()) {
      return std::nullopt;
    }
    const std::size_t cr_idx = pos + *rel;
    if (buf[cr_idx + 1uz] == static_cast<std::uint8_t>('\n')) {
      return cr_idx;
    }
    pos = cr_idx + 1uz;
  }
  return std::nullopt;
}

[[nodiscard]] constexpr std::optional<std::size_t> FindCrLf(std::string_view buf) noexcept {
  if (buf.size() < 2uz) {
    return std::nullopt;
  }
  std::size_t pos = 0uz;
  const std::size_t search_limit = buf.size() - 1uz;
  while (pos < search_limit) {
    const auto rel = FindByte(buf.substr(pos, search_limit - pos), '\r');
    if (!rel.has_value()) {
      return std::nullopt;
    }
    const std::size_t cr_idx = pos + *rel;
    if (buf[cr_idx + 1uz] == '\n') {
      return cr_idx;
    }
    pos = cr_idx + 1uz;
  }
  return std::nullopt;
}

[[nodiscard]] constexpr std::optional<std::size_t> FindHeaderEnd(std::span<const std::uint8_t> buf) noexcept {
  if (buf.size() < 4uz) {
    return std::nullopt;
  }
  std::size_t pos = 0uz;
  const std::size_t search_limit = buf.size() - 3uz;
  while (pos < search_limit) {
    const auto rel = FindByte(buf.subspan(pos, search_limit - pos), static_cast<std::uint8_t>('\r'));
    if (!rel.has_value()) {
      return std::nullopt;
    }
    const std::size_t idx = pos + *rel;
    if (buf[idx + 1uz] == static_cast<std::uint8_t>('\n') && buf[idx + 2uz] == static_cast<std::uint8_t>('\r') &&
        buf[idx + 3uz] == static_cast<std::uint8_t>('\n')) {
      return idx;
    }
    pos = idx + 1uz;
  }
  return std::nullopt;
}

[[nodiscard]] constexpr std::optional<std::size_t> FindHeaderEnd(std::string_view buf) noexcept {
  if (buf.size() < 4uz) {
    return std::nullopt;
  }
  std::size_t pos = 0uz;
  const std::size_t search_limit = buf.size() - 3uz;
  while (pos < search_limit) {
    const auto rel = FindByte(buf.substr(pos, search_limit - pos), '\r');
    if (!rel.has_value()) {
      return std::nullopt;
    }
    const std::size_t idx = pos + *rel;
    if (buf[idx + 1uz] == '\n' && buf[idx + 2uz] == '\r' && buf[idx + 3uz] == '\n') {
      return idx;
    }
    pos = idx + 1uz;
  }
  return std::nullopt;
}

[[nodiscard]] constexpr bool IsValidHeaderName(std::string_view name) noexcept {
  return !name.empty() &&
         std::ranges::all_of(name, [](char ch) noexcept { return detail::kTcharTable[static_cast<std::uint8_t>(ch)]; });
}

[[nodiscard]] constexpr bool IsValidLowercaseHeaderName(std::string_view name) noexcept {
  return !name.empty() &&
         std::ranges::all_of(name, [](char ch) noexcept { return detail::kLowerTcharTable[static_cast<std::uint8_t>(ch)]; });
}

[[nodiscard]] constexpr bool IsValidHttp2HeaderName(std::string_view name, bool allow_pseudo = true) noexcept {
  if (name.empty()) {
    return false;
  }
  std::string_view token = name;
  if (allow_pseudo && token.starts_with(':')) {
    token.remove_prefix(1);
  }
  return IsValidLowercaseHeaderName(token);
}

[[nodiscard]] constexpr bool IsValidHeaderValue(std::string_view value) noexcept {
  return detail::RunScanKernel<detail::HeaderValueValidateKernel>(value);
}

[[nodiscard]] constexpr bool AsciiEqualsIgnoreCase(std::string_view a, std::string_view b) noexcept {
  return detail::RunScanKernel<detail::AsciiEqualsIgnoreCaseKernel>(a, b);
}

constexpr void AsciiLowerInPlace(std::span<char> buf) noexcept { detail::RunScanKernel<detail::AsciiLowerKernel>(buf); }

[[nodiscard]] inline std::string AsciiLowerCopy(std::string_view input) {
  std::string out(input);
  AsciiLowerInPlace(std::span<char>(out.data(), out.size()));
  return out;
}

[[nodiscard]] constexpr std::string_view TrimAsciiWhitespace(std::string_view s) noexcept {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
    s.remove_prefix(1);
  }
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
    s.remove_suffix(1);
  }
  return s;
}

}  // namespace nexora
