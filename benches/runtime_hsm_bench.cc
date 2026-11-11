#include <array>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <nexora/probes/probes.hpp>
#include <optional>
#include <string_view>
#include <system_error>

#if defined(NEXORA_FREESTANDING)
#include <probes/gem5_entry.hpp>
#endif
namespace {
template <auto Probe>
[[gnu::noinline, nodiscard]] std::uint64_t RunMeasuredLoop(std::uint64_t iterations) noexcept {
  std::array<std::uint64_t, 4> sums{};
  std::uint64_t i = 0;
  for (; iterations - i >= 4; i += 4) {
    sums[0] += Probe();
    sums[1] += Probe();
    sums[2] += Probe();
    sums[3] += Probe();
  }
  for (; i < iterations; ++i) sums[0] += Probe();
  return sums[0] + sums[1] + sums[2] + sums[3];
}

template <auto Probe>
[[nodiscard]] std::uint64_t Run(std::uint64_t iterations, [[maybe_unused]] std::uint64_t seed) noexcept {
#if defined(NEXORA_GEM5_ROI)
  const auto warm = RunMeasuredLoop<Probe>(4096);
  asm volatile("" : : "r"(warm) : "memory");
  nexora::ResetProbeState(seed);
  asm volatile("mfence\n\tlfence\n\t.byte 0x0f, 0x04\n\t.word 0x0040\n\tlfence"
               :
               : "D"(0ULL), "S"(0ULL)
               : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "cc", "memory");
#endif
  const auto total = RunMeasuredLoop<Probe>(iterations);
#if defined(NEXORA_GEM5_ROI)
  asm volatile("lfence\n\t.byte 0x0f, 0x04\n\t.word 0x0041\n\tlfence"
               :
               : "D"(0ULL), "S"(0ULL)
               : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "cc", "memory");
#endif
  return total;
}

[[nodiscard]] std::optional<std::uint64_t> ParseCount(std::string_view text) noexcept {
#if defined(NEXORA_FREESTANDING)
  if (text.empty() || text.size() > 20) return std::nullopt;
  std::uint64_t value = 0;
  for (const char byte : text) {
    if (byte < '0' || byte > '9') return std::nullopt;
    const auto digit = static_cast<std::uint64_t>(byte - '0');
    if (value > UINT64_MAX / 10 || (value == UINT64_MAX / 10 && digit > UINT64_MAX % 10)) return std::nullopt;
    value = value * 10 + digit;
  }
  return value == 0 ? std::nullopt : std::optional(value);
#else
  std::uint64_t value = 0;
  const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
  if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || value == 0) return std::nullopt;
  return value;
#endif
}
#if defined(NEXORA_FREESTANDING)
void Report(std::string_view probe, std::uint64_t count, std::uint64_t checksum) noexcept {
  std::array<char, 160> output{};
  std::size_t offset = 0;
  const auto text = [&](std::string_view part) noexcept {
    for (char byte : part) output[offset++] = byte;
  };
  const auto number = [&](std::uint64_t value, std::size_t width) noexcept {
    std::array<char, 20> digits{};
    for (std::size_t index = width; index != 0; --index) {
      const auto quotient = uarch::arithmetic::divisor_u64<10>().div(value);
      digits[index - 1] = static_cast<char>('0' + (value - quotient * 10));
      value = quotient;
    }
    for (std::size_t index = 0; index < width; ++index) output[offset++] = digits[index];
  };
  text("probe=");
  text(probe);
  text(" iterations=");
  number(count, 20);
  text(" checksum=");
  number(checksum, 20);
  text("\n");
  NexoraGuestWrite(output.data(), offset);
}
#endif
}  // namespace

int main(int argc, char** argv) {
  std::string_view probe;
  std::uint64_t iterations = 0;
  std::uint64_t seed = 1;
  for (int i = 1; i < argc; i += 2) {
    if (i + 1 >= argc) return 2;
    const std::string_view key(argv[i]);
    const std::string_view value(argv[i + 1]);
    if (key == "--probe")
      probe = value;
    else if (key == "--iterations") {
      const auto count = ParseCount(value);
      if (!count) return 2;
      iterations = *count;
    } else if (key == "--seed") {
      const auto count = ParseCount(value);
      if (!count) return 2;
      seed = *count;
    } else
      return 2;
  }
  if (iterations == 0) return 2;
  nexora::ResetProbeState(seed);
  std::uint64_t checksum = 0;
  if (probe == "socket_step")
    checksum = Run<nexora_probe_socket_step>(iterations, seed);
  else if (probe == "h2_frame_header")
    checksum = Run<nexora_probe_h2_frame_header>(iterations, seed);
  else if (probe == "ws_mask")
    checksum = Run<nexora_probe_ws_mask>(iterations, seed);
  else if (probe == "pool_select")
    checksum = Run<nexora_probe_pool_select>(iterations, seed);
  else
    return 2;
#if defined(NEXORA_FREESTANDING)
  Report(probe, iterations, checksum);
#else
  std::printf("probe=%.*s iterations=%llu checksum=%llu\n", static_cast<int>(probe.size()), probe.data(),
              static_cast<unsigned long long>(iterations), static_cast<unsigned long long>(checksum));
#endif
  return 0;
}
