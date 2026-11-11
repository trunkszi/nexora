#pragma once

#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <uring/uring.hpp>
#include <utility>
#include <vector>

#if defined(__SANITIZE_ADDRESS__) || (defined(__has_feature) && __has_feature(address_sanitizer))
#include <sanitizer/lsan_interface.h>
#define NEXORA_DETAIL_HAS_LSAN 1
#endif

namespace nexora::detail {

inline void LeakDmaBuffer(std::vector<std::uint8_t>&& buf) noexcept {
  if (buf.capacity() == 0 || buf.data() == nullptr) {
    return;
  }
#if defined(NEXORA_DETAIL_HAS_LSAN)
  __lsan_ignore_object(buf.data());
#endif
  union DetachedBuffer {
    char inactive{};
    std::vector<std::uint8_t> leaked;
    constexpr DetachedBuffer() noexcept : inactive{} {}
    ~DetachedBuffer() noexcept {}
  } holder;
  std::construct_at(&holder.leaked, std::move(buf));
}

struct ParkedSocketDma {
  bool active{false};
  int fd{-1};
  std::uint64_t ring_instance{0};
  std::vector<std::uint8_t> rx_buffer{};
  std::vector<std::uint8_t> tx_buffer{};
  std::optional<uring::UserDataToken> rx_token{};
  std::optional<uring::UserDataToken> tx_token{};
  std::optional<uring::UserDataToken> connect_token{};
};

class SocketDmaQuarantine {
 public:
  static constexpr std::size_t kCapacity = 64;

 private:
  struct OverflowFd {
    bool active{false};
    int fd{-1};
    std::uint64_t ring_instance{0};
    std::optional<uring::UserDataToken> rx_token{};
    std::optional<uring::UserDataToken> tx_token{};
    std::optional<uring::UserDataToken> connect_token{};
  };

  std::array<ParkedSocketDma, kCapacity> slots_{};
  std::array<OverflowFd, kCapacity> overflow_{};
  std::vector<OverflowFd> emergency_overflow_{};
  std::size_t active_count_{0};
  std::size_t overflow_count_{0};
  std::size_t emergency_count_{0};
  std::int32_t last_retired_result_{0};
  std::uint64_t retired_count_{0};
  std::array<std::uint8_t, 64> last_retired_rx_prefix_{};
  std::size_t last_retired_rx_len_{0};

 public:
  constexpr SocketDmaQuarantine() noexcept = default;
  SocketDmaQuarantine(const SocketDmaQuarantine&) = delete ("DMA quarantine owns pinned buffer addresses");
  SocketDmaQuarantine& operator=(const SocketDmaQuarantine&) = delete ("DMA quarantine owns pinned buffer addresses");
  SocketDmaQuarantine(SocketDmaQuarantine&&) = delete ("DMA quarantine owns pinned buffer addresses");
  SocketDmaQuarantine& operator=(SocketDmaQuarantine&&) = delete ("DMA quarantine owns pinned buffer addresses");

  ~SocketDmaQuarantine() noexcept {
    for (auto& slot : slots_) {
      LeakDmaBuffer(std::move(slot.rx_buffer));
      LeakDmaBuffer(std::move(slot.tx_buffer));
    }
    CloseAllFds();
  }

  void CloseAllFds() noexcept {
    for (auto& slot : slots_) {
      if (slot.fd >= 0) static_cast<void>(::close(std::exchange(slot.fd, -1)));
    }
    for (auto& extra : overflow_) {
      if (extra.fd >= 0) static_cast<void>(::close(std::exchange(extra.fd, -1)));
    }
    for (auto& extra : emergency_overflow_) {
      if (extra.fd >= 0) static_cast<void>(::close(std::exchange(extra.fd, -1)));
    }
  }

  void Park(std::uint64_t ring_instance, int fd, std::vector<std::uint8_t>&& rx, std::vector<std::uint8_t>&& tx,
            std::optional<uring::UserDataToken> rx_tok, std::optional<uring::UserDataToken> tx_tok,
            std::optional<uring::UserDataToken> conn_tok) noexcept {
    const bool tracked = rx_tok.has_value() || tx_tok.has_value() || conn_tok.has_value();
    if (tracked) {
      for (auto& slot : slots_) {
        if (!slot.active) {
          slot = ParkedSocketDma{true, fd, ring_instance, std::move(rx), std::move(tx), rx_tok, tx_tok, conn_tok};
          ++active_count_;
          return;
        }
      }
      if (!RememberOverflow(ring_instance, fd, rx_tok, tx_tok, conn_tok)) {
        RememberEmergencyOverflow(ring_instance, fd, rx_tok, tx_tok, conn_tok);
      }
      LeakDmaBuffer(std::move(rx));
      LeakDmaBuffer(std::move(tx));
      return;
    }
    if (fd >= 0) static_cast<void>(::close(fd));
    LeakDmaBuffer(std::move(rx));
    LeakDmaBuffer(std::move(tx));
  }

  [[nodiscard]] constexpr std::size_t ActiveCount() const noexcept {
    return active_count_ + overflow_count_ + emergency_count_;
  }
  [[nodiscard]] constexpr std::int32_t LastRetiredResult() const noexcept { return last_retired_result_; }
  [[nodiscard]] constexpr std::uint64_t RetiredCount() const noexcept { return retired_count_; }
  [[nodiscard]] std::span<const std::uint8_t> LastRetiredRxPrefix() const noexcept {
    return {last_retired_rx_prefix_.data(), last_retired_rx_len_};
  }

  [[nodiscard]] bool TryRetire(uring::UserDataToken token, std::uint64_t ring_instance = 0, std::int32_t result = 0) noexcept {
    std::size_t& retired_count = this->retired_count_;
    std::int32_t& last_retired_result = this->last_retired_result_;
    if (this->active_count_ == 0 && this->overflow_count_ == 0 && this->emergency_count_ == 0) [[likely]] {
      return false;
    }
    for (auto& slot : slots_) {
      if (!slot.active) {
        continue;
      }
      if (ring_instance != 0 && slot.ring_instance != 0 && slot.ring_instance != ring_instance) {
        continue;
      }
      const bool m_rx = slot.rx_token.has_value() && *slot.rx_token == token;
      const bool m_tx = slot.tx_token.has_value() && *slot.tx_token == token;
      const bool m_cn = slot.connect_token.has_value() && *slot.connect_token == token;
      if (!m_rx && !m_tx && !m_cn) {
        continue;
      }
      last_retired_result = result;
      ++retired_count;
      if (m_rx) {
        if (result > 0 && !slot.rx_buffer.empty()) {
          const std::size_t n =
              std::min<std::size_t>({static_cast<std::size_t>(result), slot.rx_buffer.size(), last_retired_rx_prefix_.size()});
          std::memcpy(last_retired_rx_prefix_.data(), slot.rx_buffer.data(), n);
          last_retired_rx_len_ = n;
        } else {
          last_retired_rx_len_ = 0;
        }
        slot.rx_token.reset();
      }
      if (m_tx) {
        slot.tx_token.reset();
      }
      if (m_cn) {
        slot.connect_token.reset();
      }
      if (!slot.rx_token.has_value() && !slot.tx_token.has_value() && !slot.connect_token.has_value()) {
        if (slot.fd >= 0) {
          static_cast<void>(::close(slot.fd));
        }
        slot = ParkedSocketDma{};
        --active_count_;
      }
      return true;
    }
    if (RetireOverflowSpan(overflow_, overflow_count_, token, ring_instance, result)) {
      return true;
    }
    if (emergency_count_ != 0) {
      return RetireOverflowSpan(emergency_overflow_, emergency_count_, token, ring_instance, result);
    }
    return false;
  }

 private:
  [[nodiscard]] bool RetireOverflowSpan(std::span<OverflowFd> entries, std::size_t& count, uring::UserDataToken token,
                                        std::uint64_t ring_instance, std::int32_t result) noexcept {
    for (auto& extra : entries) {
      if (!extra.active) continue;
      if (extra.ring_instance != 0 && ring_instance != 0 && extra.ring_instance != ring_instance) continue;
      const bool m_rx = extra.rx_token.has_value() && *extra.rx_token == token;
      const bool m_tx = extra.tx_token.has_value() && *extra.tx_token == token;
      const bool m_cn = extra.connect_token.has_value() && *extra.connect_token == token;
      if (!m_rx && !m_tx && !m_cn) continue;
      last_retired_result_ = result;
      ++retired_count_;
      if (m_rx) extra.rx_token.reset();
      if (m_tx) extra.tx_token.reset();
      if (m_cn) extra.connect_token.reset();
      if (!extra.rx_token.has_value() && !extra.tx_token.has_value() && !extra.connect_token.has_value()) {
        if (extra.fd >= 0) static_cast<void>(::close(extra.fd));
        extra = OverflowFd{};
        if (count > 0) --count;
      }
      return true;
    }
    return false;
  }

  [[nodiscard]] bool RememberOverflow(std::uint64_t ring_instance, int fd, std::optional<uring::UserDataToken> rx_tok,
                                      std::optional<uring::UserDataToken> tx_tok,
                                      std::optional<uring::UserDataToken> conn_tok) noexcept {
    std::size_t& overflow_count = this->overflow_count_;
    for (auto& extra : this->overflow_) {
      if (extra.active) continue;
      extra = OverflowFd{true, fd, ring_instance, rx_tok, tx_tok, conn_tok};
      ++overflow_count;
      return true;
    }
    return false;
  }

  void RememberEmergencyOverflow(std::uint64_t ring_instance, int fd, std::optional<uring::UserDataToken> rx_tok,
                                 std::optional<uring::UserDataToken> tx_tok,
                                 std::optional<uring::UserDataToken> conn_tok) noexcept {
    for (auto& extra : emergency_overflow_) {
      if (extra.active) continue;
      extra = OverflowFd{true, fd, ring_instance, rx_tok, tx_tok, conn_tok};
      ++emergency_count_;
      return;
    }
    emergency_overflow_.push_back(OverflowFd{true, fd, ring_instance, rx_tok, tx_tok, conn_tok});
    ++emergency_count_;
  }
};

}  // namespace nexora::detail
