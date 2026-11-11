#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <uring/uring.hpp>

namespace nexora::detail {

struct ParkedSlotRef {
  void* owner{nullptr};
  bool (*retire)(void* owner, uring::UserDataToken token, std::uint64_t ring_instance) noexcept {nullptr};
};

class ParkedRegistry {
 public:
  static constexpr std::size_t kCapacity = 64;

  [[nodiscard]] constexpr std::size_t ActiveCount() const noexcept { return active_count_ + swallow_count_; }

  [[nodiscard]] bool HasSubsystem(std::uint8_t subsystem_id) const noexcept {
    if (active_count_ == 0 && swallow_count_ == 0) return false;
    for (const auto& row : rows_) {
      if (row.active && uring::Subsystem(row.token) == subsystem_id) return true;
    }
    for (std::size_t i = 0; i < swallow_count_; ++i) {
      if (uring::Subsystem(swallows_[i].token) == subsystem_id) return true;
    }
    return false;
  }

  bool Register(uring::UserDataToken token, std::uint64_t ring_instance, ParkedSlotRef ref) noexcept {
    for (auto& row : rows_) {
      if (row.active) continue;
      row.active = true;
      row.swallow = false;
      row.token = token;
      row.ring_instance = ring_instance;
      row.ref = ref;
      ++active_count_;
      return true;
    }
    RememberSwallow(token, ring_instance);
    return false;
  }

  void Unregister(uring::UserDataToken token, std::uint64_t ring_instance) noexcept {
    for (auto& row : rows_) {
      if (!row.active || row.token != token || row.ring_instance != ring_instance) continue;
      row.swallow = true;
      row.ref = {};
      return;
    }
  }

  bool Retire(uring::UserDataToken token, std::uint64_t ring_instance) noexcept {
    if (active_count_ == 0 && swallow_count_ == 0) [[likely]]
      return false;
    for (auto& row : rows_) {
      if (!row.active || row.token != token || !SameRing(row.ring_instance, ring_instance)) continue;
      const ParkedSlotRef ref = row.ref;
      const bool swallow = row.swallow || ref.retire == nullptr;
      row = {};
      if (active_count_ > 0) --active_count_;
      if (swallow) return true;
      return ref.retire(ref.owner, token, ring_instance);
    }
    return TakeSwallow(swallows_.data(), swallow_count_, token, ring_instance);
  }

 private:
  struct Row {
    bool active{false};
    bool swallow{false};
    uring::UserDataToken token{};
    std::uint64_t ring_instance{0};
    ParkedSlotRef ref{};
  };
  struct SwallowKey {
    uring::UserDataToken token{};
    std::uint64_t ring_instance{0};
  };

  [[nodiscard]] static constexpr bool SameRing(std::uint64_t stored, std::uint64_t query) noexcept {
    return stored == 0 || query == 0 || stored == query;
  }

  void RememberSwallow(uring::UserDataToken token, std::uint64_t ring_instance) noexcept {
    if (this->swallow_count_ >= this->swallows_.size()) return;
    this->swallows_[this->swallow_count_++] = SwallowKey{token, ring_instance};
  }

  [[nodiscard]] static bool TakeSwallow(SwallowKey* rows, std::size_t& count, uring::UserDataToken token,
                                        std::uint64_t ring_instance) noexcept {
    for (std::size_t i = 0; i < count; ++i) {
      if (rows[i].token != token || !SameRing(rows[i].ring_instance, ring_instance)) continue;
      rows[i] = rows[count - 1];
      --count;
      return true;
    }
    return false;
  }

  static constexpr std::size_t kSwallowCapacity = 256;

  std::size_t active_count_{0};
  std::size_t swallow_count_{0};
  std::array<Row, kCapacity> rows_{};
  std::array<SwallowKey, kSwallowCapacity> swallows_{};
};

inline ParkedRegistry& SharedParkedRegistry() noexcept {
  constinit thread_local ParkedRegistry registry{};
  return registry;
}

inline bool RetireParked(uring::UserDataToken token, std::uint64_t ring_instance) noexcept {
  auto& registry = SharedParkedRegistry();
  if (registry.ActiveCount() == 0) [[likely]]
    return false;
  return registry.Retire(token, ring_instance);
}

static_assert(std::is_standard_layout_v<ParkedRegistry>);
static_assert(std::is_trivially_destructible_v<ParkedRegistry>);

}  // namespace nexora::detail
