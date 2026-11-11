#pragma once

#include <algorithm>
#include <cares/cares.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <nexora/error/runtime_error.hpp>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace nexora {

namespace detail {

class SimplexRing {
  std::vector<std::uint8_t> storage_{};
  std::size_t head_{0};
  std::size_t tail_{0};
  std::size_t size_{0};
  std::size_t max_capacity_{65536};
  bool write_closed_{false};
  bool read_closed_{false};
  bool reset_{false};

 public:
  explicit SimplexRing(std::size_t capacity = 65536) noexcept : max_capacity_(capacity == 0 ? 65536 : capacity) {
    storage_.resize(max_capacity_, 0);
  }

  [[nodiscard]] constexpr std::size_t ReadableBytes() const noexcept { return size_; }
  [[nodiscard]] constexpr std::size_t WritableBytes() const noexcept {
    return (size_ < max_capacity_) ? (max_capacity_ - size_) : 0;
  }
  [[nodiscard]] constexpr bool IsWriteClosed() const noexcept { return write_closed_; }
  [[nodiscard]] constexpr bool IsReadClosed() const noexcept { return read_closed_; }
  [[nodiscard]] constexpr bool IsReset() const noexcept { return reset_; }

  constexpr void CloseWrite() noexcept { write_closed_ = true; }
  constexpr void CloseRead() noexcept {
    read_closed_ = true;
    head_ = 0;
    tail_ = 0;
    size_ = 0;
  }
  constexpr void Reset() noexcept {
    reset_ = true;
    write_closed_ = true;
    read_closed_ = true;
    head_ = 0;
    tail_ = 0;
    size_ = 0;
  }

  [[nodiscard]] Result<std::size_t> Write(std::span<const std::uint8_t> data) noexcept {
    if (reset_) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionReset));
    }
    if (write_closed_ || read_closed_) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    }
    if (data.empty()) {
      return std::size_t{0};
    }
    const std::size_t avail = WritableBytes();
    if (avail == 0) {
      return std::unexpected(Error::BufferOverflow());
    }
    const std::size_t to_write = std::min(avail, data.size());
    for (std::size_t i = 0; i < to_write; ++i) {
      storage_[tail_] = data[i];
      tail_ = (tail_ + 1) % max_capacity_;
    }
    size_ += to_write;
    return to_write;
  }

  [[nodiscard]] Result<void> WriteAll(std::span<const std::uint8_t> data) noexcept {
    if (reset_) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionReset));
    }
    if (write_closed_ || read_closed_) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    }
    if (data.size() > WritableBytes()) {
      return std::unexpected(Error::BufferOverflow());
    }
    auto written = Write(data);
    if (!written) {
      return std::unexpected(written.error());
    }
    return {};
  }

  [[nodiscard]] Result<std::size_t> ReadSome(std::span<std::uint8_t> out) noexcept {
    if (reset_) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionReset));
    }
    if (read_closed_) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    }
    if (out.empty()) {
      return std::size_t{0};
    }
    if (size_ == 0) {
      if (write_closed_) {
        return std::size_t{0};
      }
      return std::unexpected(Error::Incomplete());
    }
    const std::size_t to_read = std::min(size_, out.size());
    for (std::size_t i = 0; i < to_read; ++i) {
      out[i] = storage_[head_];
      head_ = (head_ + 1) % max_capacity_;
    }
    size_ -= to_read;
    return to_read;
  }
};

struct DuplexPipeState {
  SimplexRing a_to_b;
  SimplexRing b_to_a;
  std::uint32_t ref_count{2};

  explicit DuplexPipeState(std::size_t capacity) noexcept : a_to_b(capacity), b_to_a(capacity) {}

  static DuplexPipeState* Allocate(std::size_t capacity) noexcept {
    std::allocator<DuplexPipeState> alloc{};
    DuplexPipeState* ptr = alloc.allocate(1);
    std::construct_at(ptr, capacity);
    return ptr;
  }

  static void Release(DuplexPipeState* ptr) noexcept {
    if (ptr == nullptr) {
      return;
    }
    if (--ptr->ref_count == 0) {
      std::destroy_at(ptr);
      std::allocator<DuplexPipeState> alloc{};
      alloc.deallocate(ptr, 1);
    }
  }
};

}  // namespace detail

struct MemoryPipePair;

class MemoryPipe {
  detail::DuplexPipeState* state_{nullptr};
  bool is_side_a_{true};
  bool local_closed_{false};

  constexpr MemoryPipe(detail::DuplexPipeState* state, bool is_side_a) noexcept
      : state_(state), is_side_a_(is_side_a), local_closed_(false) {}

  [[nodiscard]] detail::SimplexRing& TxRing() noexcept { return is_side_a_ ? state_->a_to_b : state_->b_to_a; }
  [[nodiscard]] const detail::SimplexRing& TxRing() const noexcept { return is_side_a_ ? state_->a_to_b : state_->b_to_a; }
  [[nodiscard]] detail::SimplexRing& RxRing() noexcept { return is_side_a_ ? state_->b_to_a : state_->a_to_b; }
  [[nodiscard]] const detail::SimplexRing& RxRing() const noexcept { return is_side_a_ ? state_->b_to_a : state_->a_to_b; }

  friend struct MemoryPipePair;

 public:
  constexpr MemoryPipe() noexcept = default;

  MemoryPipe(const MemoryPipe&) = delete ("single-owner MemoryPipe handle; move instead");
  MemoryPipe& operator=(const MemoryPipe&) = delete ("single-owner MemoryPipe handle; move instead");

  constexpr MemoryPipe(MemoryPipe&& other) noexcept
      : state_(std::exchange(other.state_, nullptr)),
        is_side_a_(other.is_side_a_),
        local_closed_(std::exchange(other.local_closed_, true)) {}

  MemoryPipe& operator=(MemoryPipe&& other) noexcept {
    if (this != &other) {
      ReleaseState();
      state_ = std::exchange(other.state_, nullptr);
      is_side_a_ = other.is_side_a_;
      local_closed_ = std::exchange(other.local_closed_, true);
    }
    return *this;
  }

  ~MemoryPipe() noexcept { ReleaseState(); }

  [[nodiscard]] static Result<MemoryPipePair> CreatePair(std::size_t capacity = 65536) noexcept;

  [[nodiscard]] Result<void> Connect(const cares::Endpoint& /*endpoint*/, std::uint32_t /*timeout_ms*/ = 0) noexcept {
    if (state_ == nullptr || local_closed_) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    }
    return {};
  }

  [[nodiscard]] Result<std::size_t> Write(std::span<const std::uint8_t> data) noexcept {
    if (state_ == nullptr || local_closed_) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    }
    return TxRing().Write(data);
  }

  [[nodiscard]] Result<void> WriteAll(std::span<const std::uint8_t> data, std::uint32_t /*timeout_ms*/ = 0) noexcept {
    if (state_ == nullptr || local_closed_) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    }
    return TxRing().WriteAll(data);
  }

  [[nodiscard]] Result<void> WriteString(std::string_view text) noexcept {
    return WriteAll(std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(text.data()), text.size()});
  }

  [[nodiscard]] Result<std::size_t> ReadSome(std::span<std::uint8_t> out, std::uint32_t /*timeout_ms*/ = 0) noexcept {
    if (state_ == nullptr || local_closed_) {
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    }
    return RxRing().ReadSome(out);
  }
  [[nodiscard]] Result<std::size_t> Read(std::span<std::uint8_t> out) noexcept { return ReadSome(out, 0); }

  void CloseWrite() noexcept {
    if (state_ != nullptr && !local_closed_) {
      TxRing().CloseWrite();
    }
  }
  void ShutdownWrite() noexcept { CloseWrite(); }

  void Close() noexcept {
    if (state_ != nullptr && !local_closed_) {
      TxRing().CloseWrite();
      RxRing().CloseRead();
      local_closed_ = true;
    }
  }

  void ResetPeer() noexcept {
    if (state_ != nullptr) {
      TxRing().Reset();
      RxRing().Reset();
      local_closed_ = true;
    }
  }

  [[nodiscard]] bool IsOpen() const noexcept { return state_ != nullptr && !local_closed_; }
  [[nodiscard]] bool IsClosed() const noexcept { return !IsOpen(); }

  [[nodiscard]] std::size_t PendingReadBytes() const noexcept {
    return (state_ != nullptr && !local_closed_) ? RxRing().ReadableBytes() : 0;
  }
  [[nodiscard]] std::size_t ReadableBytes() const noexcept { return PendingReadBytes(); }

  [[nodiscard]] std::size_t WritableBytes() const noexcept {
    return (state_ != nullptr && !local_closed_) ? TxRing().WritableBytes() : 0;
  }

 private:
  void ReleaseState() noexcept {
    if (state_ != nullptr) {
      if (!local_closed_) {
        TxRing().CloseWrite();
        RxRing().CloseRead();
        local_closed_ = true;
      }
      detail::DuplexPipeState::Release(std::exchange(state_, nullptr));
    }
  }
};

struct MemoryPipePair {
  MemoryPipe client;
  MemoryPipe server;

  [[nodiscard]] static Result<MemoryPipePair> Create(std::size_t capacity = 65536) noexcept {
    auto* shared = detail::DuplexPipeState::Allocate(capacity);
    return MemoryPipePair{
        .client = MemoryPipe{shared, true},
        .server = MemoryPipe{shared, false},
    };
  }
};

inline Result<MemoryPipePair> MemoryPipe::CreatePair(std::size_t capacity) noexcept { return MemoryPipePair::Create(capacity); }

}  // namespace nexora
