/** @file @brief Zero-copy byte views, inline ring buffers, and network-order wire codecs. */
#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <nexora/bytes/scan.hpp>
#include <nexora/error/runtime_error.hpp>
#include <span>
#include <string_view>
#include <uarch/uarch.hpp>
#include <utility>
#include <vector>

namespace nexora {

namespace detail {

template <std::unsigned_integral T>
[[nodiscard]] constexpr Result<T> DecodeBe(std::span<const std::uint8_t> bytes, std::size_t offset = 0uz) noexcept {
  if (offset > bytes.size() || bytes.size() - offset < sizeof(T)) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kIncomplete));
  }
  std::array<std::uint8_t, sizeof(T)> raw{};
  if consteval {
    for (std::size_t i = 0uz; i < sizeof(T); ++i) {
      raw[i] = bytes[offset + i];
    }
  } else {
    std::memcpy(raw.data(), bytes.data() + offset, sizeof(T));
  }
  const auto val = std::bit_cast<T>(raw);
  if constexpr (std::endian::native == std::endian::little) {
    return std::byteswap(val);
  } else {
    return val;
  }
}

template <std::unsigned_integral T>
[[nodiscard]] constexpr std::array<std::uint8_t, sizeof(T)> EncodeBe(T v) noexcept {
  if constexpr (std::endian::native == std::endian::little) {
    v = std::byteswap(v);
  }
  return std::bit_cast<std::array<std::uint8_t, sizeof(T)>>(v);
}

[[nodiscard]] constexpr std::array<std::uint8_t, 2> EncodeU16Be(std::uint16_t v) noexcept { return EncodeBe<std::uint16_t>(v); }

[[nodiscard]] constexpr std::array<std::uint8_t, 3> EncodeU24Be(std::uint32_t v) noexcept {
  const auto b = EncodeBe<std::uint32_t>(v);
  return {b[1], b[2], b[3]};
}

[[nodiscard]] constexpr std::array<std::uint8_t, 4> EncodeU32Be(std::uint32_t v) noexcept { return EncodeBe<std::uint32_t>(v); }

[[nodiscard]] constexpr std::array<std::uint8_t, 8> EncodeU64Be(std::uint64_t v) noexcept { return EncodeBe<std::uint64_t>(v); }

}  // namespace detail

[[nodiscard]] constexpr Result<std::uint8_t> DecodeU8(std::span<const std::uint8_t> bytes, std::size_t offset = 0uz) noexcept {
  if (offset >= bytes.size() || bytes.size() - offset < 1uz) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kIncomplete));
  }
  return bytes[offset];
}

[[nodiscard]] constexpr Result<std::uint16_t> DecodeU16Be(std::span<const std::uint8_t> bytes,
                                                          std::size_t offset = 0uz) noexcept {
  return detail::DecodeBe<std::uint16_t>(bytes, offset);
}

[[nodiscard]] constexpr Result<std::uint32_t> DecodeU24Be(std::span<const std::uint8_t> bytes,
                                                          std::size_t offset = 0uz) noexcept {
  if (offset > bytes.size() || bytes.size() - offset < 3uz) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kIncomplete));
  }
  const std::array<std::uint8_t, 4> raw{0U, bytes[offset], bytes[offset + 1uz], bytes[offset + 2uz]};
  const auto val = std::bit_cast<std::uint32_t>(raw);
  if constexpr (std::endian::native == std::endian::little) {
    return std::byteswap(val);
  } else {
    return val;
  }
}

[[nodiscard]] constexpr Result<std::uint32_t> DecodeU32Be(std::span<const std::uint8_t> bytes,
                                                          std::size_t offset = 0uz) noexcept {
  return detail::DecodeBe<std::uint32_t>(bytes, offset);
}

[[nodiscard]] constexpr Result<std::uint64_t> DecodeU64Be(std::span<const std::uint8_t> bytes,
                                                          std::size_t offset = 0uz) noexcept {
  return detail::DecodeBe<std::uint64_t>(bytes, offset);
}

struct [[nodiscard]] BytesView {
  std::span<const std::uint8_t> data{};

  [[nodiscard]] constexpr const std::uint8_t* Data() const noexcept { return data.data(); }
  [[nodiscard]] constexpr std::size_t Size() const noexcept { return data.size(); }
  [[nodiscard]] constexpr bool Empty() const noexcept { return data.empty(); }
};

static_assert(sizeof(BytesView) == 16);
static_assert(uarch::NoPadding<BytesView>);
static_assert(uarch::RegisterPassable<BytesView>);

class Bytes {
 public:
  constexpr Bytes() noexcept = default;

  constexpr explicit Bytes(std::span<const std::uint8_t> span) noexcept : data_(span), owned_{}, is_owned_(false) {}

  constexpr Bytes(const Bytes& other) : data_(other.data_), owned_(other.owned_), is_owned_(other.is_owned_) {
    if (is_owned_) {
      data_ = std::span<const std::uint8_t>(owned_.data(), owned_.size());
    }
  }

  constexpr Bytes& operator=(const Bytes& other) {
    if (this != &other) {
      owned_ = other.owned_;
      is_owned_ = other.is_owned_;
      data_ = is_owned_ ? std::span<const std::uint8_t>(owned_.data(), owned_.size()) : other.data_;
    }
    return *this;
  }

  constexpr Bytes(Bytes&& other) noexcept : data_(other.data_), owned_(std::move(other.owned_)), is_owned_(other.is_owned_) {
    if (is_owned_) {
      data_ = std::span<const std::uint8_t>(owned_.data(), owned_.size());
    }
    other.data_ = {};
    other.is_owned_ = false;
  }

  constexpr Bytes& operator=(Bytes&& other) noexcept {
    if (this != &other) {
      const auto other_span = other.data_;
      owned_ = std::move(other.owned_);
      is_owned_ = other.is_owned_;
      data_ = is_owned_ ? std::span<const std::uint8_t>(owned_.data(), owned_.size()) : other_span;
      other.data_ = {};
      other.is_owned_ = false;
    }
    return *this;
  }

  [[nodiscard]] static constexpr Bytes FromSpan(std::span<const std::uint8_t> span) noexcept { return Bytes(span); }

  [[nodiscard]] static constexpr Bytes FromStatic(std::span<const std::uint8_t> span) noexcept { return Bytes(span); }

  [[nodiscard]] static Bytes FromString(std::string_view sv) noexcept {
    const auto* ptr = static_cast<const std::uint8_t*>(static_cast<const void*>(sv.data()));
    return Bytes(std::span<const std::uint8_t>{ptr, sv.size()});
  }

  [[nodiscard]] static constexpr Bytes FromVector(std::vector<std::uint8_t> vec) noexcept {
    Bytes out;
    out.owned_ = std::move(vec);
    out.is_owned_ = true;
    out.data_ = std::span<const std::uint8_t>(out.owned_.data(), out.owned_.size());
    return out;
  }

  [[nodiscard]] static constexpr Bytes CopyFromSlice(std::span<const std::uint8_t> slice) {
    return FromVector(std::vector<std::uint8_t>(slice.begin(), slice.end()));
  }

  [[nodiscard]] static constexpr Bytes CopyFromString(std::string_view sv) {
    std::vector<std::uint8_t> vec(sv.size());
    for (std::size_t i = 0uz; i < sv.size(); ++i) {
      vec[i] = static_cast<std::uint8_t>(sv[i]);
    }
    return FromVector(std::move(vec));
  }

  [[nodiscard]] constexpr bool IsOwned() const noexcept { return is_owned_; }
  [[nodiscard]] constexpr BytesView View() const noexcept { return BytesView{data_}; }
  [[nodiscard]] constexpr std::span<const std::uint8_t> Span() const noexcept { return data_; }

  [[nodiscard]] std::string_view AsStringView() const noexcept {
    return {static_cast<const char*>(static_cast<const void*>(data_.data())), data_.size()};
  }

  [[nodiscard]] constexpr const std::uint8_t* Data() const noexcept { return data_.data(); }
  [[nodiscard]] constexpr std::size_t Size() const noexcept { return data_.size(); }
  [[nodiscard]] constexpr bool Empty() const noexcept { return data_.empty(); }

  constexpr void Clear() noexcept {
    data_ = {};
    owned_.clear();
    is_owned_ = false;
  }

  [[nodiscard]] constexpr Bytes SliceView(std::size_t offset, std::size_t len) const noexcept {
    if (offset >= data_.size()) return Bytes{};
    const std::size_t clamped = std::min(len, data_.size() - offset);
    return Bytes(data_.subspan(offset, clamped));
  }

  [[nodiscard]] constexpr Bytes Slice(std::size_t offset, std::size_t len) const {
    if (offset >= data_.size()) return Bytes{};
    const std::size_t clamped = std::min(len, data_.size() - offset);
    const auto sub = data_.subspan(offset, clamped);
    return is_owned_ ? CopyFromSlice(sub) : Bytes(sub);
  }

  [[nodiscard]] constexpr Bytes SplitTo(std::size_t at) {
    const std::size_t split = std::min(at, data_.size());
    if (!is_owned_) {
      const Bytes prefix(data_.subspan(0, split));
      data_ = data_.subspan(split);
      return prefix;
    }
    Bytes prefix = CopyFromSlice(data_.subspan(0, split));
    owned_.erase(owned_.begin(), owned_.begin() + static_cast<std::ptrdiff_t>(split));
    data_ = std::span<const std::uint8_t>(owned_.data(), owned_.size());
    return prefix;
  }

  [[nodiscard]] constexpr Bytes SplitOff(std::size_t at) {
    const std::size_t split = std::min(at, data_.size());
    if (!is_owned_) {
      const Bytes suffix(data_.subspan(split));
      data_ = data_.subspan(0, split);
      return suffix;
    }
    Bytes suffix = CopyFromSlice(data_.subspan(split));
    owned_.resize(split);
    data_ = std::span<const std::uint8_t>(owned_.data(), owned_.size());
    return suffix;
  }

  constexpr void Consume(std::size_t n) noexcept {
    const std::size_t step = std::min(n, data_.size());
    if (!is_owned_) {
      data_ = data_.subspan(step);
      return;
    }
    owned_.erase(owned_.begin(), owned_.begin() + static_cast<std::ptrdiff_t>(step));
    data_ = std::span<const std::uint8_t>(owned_.data(), owned_.size());
  }

  constexpr void Advance(std::size_t n) noexcept { Consume(n); }

  [[nodiscard]] constexpr Result<std::uint8_t> ReadU8(std::size_t offset = 0uz) const noexcept {
    return DecodeU8(data_, offset);
  }
  [[nodiscard]] constexpr Result<std::uint16_t> ReadU16Be(std::size_t offset = 0uz) const noexcept {
    return DecodeU16Be(data_, offset);
  }
  [[nodiscard]] constexpr Result<std::uint32_t> ReadU24Be(std::size_t offset = 0uz) const noexcept {
    return DecodeU24Be(data_, offset);
  }
  [[nodiscard]] constexpr Result<std::uint32_t> ReadU32Be(std::size_t offset = 0uz) const noexcept {
    return DecodeU32Be(data_, offset);
  }
  [[nodiscard]] constexpr Result<std::uint64_t> ReadU64Be(std::size_t offset = 0uz) const noexcept {
    return DecodeU64Be(data_, offset);
  }

  [[nodiscard]] constexpr Result<std::uint8_t> TakeU8() noexcept {
    auto res = ReadU8(0);
    if (res.has_value()) Consume(1);
    return res;
  }
  [[nodiscard]] constexpr Result<std::uint16_t> TakeU16Be() noexcept {
    auto res = ReadU16Be(0);
    if (res.has_value()) Consume(2);
    return res;
  }
  [[nodiscard]] constexpr Result<std::uint32_t> TakeU24Be() noexcept {
    auto res = ReadU24Be(0);
    if (res.has_value()) Consume(3);
    return res;
  }
  [[nodiscard]] constexpr Result<std::uint32_t> TakeU32Be() noexcept {
    auto res = ReadU32Be(0);
    if (res.has_value()) Consume(4);
    return res;
  }
  [[nodiscard]] constexpr Result<std::uint64_t> TakeU64Be() noexcept {
    auto res = ReadU64Be(0);
    if (res.has_value()) Consume(8);
    return res;
  }

  [[nodiscard]] friend constexpr bool operator==(const Bytes& a, const Bytes& b) noexcept {
    return a.data_.size() == b.data_.size() && std::equal(a.data_.begin(), a.data_.end(), b.data_.begin());
  }

 private:
  std::span<const std::uint8_t> data_{};
  std::vector<std::uint8_t> owned_{};
  bool is_owned_{false};
};

template <std::size_t Capacity = 16384>
class BytesMut {
  static_assert(Capacity > 0, "BytesMut capacity must be greater than zero");

 public:
  constexpr BytesMut() noexcept = default;

  [[nodiscard]] static constexpr std::size_t MaxCapacity() noexcept { return Capacity; }

  [[nodiscard]] constexpr std::span<const std::uint8_t> ReadableSpan() const noexcept {
    return {storage_.data() + read_pos_, write_pos_ - read_pos_};
  }

  [[nodiscard]] constexpr Bytes AsBytes() const noexcept { return Bytes(ReadableSpan()); }

  [[nodiscard]] constexpr std::span<std::uint8_t> WritableSpan() noexcept {
    if (read_pos_ == write_pos_) {
      read_pos_ = 0;
      write_pos_ = 0;
    }
    return {storage_.data() + write_pos_, Capacity - write_pos_};
  }

  [[nodiscard]] std::string_view AsStringView() const noexcept {
    const auto sp = ReadableSpan();
    return {static_cast<const char*>(static_cast<const void*>(sp.data())), sp.size()};
  }

  [[nodiscard]] constexpr const std::uint8_t* Data() const noexcept { return storage_.data() + read_pos_; }
  [[nodiscard]] constexpr std::uint8_t* WritableData() noexcept { return WritableSpan().data(); }
  [[nodiscard]] constexpr std::size_t Size() const noexcept { return write_pos_ - read_pos_; }
  [[nodiscard]] constexpr bool Empty() const noexcept { return write_pos_ == read_pos_; }
  [[nodiscard]] constexpr std::size_t CapacityRemaining() const noexcept { return Capacity - Size(); }

  constexpr void Compact() noexcept {
    if (read_pos_ == 0) return;
    const std::size_t readable = Size();
    if (readable > 0) {
      if consteval {
        for (std::size_t i = 0; i < readable; ++i) storage_[i] = storage_[read_pos_ + i];
      } else {
        std::memmove(storage_.data(), storage_.data() + read_pos_, readable);
      }
    }
    read_pos_ = 0;
    write_pos_ = readable;
  }

  [[nodiscard]] constexpr Result<void> CommitWrite(std::size_t n) noexcept {
    if (n > Capacity - write_pos_) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    }
    write_pos_ += n;
    return {};
  }

  constexpr void Consume(std::size_t n) noexcept {
    read_pos_ += std::min(n, Size());
    if (read_pos_ == write_pos_) {
      read_pos_ = 0;
      write_pos_ = 0;
    }
  }

  constexpr void Advance(std::size_t n) noexcept { Consume(n); }

  constexpr void Clear() noexcept {
    read_pos_ = 0;
    write_pos_ = 0;
  }

  [[nodiscard]] constexpr Result<void> Append(std::span<const std::uint8_t> src) noexcept {
    if (src.empty()) return {};
    if (src.size() > CapacityRemaining()) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    }
    if (src.size() > Capacity - write_pos_) Compact();
    if consteval {
      for (std::size_t i = 0; i < src.size(); ++i) storage_[write_pos_ + i] = src[i];
    } else {
      std::memcpy(storage_.data() + write_pos_, src.data(), src.size());
    }
    write_pos_ += src.size();
    return {};
  }

  [[nodiscard]] constexpr Result<void> AppendString(std::string_view sv) noexcept {
    if (sv.empty()) return {};
    if (sv.size() > CapacityRemaining()) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    }
    if (sv.size() > Capacity - write_pos_) Compact();
    if consteval {
      for (std::size_t i = 0uz; i < sv.size(); ++i) {
        storage_[write_pos_ + i] = static_cast<std::uint8_t>(sv[i]);
      }
    } else {
      std::memcpy(storage_.data() + write_pos_, sv.data(), sv.size());
    }
    write_pos_ += sv.size();
    return {};
  }

  [[nodiscard]] constexpr Result<void> PutU8(std::uint8_t v) noexcept {
    const std::array<std::uint8_t, 1> buf{v};
    return Append(buf);
  }
  [[nodiscard]] constexpr Result<void> PutU16Be(std::uint16_t v) noexcept { return Append(detail::EncodeU16Be(v)); }
  [[nodiscard]] constexpr Result<void> PutU24Be(std::uint32_t v) noexcept {
    if (v > 0x00ff'ffffU) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidArgument));
    }
    return Append(detail::EncodeU24Be(v));
  }
  [[nodiscard]] constexpr Result<void> PutU32Be(std::uint32_t v) noexcept { return Append(detail::EncodeU32Be(v)); }
  [[nodiscard]] constexpr Result<void> PutU64Be(std::uint64_t v) noexcept { return Append(detail::EncodeU64Be(v)); }

  [[nodiscard]] constexpr Bytes SplitTo(std::size_t n) noexcept {
    const std::size_t count = std::min(n, Size());
    const Bytes out(ReadableSpan().subspan(0, count));
    read_pos_ += count;
    return out;
  }

  [[nodiscard]] constexpr Bytes Freeze() noexcept {
    const Bytes out(ReadableSpan());
    Clear();
    return out;
  }

  [[nodiscard]] constexpr Result<std::uint8_t> ReadU8(std::size_t offset = 0uz) const noexcept {
    return DecodeU8(ReadableSpan(), offset);
  }
  [[nodiscard]] constexpr Result<std::uint16_t> ReadU16Be(std::size_t offset = 0uz) const noexcept {
    return DecodeU16Be(ReadableSpan(), offset);
  }
  [[nodiscard]] constexpr Result<std::uint32_t> ReadU24Be(std::size_t offset = 0uz) const noexcept {
    return DecodeU24Be(ReadableSpan(), offset);
  }
  [[nodiscard]] constexpr Result<std::uint32_t> ReadU32Be(std::size_t offset = 0uz) const noexcept {
    return DecodeU32Be(ReadableSpan(), offset);
  }
  [[nodiscard]] constexpr Result<std::uint64_t> ReadU64Be(std::size_t offset = 0uz) const noexcept {
    return DecodeU64Be(ReadableSpan(), offset);
  }

 private:
  std::array<std::uint8_t, Capacity> storage_{};
  std::size_t read_pos_{0};
  std::size_t write_pos_{0};
};

class ByteBuffer {
 public:
  explicit ByteBuffer(std::size_t initial_capacity = 16384uz) : storage_(initial_capacity, 0), read_pos_(0), write_pos_(0) {}

  [[nodiscard]] std::span<const std::uint8_t> ReadableSpan() const noexcept {
    return {storage_.data() + read_pos_, write_pos_ - read_pos_};
  }

  [[nodiscard]] Bytes AsBytes() const noexcept { return Bytes(ReadableSpan()); }

  [[nodiscard]] Result<std::span<std::uint8_t>> WritableSpan(std::size_t min_writable = 4096uz) {
    if (auto res = EnsureWritable(min_writable); !res.has_value()) {
      return std::unexpected(res.error());
    }
    return std::span<std::uint8_t>{storage_.data() + write_pos_, storage_.size() - write_pos_};
  }

  [[nodiscard]] std::string_view AsStringView() const noexcept {
    const auto sp = ReadableSpan();
    return {static_cast<const char*>(static_cast<const void*>(sp.data())), sp.size()};
  }

  [[nodiscard]] const std::uint8_t* Data() const noexcept { return storage_.data() + read_pos_; }
  [[nodiscard]] std::size_t Size() const noexcept { return write_pos_ - read_pos_; }
  [[nodiscard]] bool Empty() const noexcept { return write_pos_ == read_pos_; }

  [[nodiscard]] Result<void> Reserve(std::size_t additional) { return EnsureWritable(additional); }

  [[nodiscard]] Result<void> CommitWrite(std::size_t n) noexcept {
    if (n > storage_.size() - write_pos_) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    }
    write_pos_ += n;
    return {};
  }

  void Consume(std::size_t n) noexcept {
    read_pos_ += std::min(n, Size());
    if (read_pos_ == write_pos_) {
      read_pos_ = 0;
      write_pos_ = 0;
    }
  }

  void Advance(std::size_t n) noexcept { Consume(n); }

  void Clear() noexcept {
    read_pos_ = 0;
    write_pos_ = 0;
  }

  [[nodiscard]] Result<void> Append(std::span<const std::uint8_t> src) {
    if (src.empty()) return {};
    if (auto res = EnsureWritable(src.size()); !res.has_value()) return res;
    std::memcpy(storage_.data() + write_pos_, src.data(), src.size());
    write_pos_ += src.size();
    return {};
  }

  [[nodiscard]] Result<void> AppendString(std::string_view sv) {
    if (sv.empty()) return {};
    if (auto res = EnsureWritable(sv.size()); !res.has_value()) return res;
    std::memcpy(storage_.data() + write_pos_, sv.data(), sv.size());
    write_pos_ += sv.size();
    return {};
  }

  [[nodiscard]] Result<void> PutU8(std::uint8_t v) {
    const std::array<std::uint8_t, 1> buf{v};
    return Append(buf);
  }
  [[nodiscard]] Result<void> PutU16Be(std::uint16_t v) { return Append(detail::EncodeU16Be(v)); }
  [[nodiscard]] Result<void> PutU24Be(std::uint32_t v) {
    if (v > 0x00ff'ffffU) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidArgument));
    }
    return Append(detail::EncodeU24Be(v));
  }
  [[nodiscard]] Result<void> PutU32Be(std::uint32_t v) { return Append(detail::EncodeU32Be(v)); }
  [[nodiscard]] Result<void> PutU64Be(std::uint64_t v) { return Append(detail::EncodeU64Be(v)); }

  [[nodiscard]] Bytes SplitTo(std::size_t n) {
    const std::size_t count = std::min(n, Size());
    Bytes out = Bytes::CopyFromSlice(ReadableSpan().subspan(0, count));
    Consume(count);
    return out;
  }

  [[nodiscard]] Bytes Freeze() {
    Bytes out = Bytes::CopyFromSlice(ReadableSpan());
    Clear();
    return out;
  }

 private:
  [[nodiscard]] Result<void> EnsureWritable(std::size_t needed) {
    if (read_pos_ == write_pos_) {
      read_pos_ = 0;
      write_pos_ = 0;
    }
    if (storage_.size() - write_pos_ >= needed) return {};
    const std::size_t readable = Size();
    if (read_pos_ > 0) {
      if (readable > 0) std::memmove(storage_.data(), storage_.data() + read_pos_, readable);
      read_pos_ = 0;
      write_pos_ = readable;
      if (storage_.size() - write_pos_ >= needed) return {};
    }
    const auto min_cap = uarch::checked_add(write_pos_, needed);
    if (!min_cap.has_value()) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    }
    const auto doubled = uarch::checked_mul(storage_.size(), 2uz);
    const std::size_t next_cap = doubled.has_value() ? std::max(*min_cap, *doubled) : *min_cap;
    storage_.resize(next_cap, 0);
    return {};
  }

  std::vector<std::uint8_t> storage_{};
  std::size_t read_pos_{0};
  std::size_t write_pos_{0};
};

}  // namespace nexora
