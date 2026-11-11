/** @file @brief RFC 7541 HPACK encoder and decoder. */
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <nexora/http/headers.hpp>
#include <nexora/http2/huffman.hpp>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace nexora {

inline constexpr std::size_t kHpackStaticSize = 61;

inline constexpr std::array<std::pair<std::string_view, std::string_view>, kHpackStaticSize> kHpackStatic{{
    {":authority", ""},
    {":method", "GET"},
    {":method", "POST"},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "304"},
    {":status", "400"},
    {":status", "404"},
    {":status", "500"},
    {"accept-charset", ""},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", ""},
    {"accept-ranges", ""},
    {"accept", ""},
    {"access-control-allow-origin", ""},
    {"age", ""},
    {"allow", ""},
    {"authorization", ""},
    {"cache-control", ""},
    {"content-disposition", ""},
    {"content-encoding", ""},
    {"content-language", ""},
    {"content-length", ""},
    {"content-location", ""},
    {"content-range", ""},
    {"content-type", ""},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"expect", ""},
    {"expires", ""},
    {"from", ""},
    {"host", ""},
    {"if-match", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"if-range", ""},
    {"if-unmodified-since", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"max-forwards", ""},
    {"proxy-authenticate", ""},
    {"proxy-authorization", ""},
    {"range", ""},
    {"referer", ""},
    {"refresh", ""},
    {"retry-after", ""},
    {"server", ""},
    {"set-cookie", ""},
    {"strict-transport-security", ""},
    {"transfer-encoding", ""},
    {"user-agent", ""},
    {"vary", ""},
    {"via", ""},
    {"www-authenticate", ""},
}};

struct HpackInt {
  std::uint32_t value{0};
  std::size_t used{0};
};

[[nodiscard]] inline Result<std::size_t> HpackWriteInt(std::uint32_t value, std::uint8_t prefix, std::uint8_t flags,
                                                       std::span<std::uint8_t> out) noexcept {
  const auto max = (std::uint32_t{1} << prefix) - 1U;
  if (out.empty()) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
  }
  if (value < max) {
    out[0] = static_cast<std::uint8_t>(flags | static_cast<std::uint8_t>(value));
    return 1U;
  }
  out[0] = static_cast<std::uint8_t>(flags | static_cast<std::uint8_t>(max));
  value -= max;
  std::size_t written = 1;
  while (value >= 128U) {
    if (written >= out.size()) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    }
    out[written++] = static_cast<std::uint8_t>((value & 0x7fU) | 0x80U);
    value >>= 7U;
  }
  if (written >= out.size()) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
  }
  out[written++] = static_cast<std::uint8_t>(value);
  return written;
}

[[nodiscard]] inline Result<HpackInt> HpackReadInt(std::span<const std::uint8_t> in, std::uint8_t prefix) noexcept {
  if (in.empty() || prefix > 8) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2CompressionError));
  }
  const auto max = (std::uint32_t{1} << prefix) - 1U;
  std::uint64_t value = std::uint32_t{in[0]} & max;
  if (value < max) {
    return HpackInt{static_cast<std::uint32_t>(value), 1U};
  }
  std::size_t index = 1;
  std::uint32_t shift = 0;
  while (true) {
    if (index >= in.size() || shift > 28U) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2CompressionError));
    }
    const auto byte = in[index++];
    const auto piece = std::uint64_t{byte & 0x7fU};
    // shift 28 still has 4 bits under 2^32; a wider fragment aliases to a small integer.
    if (shift == 28U && piece > 0x0fU) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2CompressionError));
    }
    const auto add = piece << shift;
    if (value > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()) - add) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2CompressionError));
    }
    value += add;
    if ((byte & 0x80U) == 0) {
      return HpackInt{static_cast<std::uint32_t>(value), index};
    }
    if (shift >= 28U) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2CompressionError));
    }
    shift += 7U;
  }
}

[[nodiscard]] inline bool HpackNeverIndex(std::string_view name) noexcept {
  return name == "authorization" || name == "proxy-authorization" || name == "cookie" || name == "set-cookie";
}

struct HpackFieldView {
  std::string_view name{};
  std::string_view value{};
};

/** @brief Bounded dynamic table. Entry bytes live in a 4096-byte arena, newest first on the wire. */
struct HpackTable {
  static constexpr std::size_t kCap = 128;
  static constexpr std::size_t kArena = 4096;
  static constexpr std::size_t kMaxBytes = kArena;

  struct Ref {
    std::uint16_t name_off{0};
    std::uint16_t name_len{0};
    std::uint16_t value_off{0};
    std::uint16_t value_len{0};
  };

  std::array<Ref, kCap> refs{};
  std::array<std::uint8_t, kArena> arena{};
  std::size_t begin{0};
  std::size_t count{0};
  std::uint16_t tail{0};
  std::uint32_t nbytes{0};
  std::uint32_t limit{4096};

  [[nodiscard]] std::size_t IndexOf(std::size_t from_newest) const noexcept {
    return (begin + count - 1U - from_newest) % kCap;
  }

  [[nodiscard]] std::string_view NameAt(std::size_t from_newest) const noexcept {
    const auto& ref = refs[IndexOf(from_newest)];
    return {reinterpret_cast<const char*>(arena.data() + ref.name_off), ref.name_len};
  }

  [[nodiscard]] std::string_view ValueAt(std::size_t from_newest) const noexcept {
    const auto& ref = refs[IndexOf(from_newest)];
    return {reinterpret_cast<const char*>(arena.data() + ref.value_off), ref.value_len};
  }

  void EvictOldest() noexcept {
    if (count == 0) {
      return;
    }
    const auto& ref = refs[begin];
    const auto size = std::uint32_t{ref.name_len} + ref.value_len + 32U;
    nbytes = nbytes >= size ? nbytes - size : 0U;
    begin = (begin + 1U) % kCap;
    --count;
  }

  void Resize(std::uint32_t next) noexcept {
    limit = next;
    while (count > 0 && nbytes > limit) {
      EvictOldest();
    }
  }

  void Compact() noexcept {
    std::array<std::uint8_t, kArena> fresh{};
    std::uint16_t used = 0;
    for (std::size_t i = 0; i < count; ++i) {
      auto& ref = refs[(begin + i) % kCap];
      for (std::uint16_t j = 0; j < ref.name_len; ++j) {
        fresh[used + j] = arena[ref.name_off + j];
      }
      ref.name_off = used;
      used = static_cast<std::uint16_t>(used + ref.name_len);
      for (std::uint16_t j = 0; j < ref.value_len; ++j) {
        fresh[used + j] = arena[ref.value_off + j];
      }
      ref.value_off = used;
      used = static_cast<std::uint16_t>(used + ref.value_len);
    }
    arena = fresh;
    tail = used;
  }

  void Insert(std::string_view name, std::string_view value) noexcept {
    const auto raw = name.size() + value.size();
    if (raw > 0xffffU) {
      return;
    }
    const auto size = static_cast<std::uint32_t>(raw + 32U);
    if (size > limit) {
      while (count > 0) {
        EvictOldest();
      }
      return;
    }
    while (count > 0 && nbytes + size > limit) {
      EvictOldest();
    }
    if (count == kCap) {
      EvictOldest();
    }
    if (tail + raw > kArena) {
      Compact();
    }
    while (count > 0 && tail + raw > kArena) {
      EvictOldest();
      Compact();
    }
    if (tail + raw > kArena) {
      return;
    }
    Ref ref{};
    ref.name_off = tail;
    ref.name_len = static_cast<std::uint16_t>(name.size());
    for (const char ch : name) {
      arena[tail++] = static_cast<std::uint8_t>(ch);
    }
    ref.value_off = tail;
    ref.value_len = static_cast<std::uint16_t>(value.size());
    for (const char ch : value) {
      arena[tail++] = static_cast<std::uint8_t>(ch);
    }
    refs[(begin + count) % kCap] = ref;
    ++count;
    nbytes += size;
  }

  [[nodiscard]] Result<HpackFieldView> Resolve(std::uint32_t index) const noexcept {
    if (index == 0) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2CompressionError));
    }
    if (index <= kHpackStaticSize) {
      return HpackFieldView{kHpackStatic[index - 1U].first, kHpackStatic[index - 1U].second};
    }
    const auto dyn = index - static_cast<std::uint32_t>(kHpackStaticSize + 1U);
    if (dyn >= count) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2CompressionError));
    }
    return HpackFieldView{NameAt(dyn), ValueAt(dyn)};
  }

  [[nodiscard]] std::uint32_t Find(std::string_view name, std::string_view value, bool exact) const noexcept {
    for (std::size_t i = 0; i < kHpackStaticSize; ++i) {
      if (kHpackStatic[i].first != name) {
        continue;
      }
      if (!exact || kHpackStatic[i].second == value) {
        return static_cast<std::uint32_t>(i + 1U);
      }
    }
    for (std::size_t i = 0; i < count; ++i) {
      if (NameAt(i) == name && (!exact || ValueAt(i) == value)) {
        return static_cast<std::uint32_t>(kHpackStaticSize + 1U + i);
      }
    }
    return 0;
  }
};

[[nodiscard]] inline Result<std::size_t> HpackWriteString(std::string_view value, std::span<std::uint8_t> out) noexcept {
  const auto raw = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(value.data()), value.size());
  const auto huffman = HuffmanEncodedSize(raw);
  // Equal length still uses Huffman so appendix C.6.2 ("307") matches the wire image.
  const bool use_huffman = huffman <= value.size();
  const auto length = static_cast<std::uint32_t>(use_huffman ? huffman : value.size());
  auto prefix = HpackWriteInt(length, 7, use_huffman ? std::uint8_t{0x80} : std::uint8_t{0}, out);
  if (!prefix) {
    return prefix;
  }
  if (use_huffman) {
    auto encoded = HuffmanEncode(raw, out.subspan(*prefix));
    if (!encoded) {
      return encoded;
    }
    return *prefix + *encoded;
  }
  if (out.size() < *prefix + value.size()) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
  }
  for (std::size_t i = 0; i < value.size(); ++i) {
    out[*prefix + i] = static_cast<std::uint8_t>(value[i]);
  }
  return *prefix + value.size();
}

template <std::size_t InlineCap, std::size_t MaxCap>
[[nodiscard]] inline Result<std::size_t> HpackDecodeInto(std::span<const std::uint8_t> in, HeaderText<InlineCap, MaxCap>& dst,
                                                         std::span<std::uint8_t> scratch) noexcept {
  if (in.empty()) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2CompressionError));
  }
  const bool huffman = (in[0] & 0x80U) != 0;
  auto length = HpackReadInt(in, 7);
  if (!length) {
    return std::unexpected(length.error());
  }
  if (length->value > 65536U || in.size() < length->used + length->value) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2CompressionError));
  }
  const std::size_t used = length->used + length->value;
  const auto bytes = in.subspan(length->used, length->value);
  if (!huffman) {
    if (!dst.TryAssign(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()))) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    }
    return used;
  }
  const auto limit = std::min<std::size_t>(scratch.size(), MaxCap);
  auto size = HuffmanDecode(bytes, scratch.first(limit));
  if (!size) {
    return std::unexpected(size.error());
  }
  if (!dst.TryAssign(std::string_view(reinterpret_cast<const char*>(scratch.data()), *size))) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
  }
  return used;
}

/** @brief RFC 7541 encoder. Emits a dynamic-table size update before the next block when the peer limit changes. */
class HpackEncoder {
 public:
  explicit HpackEncoder(std::uint32_t table_size = 4096) noexcept {
    const auto clamped = table_size > static_cast<std::uint32_t>(HpackTable::kMaxBytes)
                             ? static_cast<std::uint32_t>(HpackTable::kMaxBytes)
                             : table_size;
    table_.Resize(clamped);
    signaled_ = clamped;
  }

  /** @brief Peer SETTINGS above the arena are clamped and that clamped size is what we signal. */
  void SetMaxTableSize(std::size_t peer_max) noexcept {
    const auto clamped = static_cast<std::uint32_t>(std::min(peer_max, HpackTable::kMaxBytes));
    table_.Resize(clamped);
    if (clamped == signaled_ && pending_n_ == 0) {
      return;
    }
    if (pending_n_ > 0 && pending_[pending_n_ - 1U] == clamped) {
      return;
    }
    if (pending_n_ == pending_.size()) {
      pending_[pending_n_ - 1U] = clamped;
      return;
    }
    pending_[pending_n_++] = clamped;
  }

  [[nodiscard]] Result<std::size_t> Encode(std::span<const HeaderField> fields, std::span<std::uint8_t> out) noexcept {
    std::size_t used = 0;
    for (std::uint8_t i = 0; i < pending_n_; ++i) {
      auto wrote = HpackWriteInt(pending_[i], 5, std::uint8_t{0x20}, out.subspan(used));
      if (!wrote) {
        return wrote;
      }
      used += *wrote;
    }
    if (pending_n_ > 0) {
      signaled_ = pending_[pending_n_ - 1U];
    }
    pending_n_ = 0;
    for (const auto& field : fields) {
      const std::string_view name = field.name;
      const std::string_view value = field.value;
      if (name.empty()) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2CompressionError));
      }
      if (const auto exact = table_.Find(name, value, true); exact != 0) {
        auto wrote = HpackWriteInt(exact, 7, std::uint8_t{0x80}, out.subspan(used));
        if (!wrote) {
          return wrote;
        }
        used += *wrote;
        continue;
      }
      const bool never = HpackNeverIndex(name);
      const auto name_index = table_.Find(name, value, false);
      const std::uint8_t prefix = never ? std::uint8_t{4} : std::uint8_t{6};
      const std::uint8_t flags = never ? std::uint8_t{0x10} : std::uint8_t{0x40};
      auto wrote = HpackWriteInt(name_index, prefix, flags, out.subspan(used));
      if (!wrote) {
        return wrote;
      }
      used += *wrote;
      if (name_index == 0) {
        auto name_bytes = HpackWriteString(name, out.subspan(used));
        if (!name_bytes) {
          return name_bytes;
        }
        used += *name_bytes;
      }
      auto value_bytes = HpackWriteString(value, out.subspan(used));
      if (!value_bytes) {
        return value_bytes;
      }
      used += *value_bytes;
      if (!never) {
        table_.Insert(name, value);
      }
    }
    return used;
  }

 private:
  HpackTable table_{};
  std::array<std::uint32_t, 4> pending_{};
  std::uint32_t signaled_{4096};
  std::uint8_t pending_n_{0};
};

/** @brief RFC 7541 decoder. `max_table_size` is the largest size update this peer may send. */
class HpackDecoder {
 public:
  explicit HpackDecoder(std::uint32_t max_table_size = 4096) noexcept
      : max_allowed_(max_table_size < static_cast<std::uint32_t>(HpackTable::kMaxBytes)
                         ? max_table_size
                         : static_cast<std::uint32_t>(HpackTable::kMaxBytes)) {
    table_.Resize(max_allowed_);
  }

  [[nodiscard]] Result<std::size_t> Decode(std::span<const std::uint8_t> block, std::span<HeaderField> out) noexcept {
    std::size_t pos = 0;
    std::size_t count = 0;
    bool saw_field = false;
    while (pos < block.size()) {
      const auto lead = block[pos];
      if ((lead & 0xe0U) == 0x20U) {
        if (saw_field) {
          return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2CompressionError));
        }
        auto update = HpackReadInt(block.subspan(pos), 5);
        if (!update || update->value > max_allowed_) {
          return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2CompressionError));
        }
        table_.Resize(update->value);
        pos += update->used;
        continue;
      }
      saw_field = true;
      if (count >= out.size()) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
      }
      if ((lead & 0x80U) != 0) {
        auto index = HpackReadInt(block.subspan(pos), 7);
        if (!index) {
          return std::unexpected(index.error());
        }
        auto field = table_.Resolve(index->value);
        if (!field) {
          return std::unexpected(field.error());
        }
        if (!out[count].name.TryAssign(field->name) || !out[count].value.TryAssign(field->value)) {
          return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
        }
        ++count;
        pos += index->used;
        continue;
      }
      const bool incremental = (lead & 0x40U) != 0;
      const std::uint8_t prefix = incremental ? std::uint8_t{6} : std::uint8_t{4};
      auto index = HpackReadInt(block.subspan(pos), prefix);
      if (!index) {
        return std::unexpected(index.error());
      }
      pos += index->used;
      if (index->value == 0) {
        if (pos > block.size()) {
          return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2CompressionError));
        }
        auto name_used = HpackDecodeInto(block.subspan(pos), out[count].name, scratch_);
        if (!name_used) {
          return std::unexpected(name_used.error());
        }
        pos += *name_used;
      } else {
        auto field = table_.Resolve(index->value);
        if (!field) {
          return std::unexpected(field.error());
        }
        if (!out[count].name.TryAssign(field->name)) {
          return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
        }
      }
      auto value_used = HpackDecodeInto(block.subspan(pos), out[count].value, scratch_);
      if (!value_used) {
        return std::unexpected(value_used.error());
      }
      pos += *value_used;
      if (out[count].name.empty()) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2CompressionError));
      }
      if (incremental) {
        table_.Insert(out[count].name, out[count].value);
      }
      ++count;
    }
    return count;
  }

 private:
  HpackTable table_{};
  std::array<std::uint8_t, HeaderValueText::Capacity()> scratch_{};
  std::uint32_t max_allowed_;
};

}  // namespace nexora
