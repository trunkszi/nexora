/** @file @brief RFC 9113 HTTP/2 frame header and SETTINGS codec. */
#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <nexora/error/proto_error.hpp>
#include <span>
#include <uarch/uarch.hpp>
#include <utility>

namespace nexora {

/** @brief RFC 9113 frame type byte. */
enum class Http2FrameType : std::uint8_t {
  kData = 0x0,
  kHeaders = 0x1,
  kPriority = 0x2,
  kRstStream = 0x3,
  kSettings = 0x4,
  kPushPromise = 0x5,
  kPing = 0x6,
  kGoaway = 0x7,
  kWindowUpdate = 0x8,
  kContinuation = 0x9,
};

/** @brief Flag bits. `kAck` and `kEndStream` share the low bit on different frame types. */
enum class Http2FrameFlags : std::uint8_t {
  kEndStream = 0x1,
  kAck = 0x1,
  kEndHeaders = 0x4,
  kPadded = 0x8,
  kPriorityFlag = 0x20,
};

inline constexpr std::size_t kHttp2FrameHeaderSize = 9;
inline constexpr std::uint32_t kHttp2DefaultMaxFrameSize = 16384;
inline constexpr std::uint32_t kHttp2DefaultWindowSize = 65535;
inline constexpr std::int64_t kHttp2MaxWindow = 0x7fffffff;
inline constexpr std::array<std::uint8_t, 24> kHttp2ClientPreface = {'P',  'R',  'I', ' ', '*',  ' ',  'H',  'T',
                                                                     'T',  'P',  '/', '2', '.',  '0',  '\r', '\n',
                                                                     '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n'};

/** @brief Nine-byte frame header. `length` is the 24-bit payload size. */
struct Http2FrameHeader {
  std::uint32_t length{0};
  Http2FrameType type{Http2FrameType::kData};
  std::uint8_t flags{0};
  std::uint32_t stream_id{0};

  [[nodiscard]] constexpr bool Has(Http2FrameFlags flag) const noexcept { return (flags & std::to_underlying(flag)) != 0; }
};

/** @brief One decoded frame. `payload` aliases the caller's buffer. */
struct Http2Frame {
  Http2FrameHeader header{};
  std::span<const std::uint8_t> payload{};
};

/** @brief RFC 9113 initial SETTINGS values. */
struct Http2Settings {
  std::uint32_t header_table_size{4096};
  std::uint32_t enable_push{1};
  std::uint32_t max_concurrent_streams{0xffffffffu};
  std::uint32_t initial_window_size{kHttp2DefaultWindowSize};
  std::uint32_t max_frame_size{kHttp2DefaultMaxFrameSize};
  std::uint32_t max_header_list_size{0xffffffffu};
};

enum class Http2SettingId : std::uint16_t {
  kHeaderTableSize = 0x1,
  kEnablePush = 0x2,
  kMaxConcurrentStreams = 0x3,
  kInitialWindowSize = 0x4,
  kMaxFrameSize = 0x5,
  kMaxHeaderListSize = 0x6,
};

[[nodiscard]] inline bool FrameFlag(std::uint8_t flags, Http2FrameFlags flag) noexcept {
  return (flags & std::to_underlying(flag)) != 0;
}

[[nodiscard]] static inline std::uint16_t LoadBe16(const std::uint8_t* ptr) noexcept {
  if consteval {
    return static_cast<std::uint16_t>((std::uint16_t{ptr[0]} << 8) | std::uint16_t{ptr[1]});
  } else {
    std::uint16_t word = 0;
    std::memcpy(&word, ptr, sizeof(word));
    if constexpr (std::endian::native == std::endian::little) {
      word = std::byteswap(word);
    }
    return word;
  }
}

[[nodiscard]] static inline std::uint32_t LoadBe32(const std::uint8_t* ptr) noexcept {
  if consteval {
    return (std::uint32_t{ptr[0]} << 24) | (std::uint32_t{ptr[1]} << 16) | (std::uint32_t{ptr[2]} << 8) | std::uint32_t{ptr[3]};
  } else {
    std::uint32_t word = 0;
    std::memcpy(&word, ptr, sizeof(word));
    if constexpr (std::endian::native == std::endian::little) {
      word = std::byteswap(word);
    }
    return word;
  }
}

static inline void StoreBe16(std::uint8_t* ptr, std::uint16_t value) noexcept {
  if consteval {
    ptr[0] = static_cast<std::uint8_t>((value >> 8) & 0xffu);
    ptr[1] = static_cast<std::uint8_t>(value & 0xffu);
  } else {
    if constexpr (std::endian::native == std::endian::little) {
      value = std::byteswap(value);
    }
    std::memcpy(ptr, &value, sizeof(value));
  }
}

static inline void StoreBe32(std::uint8_t* ptr, std::uint32_t value) noexcept {
  if consteval {
    ptr[0] = static_cast<std::uint8_t>((value >> 24) & 0xffu);
    ptr[1] = static_cast<std::uint8_t>((value >> 16) & 0xffu);
    ptr[2] = static_cast<std::uint8_t>((value >> 8) & 0xffu);
    ptr[3] = static_cast<std::uint8_t>(value & 0xffu);
  } else {
    if constexpr (std::endian::native == std::endian::little) {
      value = std::byteswap(value);
    }
    std::memcpy(ptr, &value, sizeof(value));
  }
}

[[nodiscard]] inline Result<Http2FrameHeader> DecodeFrameHeader(std::span<const std::uint8_t> bytes) noexcept {
  if (bytes.size() < kHttp2FrameHeaderSize) return std::unexpected(Error::FromProto(ProtoErrorCode::kIncomplete));
  const auto lead = LoadBe32(bytes.data());
  const auto id = LoadBe32(bytes.data() + 5);
  Http2FrameHeader header{};
  header.length = lead >> 8;
  header.type = static_cast<Http2FrameType>(static_cast<std::uint8_t>(lead & 0xffu));
  header.flags = bytes[4];
  header.stream_id = id & 0x7fffffffu;
  return header;
}

inline void EncodeFrameHeader(const Http2FrameHeader& header, std::span<std::uint8_t, kHttp2FrameHeaderSize> out) noexcept {
  const auto lead = ((header.length & 0x00ffffffu) << 8) | std::uint32_t{std::to_underlying(header.type)};
  StoreBe32(out.data(), lead);
  out[4] = header.flags;
  StoreBe32(out.data() + 5, header.stream_id & 0x7fffffffu);
}

[[nodiscard]] inline Result<Http2Frame> DecodeFrame(std::span<const std::uint8_t> bytes) noexcept {
  auto header = DecodeFrameHeader(bytes);
  if (!header) return std::unexpected(header.error());
  if (bytes.size() < kHttp2FrameHeaderSize + header->length) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kIncomplete));
  }
  return Http2Frame{*header, bytes.subspan(kHttp2FrameHeaderSize, header->length)};
}

[[nodiscard]] inline Result<std::size_t> EncodeFrame(Http2FrameType type, std::uint8_t flags, std::uint32_t stream_id,
                                                     std::span<const std::uint8_t> payload,
                                                     std::span<std::uint8_t> out) noexcept {
  if (payload.size() > 0x00ffffffu) return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2FrameSizeError));
  if (out.size() < kHttp2FrameHeaderSize + payload.size()) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
  }
  Http2FrameHeader header{static_cast<std::uint32_t>(payload.size()), type, flags, stream_id};
  EncodeFrameHeader(header, std::span<std::uint8_t, kHttp2FrameHeaderSize>{out.data(), kHttp2FrameHeaderSize});
  for (std::size_t i = 0; i < payload.size(); ++i) out[kHttp2FrameHeaderSize + i] = payload[i];
  return kHttp2FrameHeaderSize + payload.size();
}

[[nodiscard]] inline Result<Http2Settings> ApplySettingsPayload(Http2Settings base,
                                                                std::span<const std::uint8_t> payload) noexcept {
  if (payload.size() % 6u != 0) return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2FrameSizeError));
  for (std::size_t i = 0; i < payload.size(); i += 6) {
    const auto id = LoadBe16(payload.data() + i);
    const auto value = LoadBe32(payload.data() + i + 2);
    switch (static_cast<Http2SettingId>(id)) {
      case Http2SettingId::kHeaderTableSize:
        base.header_table_size = value;
        break;
      case Http2SettingId::kEnablePush:
        if (value > 1) return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2ProtocolError));
        base.enable_push = value;
        break;
      case Http2SettingId::kMaxConcurrentStreams:
        base.max_concurrent_streams = value;
        break;
      case Http2SettingId::kInitialWindowSize:
        if (value > static_cast<std::uint32_t>(kHttp2MaxWindow)) {
          return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2FlowControlError));
        }
        base.initial_window_size = value;
        break;
      case Http2SettingId::kMaxFrameSize:
        if (value < kHttp2DefaultMaxFrameSize || value > 0x00ffffffu) {
          return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp2ProtocolError));
        }
        base.max_frame_size = value;
        break;
      case Http2SettingId::kMaxHeaderListSize:
        base.max_header_list_size = value;
        break;
      default:
        break;
    }
  }
  return base;
}

[[nodiscard]] inline Result<std::size_t> EncodeSettingsPayload(const Http2Settings& settings,
                                                               std::span<std::uint8_t> out) noexcept {
  constexpr std::array<Http2SettingId, 6> ids{Http2SettingId::kHeaderTableSize,      Http2SettingId::kEnablePush,
                                              Http2SettingId::kMaxConcurrentStreams, Http2SettingId::kInitialWindowSize,
                                              Http2SettingId::kMaxFrameSize,         Http2SettingId::kMaxHeaderListSize};
  const std::array<std::uint32_t, 6> values{settings.header_table_size,      settings.enable_push,
                                            settings.max_concurrent_streams, settings.initial_window_size,
                                            settings.max_frame_size,         settings.max_header_list_size};
  if (out.size() < 36) return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
  for (std::size_t i = 0; i < ids.size(); ++i) {
    const auto o = i * 6;
    StoreBe16(out.data() + o, std::to_underlying(ids[i]));
    StoreBe32(out.data() + o + 2, values[i]);
  }
  return 36;
}

[[nodiscard]] inline std::uint32_t ReadU32(std::span<const std::uint8_t> bytes) noexcept { return LoadBe32(bytes.data()); }

inline void WriteU32(std::span<std::uint8_t> out, std::uint32_t value) noexcept { StoreBe32(out.data(), value); }

}  // namespace nexora
