#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <nexora/bytes/bytes.hpp>
#include <nexora/error/proto_error.hpp>
#include <nexora/websocket/utf8.hpp>
#include <optional>
#include <span>

namespace nexora {

enum class WebSocketRole : std::uint8_t { kClient = 0, kServer = 1 };

enum class WebSocketOpcode : std::uint8_t {
  kContinuation = 0x0,
  kText = 0x1,
  kBinary = 0x2,
  kClose = 0x8,
  kPing = 0x9,
  kPong = 0xA,
};

enum class WebSocketMessageKind : std::uint8_t { kText = 1, kBinary = 2, kPing = 9, kPong = 10, kClose = 8 };

struct WebSocketHeaderWord {
  std::uint64_t raw{0};

  [[nodiscard]] static constexpr WebSocketHeaderWord ForFrame(bool fin, std::uint8_t opcode, bool masked,
                                                              std::uint8_t length) noexcept {
    auto value = static_cast<std::uint64_t>(opcode & 0x0fU);
    if (fin) {
      value |= 1ULL << 7U;
    }
    value |= static_cast<std::uint64_t>(length & 0x7fU) << 8U;
    if (masked) {
      value |= 1ULL << 15U;
    }
    return WebSocketHeaderWord{value};
  }

  [[nodiscard]] constexpr bool Fin() const noexcept { return (raw & (1ULL << 7U)) != 0; }
  [[nodiscard]] constexpr std::uint8_t OpcodeRaw() const noexcept { return static_cast<std::uint8_t>(raw & 0x0fU); }
  [[nodiscard]] constexpr bool Masked() const noexcept { return (raw & (1ULL << 15U)) != 0; }
  [[nodiscard]] constexpr std::uint8_t ShortLength() const noexcept { return static_cast<std::uint8_t>((raw >> 8U) & 0x7fU); }
  [[nodiscard]] constexpr bool ReservedClear() const noexcept {
    return (raw & ((1ULL << 4U) | (1ULL << 5U) | (1ULL << 6U))) == 0;
  }
};

struct WebSocketFrame {
  bool fin{true};
  WebSocketOpcode opcode{WebSocketOpcode::kBinary};
  Bytes payload{};
};

struct WebSocketMessage {
  WebSocketMessageKind kind{WebSocketMessageKind::kBinary};
  Bytes payload{};
  std::optional<std::uint16_t> close_code{};
};

struct WebSocketDecoded {
  std::size_t consumed{0};
  std::optional<WebSocketMessage> message{};
};

[[nodiscard]] constexpr bool WebSocketIsControl(WebSocketOpcode opcode) noexcept {
  return opcode == WebSocketOpcode::kClose || opcode == WebSocketOpcode::kPing || opcode == WebSocketOpcode::kPong;
}

static_assert(std::endian::native == std::endian::little, "WebSocket mask register shift requires little-endian byte order");

[[gnu::always_inline]] inline void ApplyWebSocketMask(std::span<std::uint8_t> payload,
                                                      std::array<std::uint8_t, 4> mask) noexcept {
  const auto key32 = std::bit_cast<std::uint32_t>(mask);
  const auto key64 = std::uint64_t{key32} | (std::uint64_t{key32} << 32U);
  std::uint8_t* data = payload.data();
  const std::size_t size = payload.size();
  std::size_t offset = 0;
  while (offset + 32 <= size) {
    std::uint64_t block0;
    std::uint64_t block1;
    std::uint64_t block2;
    std::uint64_t block3;
    std::memcpy(&block0, data + offset, sizeof(block0));
    std::memcpy(&block1, data + offset + 8, sizeof(block1));
    std::memcpy(&block2, data + offset + 16, sizeof(block2));
    std::memcpy(&block3, data + offset + 24, sizeof(block3));
    block0 ^= key64;
    block1 ^= key64;
    block2 ^= key64;
    block3 ^= key64;
    std::memcpy(data + offset, &block0, sizeof(block0));
    std::memcpy(data + offset + 8, &block1, sizeof(block1));
    std::memcpy(data + offset + 16, &block2, sizeof(block2));
    std::memcpy(data + offset + 24, &block3, sizeof(block3));
    offset += 32;
  }
  while (offset + 8 <= size) {
    std::uint64_t block;
    std::memcpy(&block, data + offset, sizeof(block));
    block ^= key64;
    std::memcpy(data + offset, &block, sizeof(block));
    offset += 8;
  }
  for (std::size_t i = 0; offset + i < size; ++i) {
    data[offset + i] = static_cast<std::uint8_t>(data[offset + i] ^ static_cast<std::uint8_t>(key32 >> ((i & 3U) * 8U)));
  }
}

inline void ApplyMaskSwar(std::span<std::uint8_t> payload, std::array<std::uint8_t, 4> mask) noexcept {
  ApplyWebSocketMask(payload, mask);
}

namespace ws_detail {

[[nodiscard]] inline Result<WebSocketOpcode> ParseOpcode(std::uint8_t raw) noexcept {
  switch (raw) {
    case 0x0:
      return WebSocketOpcode::kContinuation;
    case 0x1:
      return WebSocketOpcode::kText;
    case 0x2:
      return WebSocketOpcode::kBinary;
    case 0x8:
      return WebSocketOpcode::kClose;
    case 0x9:
      return WebSocketOpcode::kPing;
    case 0xA:
      return WebSocketOpcode::kPong;
    default:
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
  }
}

template <typename Uint>
[[nodiscard]] constexpr Uint WireBigEndian(Uint value) noexcept {
  if constexpr (std::endian::native == std::endian::little) {
    return std::byteswap(value);
  } else {
    return value;
  }
}

[[nodiscard]] inline Result<std::uint16_t> ValidateCloseCode(std::uint16_t code) noexcept {
  const bool known = code == 1000 || code == 1001 || code == 1002 || code == 1003 || code == 1007 || code == 1008 ||
                     code == 1009 || code == 1010 || code == 1011 || (code >= 1012 && code <= 1014) ||
                     (code >= 3000 && code <= 4999);
  if (code == 1005 || code == 1006 || !known) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
  }
  return code;
}

[[nodiscard]] inline Result<std::optional<std::uint16_t>> ParseClose(std::span<const std::uint8_t> payload) noexcept {
  if (payload.empty()) {
    return std::optional<std::uint16_t>{};
  }
  if (payload.size() == 1 || payload.size() > 125) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
  }
  std::uint16_t wire{};
  std::memcpy(&wire, payload.data(), sizeof(wire));
  const auto code = WireBigEndian(wire);
  auto valid = ValidateCloseCode(code);
  if (!valid.has_value()) {
    return std::unexpected(valid.error());
  }
  auto utf8 = ClassifyUtf8(payload.subspan(2));
  if (!utf8.ok) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketInvalidUtf8));
  }
  return std::optional<std::uint16_t>(code);
}

}  // namespace ws_detail

}  // namespace nexora
