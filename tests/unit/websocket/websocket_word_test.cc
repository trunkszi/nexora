#include <array>
#include <bit>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <nexora/websocket/codec.hpp>
#include <utility>

namespace {

int g_fails = 0;

void Check(bool ok, const char* message) {
  if (!ok) {
    std::fprintf(stderr, "FAIL %s\n", message);
    ++g_fails;
  }
}

bool Proto(const nexora::Error& err, nexora::ProtoErrorCode code) {
  return err.domain == nexora::ErrorDomain::kProto && err.code == static_cast<std::int32_t>(std::to_underlying(code));
}

void TestHeaderWord() {
  const auto binary = nexora::WebSocketHeaderWord::ForFrame(true, 0x2, false, 126);
  Check(binary.raw == 0x7e82ULL, "fin binary length word");
  Check(binary.Fin() && binary.OpcodeRaw() == 0x2 && !binary.Masked() && binary.ShortLength() == 126, "binary fields");
  const auto cont = nexora::WebSocketHeaderWord::ForFrame(false, 0x0, true, 127);
  Check(cont.raw == 0xff00ULL, "masked continuation word");
  Check(!cont.Fin() && cont.Masked() && cont.ShortLength() == 127 && cont.ReservedClear(), "cont fields");
  for (std::uint64_t reserved : {0x10ULL, 0x20ULL, 0x40ULL}) {
    const nexora::WebSocketHeaderWord word{0xff00ULL | reserved};
    Check(!word.ReservedClear(), "rsv set");
    Check(word.ShortLength() == 127 && word.Masked(), "rsv keeps length and mask");
  }
}

void TestMaskTails() {
  const std::array<std::uint8_t, 4> mask{0x37, 0xfa, 0x21, 0x3d};
  std::array<std::uint8_t, 5> hello{'H', 'e', 'l', 'l', 'o'};
  nexora::ApplyWebSocketMask(hello, mask);
  constexpr std::array<std::uint8_t, 5> expect{0x7f, 0x9f, 0x4d, 0x51, 0x58};
  Check(std::memcmp(hello.data(), expect.data(), expect.size()) == 0, "rfc mask hello");
  nexora::ApplyMaskSwar(hello, mask);
  Check(hello[0] == 'H' && hello[4] == 'o', "mask alias round trip");

  for (std::size_t offset = 0; offset < 8; ++offset) {
    for (std::size_t len = 0; len < 80; ++len) {
      std::array<std::uint8_t, 96> bytes{};
      for (auto& byte : bytes) {
        byte = 0x5a;
      }
      nexora::ApplyWebSocketMask(std::span<std::uint8_t>(bytes.data() + offset, len), mask);
      bool ok = true;
      for (std::size_t i = 0; i < len; ++i) {
        const auto mixed = static_cast<std::uint8_t>(0x5a ^ mask[i & 3U]);
        if (bytes[offset + i] != mixed) {
          ok = false;
        }
      }
      nexora::ApplyWebSocketMask(std::span<std::uint8_t>(bytes.data() + offset, len), mask);
      for (std::uint8_t byte : bytes) {
        if (byte != 0x5a) {
          ok = false;
        }
      }
      if (!ok) {
        Check(false, "unaligned mask");
        return;
      }
    }
  }
}

nexora::Bytes Fill(std::size_t length, std::uint8_t marker) {
  nexora::BytesMut<70000> raw;
  std::array<std::uint8_t, 1024> chunk{};
  for (auto& byte : chunk) {
    byte = marker;
  }
  std::size_t filled = 0;
  while (filled < length) {
    const std::size_t take = length - filled < chunk.size() ? length - filled : chunk.size();
    Check(raw.Append(std::span<const std::uint8_t>(chunk.data(), take)).has_value(), "fill payload");
    filled += take;
  }
  return nexora::Bytes::CopyFromSlice(raw.ReadableSpan());
}

void TestLengthRoundTrip(std::size_t length, std::uint8_t short_len) {
  nexora::WebSocketCodec<70000> server = nexora::WebSocketCodec<70000>::Server();
  nexora::WebSocketCodec<70000> client = nexora::WebSocketCodec<70000>::Client();
  nexora::WebSocketFrame frame;
  frame.fin = true;
  frame.opcode = nexora::WebSocketOpcode::kBinary;
  frame.payload = Fill(length, 0x5a);
  auto wire = server.EncodeFrame(frame);
  Check(wire.has_value(), "encode length");
  if (!wire.has_value()) {
    return;
  }
  const auto bytes = wire->ReadableSpan();
  Check(bytes.size() >= 2 && bytes[1] == short_len, "length code");
  if (short_len == 126) {
    std::uint16_t wire16{};
    std::memcpy(&wire16, bytes.data() + 2, sizeof(wire16));
    Check(std::byteswap(wire16) == length, "16-bit length");
  } else if (short_len == 127) {
    std::uint64_t wire64{};
    std::memcpy(&wire64, bytes.data() + 2, sizeof(wire64));
    Check(std::byteswap(wire64) == length, "64-bit length");
  }
  auto seen = client.DecodeMessage(bytes);
  Check(seen.has_value() && seen->message.has_value(), "decode length");
  if (!(seen.has_value() && seen->message.has_value())) {
    return;
  }
  const auto payload = seen->message->payload.Span();
  bool same = payload.size() == length;
  for (std::uint8_t byte : payload) {
    if (byte != 0x5a) {
      same = false;
    }
  }
  Check(same, "length payload");
}

void ExpectReject(std::span<const std::uint8_t> frame, nexora::ProtoErrorCode code, const char* name) {
  auto server = nexora::WebSocketCodec<>::Server();
  auto seen = server.DecodeMessage(frame);
  Check(!seen.has_value() && Proto(seen.error(), code), name);
}

void TestLengthCoding() {
  constexpr std::array<std::uint8_t, 4> short_len{0x82, 0xfe, 0x00, 0x01};
  ExpectReject(short_len, nexora::ProtoErrorCode::kWebSocketProtocolError, "noncanonical 16-bit length");
  constexpr std::array<std::uint8_t, 4> below126{0x82, 0xfe, 0x00, 0x7d};
  ExpectReject(below126, nexora::ProtoErrorCode::kWebSocketProtocolError, "16-bit length below 126");
  constexpr std::array<std::uint8_t, 10> wide126{0x82, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e};
  ExpectReject(wide126, nexora::ProtoErrorCode::kWebSocketProtocolError, "64-bit length 126");
  constexpr std::array<std::uint8_t, 10> wide65535{0x82, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
  ExpectReject(wide65535, nexora::ProtoErrorCode::kWebSocketProtocolError, "64-bit length 65535");
  constexpr std::array<std::uint8_t, 10> too_big{0x82, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
  ExpectReject(too_big, nexora::ProtoErrorCode::kWebSocketPayloadTooLarge, "64-bit length above max");
  constexpr std::array<std::uint8_t, 10> wide{0x82, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 1};
  ExpectReject(wide, nexora::ProtoErrorCode::kWebSocketProtocolError, "msb length rejected");
  TestLengthRoundTrip(125, 125);
  TestLengthRoundTrip(126, 126);
  TestLengthRoundTrip(65535, 126);
  TestLengthRoundTrip(65536, 127);
}

}  // namespace

int main() {
  TestHeaderWord();
  TestMaskTails();
  TestLengthCoding();
  return g_fails == 0 ? 0 : 1;
}
