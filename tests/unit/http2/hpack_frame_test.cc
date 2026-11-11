#include <array>
#include <cstdio>
#include <cstring>
#include <nexora/http2/frame.hpp>
#include <nexora/http2/hpack.hpp>
#include <string_view>
#include <vector>

namespace {

int Fail(int line) {
  std::printf("fail line %d\n", line);
  return line;
}

bool Same(std::span<const std::uint8_t> got, std::span<const std::uint8_t> expect) {
  return got.size() == expect.size() && std::memcmp(got.data(), expect.data(), got.size()) == 0;
}

std::vector<std::uint8_t> Hex(std::string_view text) {
  std::vector<std::uint8_t> out;
  int high = -1;
  for (const char ch : text) {
    int nibble = -1;
    if (ch >= '0' && ch <= '9')
      nibble = ch - '0';
    else if (ch >= 'a' && ch <= 'f')
      nibble = ch - 'a' + 10;
    else if (ch >= 'A' && ch <= 'F')
      nibble = ch - 'A' + 10;
    if (nibble < 0) continue;
    if (high < 0)
      high = nibble;
    else {
      out.push_back(static_cast<std::uint8_t>((high << 4) | nibble));
      high = -1;
    }
  }
  return out;
}

nexora::HeaderField Field(const char* name, const char* value) {
  nexora::HeaderField field;
  if (!field.name.TryAssign(name) || !field.value.TryAssign(value)) {
    std::printf("field assign failed\n");
  }
  return field;
}

int FrameRoundTrip() {
  constexpr std::array<std::uint8_t, 5> payload{1, 2, 3, 4, 5};
  std::array<std::uint8_t, 32> bytes{};
  auto size = nexora::EncodeFrame(nexora::Http2FrameType::kData, 0x1, 7, payload, bytes);
  if (!size || *size != 14) return Fail(__LINE__);
  auto frame = nexora::DecodeFrame(std::span<const std::uint8_t>(bytes.data(), *size));
  if (!frame || frame->header.stream_id != 7 || frame->header.length != 5) return Fail(__LINE__);
  if (!frame->header.Has(nexora::Http2FrameFlags::kEndStream)) return Fail(__LINE__);
  if (std::memcmp(frame->payload.data(), payload.data(), payload.size()) != 0) return Fail(__LINE__);
  if (nexora::DecodeFrame(std::span<const std::uint8_t>(bytes.data(), 8))) return Fail(__LINE__);
  return 0;
}

int SettingsBounds() {
  nexora::Http2Settings settings{};
  std::array<std::uint8_t, 36> payload{};
  settings.enable_push = 2;
  auto size = nexora::EncodeSettingsPayload(settings, payload);
  if (!size) return Fail(__LINE__);
  if (nexora::ApplySettingsPayload({}, std::span<const std::uint8_t>(payload.data(), *size))) return Fail(__LINE__);
  settings.enable_push = 1;
  settings.initial_window_size = 0x80000000U;
  size = nexora::EncodeSettingsPayload(settings, payload);
  if (!size || nexora::ApplySettingsPayload({}, std::span<const std::uint8_t>(payload.data(), *size))) return Fail(__LINE__);
  settings.initial_window_size = 0;
  settings.max_frame_size = 16384;
  size = nexora::EncodeSettingsPayload(settings, payload);
  auto applied = nexora::ApplySettingsPayload({}, std::span<const std::uint8_t>(payload.data(), *size));
  if (!applied || applied->initial_window_size != 0) return Fail(__LINE__);
  return 0;
}

int HuffmanVector() {
  const auto raw = std::string_view{"www.example.com"};
  constexpr std::array<std::uint8_t, 12> expect{0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
  const auto bytes = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(raw.data()), raw.size());
  if (nexora::HuffmanEncodedSize(bytes) != expect.size()) return Fail(__LINE__);
  std::array<std::uint8_t, 32> encoded{};
  auto size = nexora::HuffmanEncode(bytes, encoded);
  if (!size || !Same(std::span<const std::uint8_t>(encoded.data(), *size), expect)) return Fail(__LINE__);
  std::array<std::uint8_t, 32> decoded{};
  auto back = nexora::HuffmanDecode(std::span<const std::uint8_t>(encoded.data(), *size), decoded);
  if (!back || *back != raw.size() || std::memcmp(decoded.data(), raw.data(), raw.size()) != 0) return Fail(__LINE__);
  constexpr std::array<std::uint8_t, 4> eos{0xff, 0xff, 0xff, 0xff};
  if (nexora::HuffmanDecode(eos, decoded)) return Fail(__LINE__);
  encoded[*size - 1] = 0;
  if (nexora::HuffmanDecode(std::span<const std::uint8_t>(encoded.data(), *size), decoded)) return Fail(__LINE__);
  return 0;
}

int HuffmanAllBytes() {
  std::array<std::uint8_t, 256> raw{};
  for (std::size_t i = 0; i < raw.size(); ++i) raw[i] = static_cast<std::uint8_t>(i);
  std::array<std::uint8_t, 2048> encoded{};
  auto size = nexora::HuffmanEncode(raw, encoded);
  std::array<std::uint8_t, 256> decoded{};
  auto back = size ? nexora::HuffmanDecode(std::span<const std::uint8_t>(encoded.data(), *size), decoded) : size;
  if (!back || *back != 256 || std::memcmp(decoded.data(), raw.data(), raw.size()) != 0) return Fail(__LINE__);
  return 0;
}

int HpackIntHighBit() {
  constexpr std::array<std::uint8_t, 6> overflow{0xff, 0x80, 0x80, 0x80, 0x80, 0x10};
  if (nexora::HpackReadInt(overflow, 7)) return Fail(__LINE__);
  constexpr std::array<std::uint8_t, 2> small{0xff, 0x00};
  auto value = nexora::HpackReadInt(small, 7);
  if (!value || value->value != 127 || value->used != 2) return Fail(__LINE__);
  return 0;
}

int DecodeEq(nexora::HpackDecoder& decoder, std::span<const std::uint8_t> block,
             std::initializer_list<std::pair<const char*, const char*>> want) {
  std::array<nexora::HeaderField, 8> got{};
  auto count = decoder.Decode(block, got);
  if (!count || *count != want.size()) return Fail(__LINE__);
  std::size_t index = 0;
  for (const auto& item : want) {
    if (got[index].name != item.first || got[index].value != item.second) return Fail(__LINE__);
    ++index;
  }
  return 0;
}

int EncodeEq(nexora::HpackEncoder& encoder, std::span<const nexora::HeaderField> fields, std::span<const std::uint8_t> expect) {
  std::array<std::uint8_t, 256> out{};
  auto size = encoder.Encode(fields, out);
  if (!size || !Same(std::span<const std::uint8_t>(out.data(), *size), expect)) return Fail(__LINE__);
  return 0;
}

int AppendixRequests() {
  const auto c31 = Hex("828684410f7777772e6578616d706c652e636f6d");
  const auto c32 = Hex("828684be58086e6f2d6361636865");
  const auto c33 = Hex("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565");
  const auto c41 = Hex("828684418cf1e3c2e5f23a6ba0ab90f4ff");
  const auto c42 = Hex("828684be5886a8eb10649cbf");
  const auto c43 = Hex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf");
  nexora::HpackDecoder plain;
  if (const int line =
          DecodeEq(plain, c31, {{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"}}))
    return line;
  if (const int line = DecodeEq(plain, c32,
                                {{":method", "GET"},
                                 {":scheme", "http"},
                                 {":path", "/"},
                                 {":authority", "www.example.com"},
                                 {"cache-control", "no-cache"}}))
    return line;
  if (const int line = DecodeEq(plain, c33,
                                {{":method", "GET"},
                                 {":scheme", "https"},
                                 {":path", "/index.html"},
                                 {":authority", "www.example.com"},
                                 {"custom-key", "custom-value"}}))
    return line;
  const auto first = std::array{Field(":method", "GET"), Field(":scheme", "http"), Field(":path", "/"),
                                Field(":authority", "www.example.com")};
  const auto second = std::array{Field(":method", "GET"), Field(":scheme", "http"), Field(":path", "/"),
                                 Field(":authority", "www.example.com"), Field("cache-control", "no-cache")};
  const auto third = std::array{Field(":method", "GET"), Field(":scheme", "https"), Field(":path", "/index.html"),
                                Field(":authority", "www.example.com"), Field("custom-key", "custom-value")};
  nexora::HpackEncoder encoder;
  if (const int line = EncodeEq(encoder, first, c41)) return line;
  if (const int line = EncodeEq(encoder, second, c42)) return line;
  if (const int line = EncodeEq(encoder, third, c43)) return line;
  encoder.SetMaxTableSize(0);
  std::array<std::uint8_t, 64> blocked{};
  auto size = encoder.Encode(std::span<const nexora::HeaderField>(first.data(), 1), blocked);
  if (!size || blocked[0] != 0x20) return Fail(__LINE__);
  return 0;
}

int AppendixResponses() {
  const auto c51 = Hex(
      "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e"
      "6578616d706c652e636f6d");
  const auto c52 = Hex("4803333037c1c0bf");
  const auto c53 = Hex(
      "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f51"
      "57454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31");
  const auto c61 =
      Hex("488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3");
  const auto c62 = Hex("4883640effc1c0bf");
  const auto c63 = Hex(
      "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab"
      "270fb5291f9587316065c003ed4ee5b1063d5007");
  const char* date = "Mon, 21 Oct 2013 20:13:21 GMT";
  const char* date2 = "Mon, 21 Oct 2013 20:13:22 GMT";
  const char* location = "https://www.example.com";
  const char* cookie = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1";
  nexora::HpackDecoder plain(256);
  if (const int line =
          DecodeEq(plain, c51, {{":status", "302"}, {"cache-control", "private"}, {"date", date}, {"location", location}}))
    return line;
  if (const int line =
          DecodeEq(plain, c52, {{":status", "307"}, {"cache-control", "private"}, {"date", date}, {"location", location}}))
    return line;
  if (const int line = DecodeEq(plain, c53,
                                {{":status", "200"},
                                 {"cache-control", "private"},
                                 {"date", date2},
                                 {"location", location},
                                 {"content-encoding", "gzip"},
                                 {"set-cookie", cookie}}))
    return line;
  const auto first =
      std::array{Field(":status", "302"), Field("cache-control", "private"), Field("date", date), Field("location", location)};
  const auto second =
      std::array{Field(":status", "307"), Field("cache-control", "private"), Field("date", date), Field("location", location)};
  nexora::HpackEncoder encoder(256);
  if (const int line = EncodeEq(encoder, first, c61)) return line;
  if (const int line = EncodeEq(encoder, second, c62)) return line;
  nexora::HpackDecoder huff(256);
  if (const int line =
          DecodeEq(huff, c61, {{":status", "302"}, {"cache-control", "private"}, {"date", date}, {"location", location}}))
    return line;
  if (const int line =
          DecodeEq(huff, c62, {{":status", "307"}, {"cache-control", "private"}, {"date", date}, {"location", location}}))
    return line;
  if (const int line = DecodeEq(huff, c63,
                                {{":status", "200"},
                                 {"cache-control", "private"},
                                 {"date", date2},
                                 {"location", location},
                                 {"content-encoding", "gzip"},
                                 {"set-cookie", cookie}}))
    return line;
  return 0;
}

int TableSizeClamp() {
  nexora::HpackEncoder encoder;
  encoder.SetMaxTableSize(65536);
  std::array<nexora::HeaderField, 20> fields{};
  const auto value = std::string(180, 'b');
  for (std::size_t i = 0; i < fields.size(); ++i) {
    auto text = value;
    text.push_back(static_cast<char>('A' + static_cast<int>(i)));
    if (!fields[i].name.TryAssign("n") || !fields[i].value.TryAssign(text)) return Fail(__LINE__);
  }
  std::vector<std::uint8_t> block(8192);
  auto size = encoder.Encode(fields, block);
  if (!size || (block[0] & 0xe0) == 0x20) return Fail(__LINE__);
  std::array<std::uint8_t, 64> again{};
  auto indexed = encoder.Encode(std::span<const nexora::HeaderField>(fields.data() + 19, 1), again);
  if (!indexed || *indexed != 1 || again[0] != 0xbe) return Fail(__LINE__);
  nexora::HpackDecoder decoder(65536);
  std::array<nexora::HeaderField, 20> got{};
  auto count = decoder.Decode(std::span<const std::uint8_t>(block.data(), *size), got);
  if (!count || *count != 20 || got[19].value != fields[19].value) return Fail(__LINE__);
  auto follow = decoder.Decode(std::span<const std::uint8_t>(again.data(), *indexed), got);
  if (!follow || *follow != 1 || got[0].value != fields[19].value) return Fail(__LINE__);
  return 0;
}

int HpackStaticAndDynamic() {
  constexpr std::array<std::uint8_t, 17> expect{0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5,
                                                0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
  const auto first = std::array{Field(":method", "GET"), Field(":scheme", "http"), Field(":path", "/"),
                                Field(":authority", "www.example.com")};
  nexora::HpackEncoder encoder;
  if (const int line = EncodeEq(encoder, first, expect)) return line;
  return 0;
}

}  // namespace

int main() {
  if (const int line = FrameRoundTrip()) return line;
  if (const int line = SettingsBounds()) return line;
  if (const int line = HuffmanVector()) return line;
  if (const int line = HuffmanAllBytes()) return line;
  if (const int line = HpackIntHighBit()) return line;
  if (const int line = AppendixRequests()) return line;
  if (const int line = AppendixResponses()) return line;
  if (const int line = TableSizeClamp()) return line;
  if (const int line = HpackStaticAndDynamic()) return line;
  return 0;
}
