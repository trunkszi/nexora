#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <nexora/bytes/bytes.hpp>
#include <nexora/bytes/scan.hpp>
#include <nexora/error/proto_error.hpp>
#include <nexora/error/runtime_error.hpp>
#include <nexora/http/message.hpp>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace {

void Check(bool cond) noexcept {
  if (!cond) {
    std::abort();
  }
}

void TestErrors() noexcept {
  constexpr nexora::Error ok = nexora::Error::FromProto(nexora::ProtoErrorCode::kOk);
  static_assert(ok.Ok());
  static_assert(ok.Message() == "ok");

  constexpr nexora::Error proto_err = nexora::Error::FromProto(nexora::ProtoErrorCode::kInvalidUri);
  static_assert(!proto_err.Ok());
  static_assert(proto_err.domain == nexora::ErrorDomain::kProto);
  static_assert(proto_err.Message() == "invalid URI");

  constexpr nexora::Error h2_ok = nexora::Error::FromHttp2(nexora::Http2ErrorCode::kNoError);
  static_assert(h2_ok.Ok());

  constexpr nexora::Error h2_err = nexora::Error::FromHttp2(nexora::Http2ErrorCode::kFlowControlError);
  static_assert(!h2_err.Ok());
  static_assert(h2_err.domain == nexora::ErrorDomain::kHttp2);
  static_assert(h2_err.Message() == "FLOW_CONTROL_ERROR");
  static_assert(nexora::Http2ErrorCodeFromU32(999U) == nexora::Http2ErrorCode::kInternalError);

  constexpr nexora::Error rt_err = nexora::Error::Timeout();
  static_assert(!rt_err.Ok());
  static_assert(rt_err.domain == nexora::ErrorDomain::kRuntime);
  static_assert(rt_err.Message() == "operation timed out");

  constexpr nexora::Error dns_err = nexora::Error::DnsFailed(4);
  static_assert(!dns_err.Ok());
  static_assert(dns_err.domain == nexora::ErrorDomain::kRuntime);
  static_assert(dns_err.code == static_cast<std::int32_t>(std::to_underlying(nexora::RuntimeErrorCode::kDnsError)));
  static_assert(dns_err.SysErrno() == 4);
  static_assert(dns_err.Message() == "DNS resolution error");

  constexpr nexora::Error uring_err = nexora::Error::UringFailed(-EINVAL);
  static_assert(!uring_err.Ok());
  static_assert(uring_err.domain == nexora::ErrorDomain::kRuntime);
  static_assert(uring_err.code == static_cast<std::int32_t>(std::to_underlying(nexora::RuntimeErrorCode::kUringError)));
  static_assert(uring_err.SysErrno() == -EINVAL);
  static_assert(uring_err.Message() == "io_uring completion error");

  constexpr nexora::Error errno_ok = nexora::Error::FromErrno(0);
  static_assert(errno_ok.Ok());
  constexpr nexora::Error errno_err = nexora::Error::FromErrno(EAGAIN);
  static_assert(!errno_err.Ok());
  static_assert(errno_err.domain == nexora::ErrorDomain::kErrno);
  static_assert(errno_err.SysErrno() == EAGAIN);
  static_assert(errno_err.Message() == "resource temporarily unavailable (EAGAIN)");

  Check(std::format("{}", proto_err) == "invalid URI");
  Check(std::format("{}", errno_err) == "resource temporarily unavailable (EAGAIN)");
}

void TestBytesAndSlices() {
  static_assert(sizeof(nexora::BytesView) == 16);
  static_assert(uarch::NoPadding<nexora::BytesView>);
  static_assert(uarch::RegisterPassable<nexora::BytesView>);

  constexpr std::array<std::uint8_t, 10> static_bytes{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
  nexora::Bytes static_view = nexora::Bytes::FromStatic(static_bytes);
  Check(!static_view.IsOwned());
  Check(static_view.Data() == static_bytes.data());
  Check(static_view.Size() == 10);
  Check(!static_view.Empty());

  nexora::Bytes sub = static_view.Slice(2, 5);
  Check(!sub.IsOwned());
  Check(sub.AsStringView() == "23456");
  Check(sub.Data() == static_bytes.data() + 2);

  nexora::Bytes view = static_view.Slice(1, 8);
  nexora::Bytes prefix = view.SplitTo(2);
  nexora::Bytes suffix = view.SplitOff(3);
  Check(prefix.AsStringView() == "12");
  Check(view.AsStringView() == "345");
  Check(suffix.AsStringView() == "678");
  Check(prefix.Data() == static_bytes.data() + 1);
  Check(view.Data() == static_bytes.data() + 3);
  Check(suffix.Data() == static_bytes.data() + 6);

  nexora::Bytes from_str = nexora::Bytes::FromString("prefix-body");
  nexora::Bytes str_prefix = from_str.SplitTo(7);
  Check(str_prefix.AsStringView() == "prefix-");
  Check(from_str.AsStringView() == "body");
  from_str.Clear();
  Check(from_str.Empty());
  Check(str_prefix.AsStringView() == "prefix-");

  // CopyFromString and CopyFromSlice own their payload after source temporaries expire.
  nexora::Bytes copied_str = nexora::Bytes::CopyFromString(std::string(128, 'x'));
  Check(copied_str.IsOwned());
  Check(copied_str.AsStringView() == std::string(128, 'x'));

  nexora::Bytes copied_slice;
  {
    std::array<std::uint8_t, 64> stack_buf{};
    stack_buf.fill(static_cast<std::uint8_t>('s'));
    copied_slice = nexora::Bytes::CopyFromSlice(stack_buf);
    stack_buf.fill(0);
  }
  Check(copied_slice.IsOwned());
  Check(copied_slice.AsStringView() == std::string(64, 's'));
  nexora::Bytes owned_sub = copied_slice.Slice(4, 16);
  copied_slice.Clear();
  Check(owned_sub.IsOwned());
  Check(owned_sub.AsStringView() == std::string(16, 's'));

  const auto uri = *nexora::Uri::Parse("http://example.test/upload");
  auto req = nexora::Request::Post(uri, std::string(128, 'y'));
  auto resp = nexora::Response::Ok(std::string(128, 'z'));
  Check(req.body.IsOwned());
  Check(req.body.AsStringView() == std::string(128, 'y'));
  Check(resp.body.IsOwned());
  Check(resp.body.AsStringView() == std::string(128, 'z'));
}

void TestNetworkOrderReadersAndWriters() {
  nexora::BytesMut<64> fixed;
  Check(fixed.PutU8(0x01U).has_value());
  Check(fixed.PutU16Be(0x0203U).has_value());
  Check(fixed.PutU24Be(0x040506U).has_value());
  Check(!fixed.PutU24Be(0x01000000U).has_value());
  Check(fixed.PutU32Be(0x0708090aU).has_value());
  Check(fixed.PutU64Be(0x0b0c0d0e0f101112ULL).has_value());
  Check(fixed.Size() == 18);

  for (std::size_t i = 0; i < 18; ++i) {
    Check(fixed.ReadableSpan()[i] == static_cast<std::uint8_t>(i + 1));
  }

  Check(*fixed.ReadU8(0) == 0x01U);
  Check(*fixed.ReadU16Be(1) == 0x0203U);
  Check(*fixed.ReadU24Be(3) == 0x040506U);
  Check(*fixed.ReadU32Be(6) == 0x0708090aU);
  Check(*fixed.ReadU64Be(10) == 0x0b0c0d0e0f101112ULL);
  Check(!fixed.ReadU64Be(11).has_value());

  nexora::Bytes frozen = fixed.Freeze();
  Check(fixed.Empty());
  Check(*frozen.TakeU8() == 0x01U);
  Check(*frozen.TakeU16Be() == 0x0203U);
  Check(*frozen.TakeU24Be() == 0x040506U);
  Check(*frozen.TakeU32Be() == 0x0708090aU);
  Check(*frozen.TakeU64Be() == 0x0b0c0d0e0f101112ULL);
  Check(frozen.Empty());
  Check(!frozen.TakeU8().has_value());

  nexora::BytesMut<8> tiny;
  Check(tiny.AppendString("123456").has_value());
  tiny.Consume(4);
  Check(tiny.Size() == 2);
  // Compaction allows 6 more bytes to fit into 8-byte capacity.
  Check(tiny.AppendString("abcdef").has_value());
  Check(tiny.AsStringView() == "56abcdef");
  Check(!tiny.PutU8(0xffU).has_value());

  nexora::ByteBuffer dyn(4);
  Check(dyn.PutU8(1).has_value());
  Check(dyn.PutU16Be(0x0203U).has_value());
  Check(dyn.PutU24Be(0x040506U).has_value());
  Check(dyn.PutU32Be(0x0708090aU).has_value());
  Check(dyn.PutU64Be(0x0b0c0d0e0f101112ULL).has_value());
  dyn.Advance(10);
  Check(dyn.Reserve(32).has_value());
  Check(dyn.WritableSpan(16).has_value());
  Check(dyn.AppendString("tail").has_value());
  const std::array<std::uint8_t, 12> expected{11, 12, 13, 14, 15, 16, 17, 18, 't', 'a', 'i', 'l'};
  Check(dyn.Size() == expected.size());
  for (std::size_t i = 0; i < expected.size(); ++i) {
    Check(dyn.ReadableSpan()[i] == expected[i]);
  }
}

void TestSimdAndSwarScanners() noexcept {
  constexpr std::string_view wire =
      "GET /very/long/path/that/exceeds/sixteen/bytes HTTP/1.1\r\n"
      "Host: example.test\r\r\n"
      "X-Custom: value\r\n\r\nbody";
  const auto crlf = nexora::FindCrLf(wire);
  Check(crlf.has_value() && *crlf == 55U);

  const auto hdr_end = nexora::FindHeaderEnd(wire);
  Check(hdr_end.has_value());
  Check(wire.substr(*hdr_end + 4) == "body");

  Check(!nexora::FindCrLf("no-line-break\r").has_value());
  Check(!nexora::FindHeaderEnd("Host: a\r\n\r").has_value());

  Check(nexora::IsValidHeaderName("X-Request-Id_123!#$%&'*+-.^`|~"));
  Check(!nexora::IsValidHeaderName(""));
  Check(!nexora::IsValidHeaderName("Bad Header"));
  Check(!nexora::IsValidHeaderName("Bad:Header"));

  Check(nexora::IsValidHttp2HeaderName(":method", true));
  Check(!nexora::IsValidHttp2HeaderName(":method", false));
  Check(!nexora::IsValidHttp2HeaderName("X-Upper", true));
  Check(!nexora::IsValidHttp2HeaderName(":", true));

  // Verify FindByte across offsets 0..71 in a 72-byte buffer (spanning 16B, 32B, and 64B chunks).
  for (std::size_t pos = 0; pos < 72; ++pos) {
    std::array<std::uint8_t, 72> hay{};
    hay.fill(static_cast<std::uint8_t>('.'));
    hay[pos] = static_cast<std::uint8_t>(':');
    const auto found = nexora::FindByte(hay, static_cast<std::uint8_t>(':'));
    Check(found.has_value() && *found == pos);
    const auto scalar_found = uarch::run<nexora::detail::FindByteKernel{}>(uarch::Scalar{}, std::span<const std::uint8_t>(hay),
                                                                           static_cast<std::uint8_t>(':'));
    Check(scalar_found == found);
  }

  // Verify IsValidHeaderValue & IsValidHeaderName with valid/invalid bytes at offsets 0..15 in a
  // 64-byte buffer (inside the first SIMD vector chunk, not just the scalar tail), against both
  // active tier dispatch and an explicit uarch::Scalar{} token.
  constexpr std::array<char, 5> bad_value_bytes{'\0', '\r', '\n', '\x1f', '\x7f'};
  for (std::size_t offset = 0; offset < 16; ++offset) {
    for (char bad : bad_value_bytes) {
      std::array<char, 64> val_buf{};
      val_buf.fill('a');
      val_buf[offset] = bad;
      const std::string_view sv(val_buf.data(), val_buf.size());
      Check(!nexora::IsValidHeaderValue(sv));
      Check(!uarch::run<nexora::detail::HeaderValueValidateKernel{}>(uarch::Scalar{}, sv));
    }

    // Valid HTAB ('\t') and obs-text (0x80, 0xff) inside first 16-byte SIMD chunk.
    for (unsigned char good : std::array<unsigned char, 3>{0x09U, 0x80U, 0xffU}) {
      std::array<char, 64> val_buf{};
      val_buf.fill('v');
      val_buf[offset] = static_cast<char>(good);
      const std::string_view sv(val_buf.data(), val_buf.size());
      Check(nexora::IsValidHeaderValue(sv));
      Check(uarch::run<nexora::detail::HeaderValueValidateKernel{}>(uarch::Scalar{}, sv));
    }

    // Invalid header name bytes (' ', ':', '\x7f', '\x80') at offset 0..15 in a 64-byte name.
    for (unsigned char bad_name : std::array<unsigned char, 4>{' ', ':', 0x7fU, 0x80U}) {
      std::array<char, 64> name_buf{};
      name_buf.fill('x');
      name_buf[offset] = static_cast<char>(bad_name);
      const std::string_view sv(name_buf.data(), name_buf.size());
      Check(!nexora::IsValidHeaderName(sv));
      Check(!uarch::run<nexora::detail::HeaderNameValidateKernel{}>(uarch::Scalar{}, sv));
    }
  }

  // Verify AsciiEqualsIgnoreCase and AsciiLowerInPlace at offsets 0..15 in 64-byte buffers,
  // including ASCII alphabet boundaries ('@', '[', '`', '{') and high bytes (>= 0x80).
  for (std::size_t offset = 0; offset < 16; ++offset) {
    std::array<char, 64> upper_buf{};
    std::array<char, 64> lower_buf{};
    upper_buf.fill('A');
    lower_buf.fill('a');
    const std::string_view upper_sv(upper_buf.data(), upper_buf.size());
    std::string_view lower_sv(lower_buf.data(), lower_buf.size());
    Check(nexora::AsciiEqualsIgnoreCase(upper_sv, lower_sv));
    Check(uarch::run<nexora::detail::AsciiEqualsIgnoreCaseKernel{}>(uarch::Scalar{}, upper_sv, lower_sv));

    // Mismatch at offset inside first SIMD vector chunk.
    lower_buf[offset] = 'b';
    Check(!nexora::AsciiEqualsIgnoreCase(upper_sv, lower_sv));
    Check(!uarch::run<nexora::detail::AsciiEqualsIgnoreCaseKernel{}>(uarch::Scalar{}, upper_sv, lower_sv));

    // Boundary pairs that differ by 0x20 but are NOT ASCII letters must NOT compare equal.
    std::array<char, 64> left_boundary{};
    std::array<char, 64> right_boundary{};
    left_boundary.fill('x');
    right_boundary.fill('x');
    left_boundary[offset] = '[';
    right_boundary[offset] = '{';
    const std::string_view left_sv(left_boundary.data(), left_boundary.size());
    const std::string_view right_sv(right_boundary.data(), right_boundary.size());
    Check(!nexora::AsciiEqualsIgnoreCase(left_sv, right_sv));
    Check(!uarch::run<nexora::detail::AsciiEqualsIgnoreCaseKernel{}>(uarch::Scalar{}, left_sv, right_sv));

    left_boundary[offset] = '@';
    right_boundary[offset] = '`';
    Check(!nexora::AsciiEqualsIgnoreCase(left_sv, right_sv));
    Check(!uarch::run<nexora::detail::AsciiEqualsIgnoreCaseKernel{}>(uarch::Scalar{}, left_sv, right_sv));

    left_boundary[offset] = static_cast<char>(0xc1U);
    right_boundary[offset] = static_cast<char>(0xe1U);
    Check(!nexora::AsciiEqualsIgnoreCase(left_sv, right_sv));
    Check(!uarch::run<nexora::detail::AsciiEqualsIgnoreCaseKernel{}>(uarch::Scalar{}, left_sv, right_sv));

    // AsciiLowerInPlace must lower 'A'..'Z' and leave '@', '[', '`', '{', 0x80, 0xc1 untouched.
    std::array<char, 64> to_lower{};
    to_lower.fill('Z');
    to_lower[offset] = '@';
    to_lower[offset + 1] = '[';
    to_lower[offset + 2] = '`';
    to_lower[offset + 3] = '{';
    to_lower[offset + 4] = static_cast<char>(0x80U);
    to_lower[offset + 5] = static_cast<char>(0xc1U);
    to_lower[offset + 6] = 'A';
    auto scalar_lower = to_lower;
    nexora::AsciiLowerInPlace(std::span<char>(to_lower));
    uarch::run<nexora::detail::AsciiLowerKernel{}>(uarch::Scalar{}, std::span<char>(scalar_lower));
    Check(to_lower == scalar_lower);
    Check(to_lower[offset] == '@');
    Check(to_lower[offset + 1] == '[');
    Check(to_lower[offset + 2] == '`');
    Check(to_lower[offset + 3] == '{');
    Check(static_cast<unsigned char>(to_lower[offset + 4]) == 0x80U);
    Check(static_cast<unsigned char>(to_lower[offset + 5]) == 0xc1U);
    Check(to_lower[offset + 6] == 'a');
  }
}

}  // namespace

int main() {
  TestErrors();
  TestBytesAndSlices();
  TestNetworkOrderReadersAndWriters();
  TestSimdAndSwarScanners();
  return 0;
}
