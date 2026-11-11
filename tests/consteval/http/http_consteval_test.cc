#include <array>
#include <cstdint>
#include <nexora/bytes/bytes.hpp>
#include <nexora/bytes/scan.hpp>
#include <nexora/error/proto_error.hpp>
#include <nexora/error/runtime_error.hpp>
#include <nexora/http/headers.hpp>
#include <nexora/http/message.hpp>
#include <nexora/http/reflect_decl.hpp>
#include <nexora/http/uri.hpp>

namespace {

// Compile-time error and HTTP2 error mapping assertions.
static_assert(nexora::Error{}.Ok());
static_assert(!nexora::Error::Timeout().Ok());
static_assert(!nexora::Error::Cancelled().Ok());
static_assert(!nexora::Error::InvalidArgument().Ok());
static_assert(nexora::Http2ErrorCodeFromU32(0x0U) == nexora::Http2ErrorCode::kNoError);
static_assert(nexora::Http2ErrorCodeFromU32(0xdU) == nexora::Http2ErrorCode::kHttp11Required);
static_assert(nexora::Http2ErrorCodeFromU32(0xffU) == nexora::Http2ErrorCode::kInternalError);

// Compile-time big-endian wire decoders and BytesMut operations.
consteval bool VerifyConstexprBytesMut() {
  nexora::BytesMut<32> buf;
  if (!buf.PutU8(0x12U).has_value()) {
    return false;
  }
  if (!buf.PutU16Be(0x3456U).has_value()) {
    return false;
  }
  if (!buf.PutU24Be(0x789abcU).has_value()) {
    return false;
  }
  if (!buf.PutU32Be(0xdef01234U).has_value()) {
    return false;
  }
  if (!buf.PutU64Be(0x0102030405060708ULL).has_value()) {
    return false;
  }
  if (!buf.AppendString("ok").has_value()) {
    return false;
  }
  if (*buf.ReadU8(0) != 0x12U) {
    return false;
  }
  if (*buf.ReadU16Be(1) != 0x3456U) {
    return false;
  }
  if (*buf.ReadU24Be(3) != 0x789abcU) {
    return false;
  }
  if (*buf.ReadU32Be(6) != 0xdef01234U) {
    return false;
  }
  if (*buf.ReadU64Be(10) != 0x0102030405060708ULL) {
    return false;
  }
  if (*buf.ReadU16Be(18) != 0x6f6bU || buf.ReadableSpan()[18] != 'o' || buf.ReadableSpan()[19] != 'k') {
    return false;
  }
  return buf.Size() == 20uz;
}
static_assert(VerifyConstexprBytesMut());

// Compile-time scanner and header literal validators.
static_assert(nexora::FindCrLf("GET / HTTP/1.1\r\nHost: a\r\n") == 14U);
static_assert(nexora::FindHeaderEnd("GET / HTTP/1.1\r\nHost: a\r\n\r\n") == 23U);
static_assert(nexora::IsValidHeaderName("x-custom-token"));
static_assert(!nexora::IsValidHeaderName("bad:header"));
static_assert(nexora::IsValidHttp2HeaderName(":authority", true));
static_assert(!nexora::IsValidHttp2HeaderName(":Authority", true));
static_assert(nexora::IsValidHeaderValue("valid\tvalue"));
static_assert(!nexora::IsValidHeaderValue("bad\r\nvalue"));
static_assert(nexora::AsciiEqualsIgnoreCase("Content-Type", "content-type"));

static_assert(nexora::ValidateHeaderNameLiteral("X-Request-Id") == "X-Request-Id");
static_assert(nexora::ValidateHeaderValueLiteral("application/grpc+proto") == "application/grpc+proto");
static_assert(nexora::ValidateHttp2HeaderNameLiteral(":status") == ":status");

// Compile-time StatusCode and Method checks.
static_assert(nexora::ParseMethod("POST").value() == nexora::Method::kPost);
static_assert(!nexora::ParseMethod("INVALID").has_value());
static_assert(nexora::StatusCode::FromU16(200).value().IsSuccess());
static_assert(!nexora::StatusCode::FromU16(99).has_value());

}  // namespace

int main() { return 0; }
