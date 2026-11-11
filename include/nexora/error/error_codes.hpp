/** @file @brief Protocol, HTTP/2, runtime, and system errno error codes. */
#pragma once

#include <cerrno>
#include <cstdint>
#include <string_view>

namespace nexora {

enum class ProtoErrorCode : std::uint16_t {
  kOk = 0,
  kIncomplete,
  kInvalidArgument,
  kBufferOverflow,
  kInvalidUri,
  kInvalidHeaderName,
  kInvalidHeaderValue,
  kInvalidMethod,
  kInvalidStatus,
  kHttp1ParseError,
  kHttp1ConflictingFraming,
  kHttp1MessageTooLarge,
  kHttp2FrameSizeError,
  kHttp2CompressionError,
  kHttp2FlowControlError,
  kHttp2ProtocolError,
  kHttp2StreamClosed,
  kHttp2RefusedStream,
  kHttp2Cancel,
  kHttp2Goaway,
  kWebSocketHandshakeFailed,
  kWebSocketProtocolError,
  kWebSocketInvalidUtf8,
  kWebSocketPayloadTooLarge,
  kTlsConfigError,
  kTlsHandshakeFailed,
  kTlsVerifyFailed,
  kTlsIoError,
  kTlsClosed,
};

enum class Http2ErrorCode : std::uint32_t {
  kNoError = 0x0,
  kProtocolError = 0x1,
  kInternalError = 0x2,
  kFlowControlError = 0x3,
  kSettingsTimeout = 0x4,
  kStreamClosed = 0x5,
  kFrameSizeError = 0x6,
  kRefusedStream = 0x7,
  kCancel = 0x8,
  kCompressionError = 0x9,
  kConnectError = 0xa,
  kEnhanceYourCalm = 0xb,
  kInadequateSecurity = 0xc,
  kHttp11Required = 0xd,
};

[[nodiscard]] constexpr Http2ErrorCode Http2ErrorCodeFromU32(std::uint32_t raw) noexcept {
  switch (raw) {
    case 0x0:
      return Http2ErrorCode::kNoError;
    case 0x1:
      return Http2ErrorCode::kProtocolError;
    case 0x2:
      return Http2ErrorCode::kInternalError;
    case 0x3:
      return Http2ErrorCode::kFlowControlError;
    case 0x4:
      return Http2ErrorCode::kSettingsTimeout;
    case 0x5:
      return Http2ErrorCode::kStreamClosed;
    case 0x6:
      return Http2ErrorCode::kFrameSizeError;
    case 0x7:
      return Http2ErrorCode::kRefusedStream;
    case 0x8:
      return Http2ErrorCode::kCancel;
    case 0x9:
      return Http2ErrorCode::kCompressionError;
    case 0xa:
      return Http2ErrorCode::kConnectError;
    case 0xb:
      return Http2ErrorCode::kEnhanceYourCalm;
    case 0xc:
      return Http2ErrorCode::kInadequateSecurity;
    case 0xd:
      return Http2ErrorCode::kHttp11Required;
    default:
      // RFC 9113 Section 7: unknown error codes are treated as INTERNAL_ERROR.
      return Http2ErrorCode::kInternalError;
  }
}

[[nodiscard]] constexpr std::string_view ProtoErrorMessage(ProtoErrorCode code) noexcept {
  switch (code) {
    case ProtoErrorCode::kOk:
      return "ok";
    case ProtoErrorCode::kIncomplete:
      return "incomplete frame or message";
    case ProtoErrorCode::kInvalidArgument:
      return "invalid argument";
    case ProtoErrorCode::kBufferOverflow:
      return "buffer capacity exceeded";
    case ProtoErrorCode::kInvalidUri:
      return "invalid URI";
    case ProtoErrorCode::kInvalidHeaderName:
      return "invalid HTTP header name";
    case ProtoErrorCode::kInvalidHeaderValue:
      return "invalid HTTP header value";
    case ProtoErrorCode::kInvalidMethod:
      return "invalid HTTP method";
    case ProtoErrorCode::kInvalidStatus:
      return "invalid HTTP status code";
    case ProtoErrorCode::kHttp1ParseError:
      return "HTTP/1.1 parse error";
    case ProtoErrorCode::kHttp1ConflictingFraming:
      return "HTTP/1.1 conflicting framing headers";
    case ProtoErrorCode::kHttp1MessageTooLarge:
      return "HTTP/1.1 message exceeds size limit";
    case ProtoErrorCode::kHttp2FrameSizeError:
      return "HTTP/2 frame size error";
    case ProtoErrorCode::kHttp2CompressionError:
      return "HTTP/2 HPACK compression error";
    case ProtoErrorCode::kHttp2FlowControlError:
      return "HTTP/2 flow control error";
    case ProtoErrorCode::kHttp2ProtocolError:
      return "HTTP/2 protocol error";
    case ProtoErrorCode::kHttp2StreamClosed:
      return "HTTP/2 stream closed";
    case ProtoErrorCode::kHttp2RefusedStream:
      return "HTTP/2 stream refused";
    case ProtoErrorCode::kHttp2Cancel:
      return "HTTP/2 stream cancelled";
    case ProtoErrorCode::kHttp2Goaway:
      return "HTTP/2 GOAWAY received";
    case ProtoErrorCode::kWebSocketHandshakeFailed:
      return "WebSocket handshake failed";
    case ProtoErrorCode::kWebSocketProtocolError:
      return "WebSocket protocol error";
    case ProtoErrorCode::kWebSocketInvalidUtf8:
      return "WebSocket text payload is not valid UTF-8";
    case ProtoErrorCode::kWebSocketPayloadTooLarge:
      return "WebSocket payload exceeds maximum size";
    case ProtoErrorCode::kTlsConfigError:
      return "TLS configuration error";
    case ProtoErrorCode::kTlsHandshakeFailed:
      return "TLS handshake failed";
    case ProtoErrorCode::kTlsVerifyFailed:
      return "TLS peer certificate verification failed";
    case ProtoErrorCode::kTlsIoError:
      return "TLS BIO or record I/O error";
    case ProtoErrorCode::kTlsClosed:
      return "TLS session closed";
  }
  return "unknown protocol error";
}

[[nodiscard]] constexpr std::string_view Http2ErrorMessage(Http2ErrorCode code) noexcept {
  switch (code) {
    case Http2ErrorCode::kNoError:
      return "NO_ERROR";
    case Http2ErrorCode::kProtocolError:
      return "PROTOCOL_ERROR";
    case Http2ErrorCode::kInternalError:
      return "INTERNAL_ERROR";
    case Http2ErrorCode::kFlowControlError:
      return "FLOW_CONTROL_ERROR";
    case Http2ErrorCode::kSettingsTimeout:
      return "SETTINGS_TIMEOUT";
    case Http2ErrorCode::kStreamClosed:
      return "STREAM_CLOSED";
    case Http2ErrorCode::kFrameSizeError:
      return "FRAME_SIZE_ERROR";
    case Http2ErrorCode::kRefusedStream:
      return "REFUSED_STREAM";
    case Http2ErrorCode::kCancel:
      return "CANCEL";
    case Http2ErrorCode::kCompressionError:
      return "COMPRESSION_ERROR";
    case Http2ErrorCode::kConnectError:
      return "CONNECT_ERROR";
    case Http2ErrorCode::kEnhanceYourCalm:
      return "ENHANCE_YOUR_CALM";
    case Http2ErrorCode::kInadequateSecurity:
      return "INADEQUATE_SECURITY";
    case Http2ErrorCode::kHttp11Required:
      return "HTTP_1_1_REQUIRED";
  }
  return "INTERNAL_ERROR";
}

enum class RuntimeErrorCode : std::uint16_t {
  kOk = 0,
  kTimedOut,
  kCancelled,
  kConnectionRefused,
  kConnectionReset,
  kConnectionClosed,
  kPoolExhausted,
  kAllEndpointsUnhealthy,
  kDnsError,
  kUringError,
  kSyscallError,
  kInvalidState,
};

[[nodiscard]] constexpr std::string_view RuntimeErrorMessage(RuntimeErrorCode code) noexcept {
  switch (code) {
    case RuntimeErrorCode::kOk:
      return "ok";
    case RuntimeErrorCode::kTimedOut:
      return "operation timed out";
    case RuntimeErrorCode::kCancelled:
      return "operation cancelled";
    case RuntimeErrorCode::kConnectionRefused:
      return "connection refused";
    case RuntimeErrorCode::kConnectionReset:
      return "connection reset by peer";
    case RuntimeErrorCode::kConnectionClosed:
      return "connection closed";
    case RuntimeErrorCode::kPoolExhausted:
      return "connection pool exhausted";
    case RuntimeErrorCode::kAllEndpointsUnhealthy:
      return "all endpoints unhealthy";
    case RuntimeErrorCode::kDnsError:
      return "DNS resolution error";
    case RuntimeErrorCode::kUringError:
      return "io_uring completion error";
    case RuntimeErrorCode::kSyscallError:
      return "system call error";
    case RuntimeErrorCode::kInvalidState:
      return "invalid state transition";
  }
  return "unknown runtime error";
}

[[nodiscard]] constexpr std::string_view SysErrnoMessage(std::int32_t err) noexcept {
  const std::int32_t pos = err < 0 ? -err : err;
  switch (pos) {
    case 0:
      return "ok";
    case EAGAIN:
      return "resource temporarily unavailable (EAGAIN)";
    case EINTR:
      return "interrupted system call (EINTR)";
    case EINVAL:
      return "invalid argument (EINVAL)";
    case ENOMEM:
      return "out of memory (ENOMEM)";
    case EACCES:
      return "permission denied (EACCES)";
    case EBADF:
      return "bad file descriptor (EBADF)";
    case EPIPE:
      return "broken pipe (EPIPE)";
    case ECONNRESET:
      return "connection reset by peer (ECONNRESET)";
    case ECONNREFUSED:
      return "connection refused (ECONNREFUSED)";
    case ETIMEDOUT:
      return "connection timed out (ETIMEDOUT)";
    case EHOSTUNREACH:
      return "no route to host (EHOSTUNREACH)";
    case ENETUNREACH:
      return "network is unreachable (ENETUNREACH)";
    case EADDRINUSE:
      return "address already in use (EADDRINUSE)";
    case EADDRNOTAVAIL:
      return "address not available (EADDRNOTAVAIL)";
    case EINPROGRESS:
      return "operation now in progress (EINPROGRESS)";
    case EALREADY:
      return "operation already in progress (EALREADY)";
    case ENOTCONN:
      return "transport endpoint is not connected (ENOTCONN)";
    case EMSGSIZE:
      return "message too long (EMSGSIZE)";
    case ENOSPC:
      return "no space left on device (ENOSPC)";
    default:
      return "system errno error";
  }
}

enum class ErrorDomain : std::uint8_t {
  kNone = 0,
  kProto,
  kHttp2,
  kRuntime,
  kErrno,
};

}  // namespace nexora
