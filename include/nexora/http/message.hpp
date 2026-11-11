/** @file @brief HTTP methods, versions, status codes, Request, and Response models. */
#pragma once

#include <compare>
#include <cstdint>
#include <nexora/bytes/bytes.hpp>
#include <nexora/error/runtime_error.hpp>
#include <nexora/http/headers.hpp>
#include <nexora/http/uri.hpp>
#include <string_view>
#include <utility>

namespace nexora {

enum class Method : std::uint8_t {
  kGet = 0,
  kPost = 1,
  kPut = 2,
  kDelete = 3,
  kHead = 4,
  kOptions = 5,
  kPatch = 6,
  kConnect = 7,
  kTrace = 8,
};

[[nodiscard]] constexpr std::string_view MethodAsStr(Method m) noexcept {
  switch (m) {
    case Method::kGet:
      return "GET";
    case Method::kPost:
      return "POST";
    case Method::kPut:
      return "PUT";
    case Method::kDelete:
      return "DELETE";
    case Method::kHead:
      return "HEAD";
    case Method::kOptions:
      return "OPTIONS";
    case Method::kPatch:
      return "PATCH";
    case Method::kConnect:
      return "CONNECT";
    case Method::kTrace:
      return "TRACE";
  }
  return "GET";
}

[[nodiscard]] constexpr Result<Method> ParseMethod(std::string_view token) noexcept {
  if (token == "GET") {
    return Method::kGet;
  }
  if (token == "POST") {
    return Method::kPost;
  }
  if (token == "PUT") {
    return Method::kPut;
  }
  if (token == "DELETE") {
    return Method::kDelete;
  }
  if (token == "HEAD") {
    return Method::kHead;
  }
  if (token == "OPTIONS") {
    return Method::kOptions;
  }
  if (token == "PATCH") {
    return Method::kPatch;
  }
  if (token == "CONNECT") {
    return Method::kConnect;
  }
  if (token == "TRACE") {
    return Method::kTrace;
  }
  return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidMethod));
}

enum class Version : std::uint8_t {
  kHttp11 = 0,
  kHttp10 = 1,
  kHttp2 = 2,
};

[[nodiscard]] constexpr std::string_view VersionAsStr(Version v) noexcept {
  switch (v) {
    case Version::kHttp11:
      return "HTTP/1.1";
    case Version::kHttp10:
      return "HTTP/1.0";
    case Version::kHttp2:
      return "HTTP/2.0";
  }
  return "HTTP/1.1";
}

[[nodiscard]] constexpr Result<Version> ParseHttp1Version(std::string_view raw) noexcept {
  if (raw == "HTTP/1.1") {
    return Version::kHttp11;
  }
  if (raw == "HTTP/1.0") {
    return Version::kHttp10;
  }
  return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
}

struct StatusCode {
  std::uint16_t value{200};

  constexpr StatusCode() noexcept = default;
  constexpr StatusCode(std::uint16_t raw) noexcept : value(raw) {}

  [[nodiscard]] static constexpr Result<StatusCode> FromU16(std::uint16_t raw) noexcept {
    if (raw < 100U || raw > 599U) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidStatus));
    }
    return StatusCode{raw};
  }

  [[nodiscard]] constexpr std::uint16_t Code() const noexcept { return value; }
  [[nodiscard]] constexpr std::uint16_t code() const noexcept { return value; }
  [[nodiscard]] constexpr std::uint16_t AsU16() const noexcept { return value; }

  [[nodiscard]] constexpr bool IsInformational() const noexcept { return value >= 100U && value < 200U; }
  [[nodiscard]] constexpr bool IsSuccess() const noexcept { return value >= 200U && value < 300U; }
  [[nodiscard]] constexpr bool IsRedirection() const noexcept { return value >= 300U && value < 400U; }
  [[nodiscard]] constexpr bool IsClientError() const noexcept { return value >= 400U && value < 500U; }
  [[nodiscard]] constexpr bool IsServerError() const noexcept { return value >= 500U && value < 600U; }

  [[nodiscard]] constexpr std::string_view ReasonPhrase() const noexcept {
    switch (value) {
      case 100:
        return "Continue";
      case 101:
        return "Switching Protocols";
      case 200:
        return "OK";
      case 201:
        return "Created";
      case 202:
        return "Accepted";
      case 204:
        return "No Content";
      case 301:
        return "Moved Permanently";
      case 302:
        return "Found";
      case 303:
        return "See Other";
      case 304:
        return "Not Modified";
      case 307:
        return "Temporary Redirect";
      case 308:
        return "Permanent Redirect";
      case 400:
        return "Bad Request";
      case 401:
        return "Unauthorized";
      case 403:
        return "Forbidden";
      case 404:
        return "Not Found";
      case 405:
        return "Method Not Allowed";
      case 408:
        return "Request Timeout";
      case 413:
        return "Content Too Large";
      case 429:
        return "Too Many Requests";
      case 500:
        return "Internal Server Error";
      case 501:
        return "Not Implemented";
      case 502:
        return "Bad Gateway";
      case 503:
        return "Service Unavailable";
      case 504:
        return "Gateway Timeout";
      default:
        return "";
    }
  }

  static constexpr std::uint16_t kContinue = 100;
  static constexpr std::uint16_t kSwitchingProtocols = 101;
  static constexpr std::uint16_t kOk = 200;
  static constexpr std::uint16_t kCreated = 201;
  static constexpr std::uint16_t kAccepted = 202;
  static constexpr std::uint16_t kNoContent = 204;
  static constexpr std::uint16_t kMovedPermanently = 301;
  static constexpr std::uint16_t kFound = 302;
  static constexpr std::uint16_t kSeeOther = 303;
  static constexpr std::uint16_t kNotModified = 304;
  static constexpr std::uint16_t kTemporaryRedirect = 307;
  static constexpr std::uint16_t kPermanentRedirect = 308;
  static constexpr std::uint16_t kBadRequest = 400;
  static constexpr std::uint16_t kUnauthorized = 401;
  static constexpr std::uint16_t kForbidden = 403;
  static constexpr std::uint16_t kNotFound = 404;
  static constexpr std::uint16_t kMethodNotAllowed = 405;
  static constexpr std::uint16_t kRequestTimeout = 408;
  static constexpr std::uint16_t kPayloadTooLarge = 413;
  static constexpr std::uint16_t kTooManyRequests = 429;
  static constexpr std::uint16_t kInternalServerError = 500;
  static constexpr std::uint16_t kNotImplemented = 501;
  static constexpr std::uint16_t kBadGateway = 502;
  static constexpr std::uint16_t kServiceUnavailable = 503;
  static constexpr std::uint16_t kGatewayTimeout = 504;

  constexpr auto operator<=>(const StatusCode&) const noexcept = default;
};

struct Request {
  Method method{Method::kGet};
  Uri uri{};
  Version version{Version::kHttp11};
  Headers<> headers{};
  Bytes body{};
  Headers<> trailers{};

  Request() noexcept = default;

  Request(Method m, Uri u, Version v = Version::kHttp11) noexcept : method(m), uri(std::move(u)), version(v) {}

  [[nodiscard]] static Result<Request> Build(Method m, std::string_view raw_uri, Bytes payload = {}) noexcept {
    auto parsed = Uri::Parse(raw_uri);
    if (!parsed.has_value()) {
      return std::unexpected(parsed.error());
    }
    Request req(m, std::move(*parsed));
    req.body = std::move(payload);
    return req;
  }

  [[nodiscard]] static Result<Request> Get(std::string_view raw_uri) noexcept { return Build(Method::kGet, raw_uri); }

  [[nodiscard]] static Result<Request> Post(std::string_view raw_uri, Bytes payload) noexcept {
    return Build(Method::kPost, raw_uri, std::move(payload));
  }

  [[nodiscard]] static Result<Request> Post(std::string_view raw_uri, std::string_view payload) {
    return Build(Method::kPost, raw_uri, Bytes::CopyFromString(payload));
  }

  [[nodiscard]] static Request Post(Uri u, Bytes payload) noexcept {
    Request req(Method::kPost, std::move(u));
    req.body = std::move(payload);
    return req;
  }

  [[nodiscard]] static Request Post(Uri u, std::string_view payload) {
    return Post(std::move(u), Bytes::CopyFromString(payload));
  }

  [[nodiscard]] Result<void> SetHeader(std::string_view name, std::string_view value) noexcept {
    return headers.Set(name, value);
  }

  [[nodiscard]] Result<void> AddHeader(std::string_view name, std::string_view value) noexcept {
    return headers.Add(name, value);
  }
};

struct Response {
  StatusCode status{StatusCode::kOk};
  Version version{Version::kHttp11};
  Headers<> headers{};
  Bytes body{};
  Headers<> trailers{};

  Response() noexcept = default;

  explicit Response(StatusCode s, Bytes payload = {}) noexcept : status(s), body(std::move(payload)) {}

  [[nodiscard]] static Response Ok(Bytes payload = {}) noexcept {
    return Response(StatusCode{StatusCode::kOk}, std::move(payload));
  }

  [[nodiscard]] static Response Ok(std::string_view payload) noexcept {
    return Response(StatusCode{StatusCode::kOk}, Bytes::CopyFromString(payload));
  }

  [[nodiscard]] static Response WithStatus(StatusCode s, Bytes payload = {}) noexcept {
    return Response(s, std::move(payload));
  }

  [[nodiscard]] Result<void> SetHeader(std::string_view name, std::string_view value) noexcept {
    return headers.Set(name, value);
  }

  [[nodiscard]] Result<void> AddHeader(std::string_view name, std::string_view value) noexcept {
    return headers.Add(name, value);
  }
};

}  // namespace nexora
