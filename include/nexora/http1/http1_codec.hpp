#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <nexora/http1/http1_body.hpp>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

namespace nexora {

template <std::size_t MaxHeader = 8192, std::size_t MaxBody = 16384>
class Http1ClientCodec {
 public:
  [[nodiscard]] bool EncodeClosed() const noexcept { return encode_closed_; }
  [[nodiscard]] bool DecodeClosed() const noexcept { return decode_closed_; }

  [[nodiscard]] Result<BytesMut<MaxHeader + MaxBody + 64>> EncodeRequest(const Request& req) noexcept {
    if (encode_closed_ || decode_closed_) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    if (req.body.Size() > MaxBody) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1MessageTooLarge));
    }
    if (req.version != Version::kHttp11 && req.version != Version::kHttp10) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    const std::string_view target = FormatTarget(req);
    if (target.empty()) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    for (char c : target) {
      const auto b = static_cast<unsigned char>(c);
      if (b <= 0x20U || b == 0x7fU) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
      }
    }
    http1_detail::HeadWriter<MaxHeader> head;
    auto method = head.Add(MethodAsStr(req.method));
    if (!method.has_value()) {
      return std::unexpected(method.error());
    }
    auto sp1 = head.Add(" ");
    if (!sp1.has_value()) {
      return std::unexpected(sp1.error());
    }
    auto path = head.Add(target);
    if (!path.has_value()) {
      return std::unexpected(path.error());
    }
    auto sp2 = head.Add(" ");
    if (!sp2.has_value()) {
      return std::unexpected(sp2.error());
    }
    auto version = head.Add(VersionAsStr(req.version));
    if (!version.has_value()) {
      return std::unexpected(version.error());
    }
    auto line = head.AddCrLf();
    if (!line.has_value()) {
      return std::unexpected(line.error());
    }
    auto fields = head.AddHeaders(req.headers);
    if (!fields.has_value()) {
      return std::unexpected(fields.error());
    }
    if (!req.headers.Contains("host")) {
      auto host_ok = http1_detail::ValidateAuthority(req.uri.Authority());
      if (!host_ok.has_value()) {
        return std::unexpected(host_ok.error());
      }
      auto host = head.Add("host: ");
      if (!host.has_value()) {
        return std::unexpected(host.error());
      }
      auto auth = head.Add(req.uri.Authority());
      if (!auth.has_value()) {
        return std::unexpected(auth.error());
      }
      auto crlf = head.AddCrLf();
      if (!crlf.has_value()) {
        return std::unexpected(crlf.error());
      }
    }
    auto framing = http1_detail::MessageFraming(req.headers, req.version);
    if (!framing.has_value()) {
      return std::unexpected(framing.error());
    }
    auto upgrade = http1_detail::ValidateUpgradeFraming(req.headers, *framing, req.body.Size());
    if (!upgrade.has_value()) {
      return std::unexpected(upgrade.error());
    }
    auto length = head.AddLength(*framing, req.body.Size());
    if (!length.has_value()) {
      return std::unexpected(length.error());
    }
    auto blank = head.AddCrLf();
    if (!blank.has_value()) {
      return std::unexpected(blank.error());
    }
    if (head.Size() > MaxHeader) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1MessageTooLarge));
    }
    auto framed = http1_detail::Assemble<MaxHeader + MaxBody + 64>(head.Bytes(), req.body.Span(), *framing);
    if (!framed.has_value()) {
      return framed;
    }
    encode_closed_ = http1_detail::Persistence(req.version, req.headers, false) != Http1KeepAlive::kKeepAlive;
    return framed;
  }

  [[nodiscard]] Result<std::optional<Http1Decoded<Response>>> DecodeResponse(std::span<const std::uint8_t> in,
                                                                             Method request_method = Method::kGet) noexcept {
    if (decode_closed_) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    std::size_t used = 0;
    if (phase_ == Phase::kHead) {
      auto ready = head_acc_.Push(in);
      if (!ready.has_value()) {
        ClearPartial();
        return std::unexpected(ready.error());
      }
      if (!ready->has_value()) {
        return std::optional<Http1Decoded<Response>>{};
      }
      used = (*ready)->consumed;
      auto opened = OpenResponse((*ready)->head, request_method);
      head_acc_.Reset();
      if (!opened.has_value()) {
        ClearPartial();
        return std::unexpected(opened.error());
      }
      if (phase_ == Phase::kHead) {
        return FinishResponse(http1_detail::BodyReady{}, used);
      }
      in = in.subspan(used);
    }
    auto pushed = body_.Push(in);
    if (!pushed.has_value()) {
      ClearPartial();
      return std::unexpected(pushed.error());
    }
    if (!pushed->has_value()) {
      return std::optional<Http1Decoded<Response>>{};
    }
    return FinishResponse(std::move(**pushed), used + (*pushed)->consumed);
  }

  void Reset() noexcept {
    encode_closed_ = false;
    decode_closed_ = false;
    connect_len_ = 0;
    ClearPartial();
  }

 private:
  enum class Phase : std::uint8_t { kHead, kBody };

  void ClearPartial() noexcept {
    phase_ = Phase::kHead;
    head_acc_.Reset();
    body_.Reset();
    pending_headers_ = {};
    pending_upgrade_ = false;
    pending_final_ = false;
    pending_keep_ = Http1KeepAlive::kKeepAlive;
  }

  [[nodiscard]] Result<void> OpenResponse(const http1_detail::Head& head, Method request_method) noexcept {
    const auto start = head.start;
    const auto sp1 = start.find(' ');
    const auto sp2 = (sp1 == std::string_view::npos) ? sp1 : start.find(' ', sp1 + 1);
    if (sp1 == std::string_view::npos || sp2 == std::string_view::npos) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    auto version = ParseHttp1Version(start.substr(0, sp1));
    if (!version.has_value()) {
      return std::unexpected(version.error());
    }
    const auto code = start.substr(sp1 + 1, sp2 - (sp1 + 1));
    if (code.size() != 3 || code[0] < '0' || code[0] > '9' || code[1] < '0' || code[1] > '9' || code[2] < '0' ||
        code[2] > '9') {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidStatus));
    }
    const auto status_raw = static_cast<std::uint16_t>((code[0] - '0') * 100 + (code[1] - '0') * 10 + (code[2] - '0'));
    auto status = StatusCode::FromU16(status_raw);
    if (!status.has_value()) {
      return std::unexpected(status.error());
    }
    if (!IsValidHeaderValue(start.substr(sp2 + 1))) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
    }
    const bool connect_tunnel = request_method == Method::kConnect && status->IsSuccess();
    http1_detail::Framing framing{};
    if (!connect_tunnel) {
      auto parsed = http1_detail::MessageFraming(head.headers, *version);
      if (!parsed.has_value()) {
        return std::unexpected(parsed.error());
      }
      framing = *parsed;
    }
    auto status_ok = http1_detail::ValidateStatusFraming(*status, framing);
    if (!status_ok.has_value()) {
      return std::unexpected(status_ok.error());
    }
    const bool upgrade = status->AsU16() == StatusCode::kSwitchingProtocols || connect_tunnel;
    const bool bodyless = request_method == Method::kHead || status->IsInformational() ||
                          status->AsU16() == StatusCode::kNoContent || status->AsU16() == 304 || upgrade;
    if (!bodyless && framing.kind == http1_detail::Framing::Kind::kAbsent) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    pending_version_ = *version;
    pending_status_ = *status;
    pending_headers_ = head.headers;
    pending_upgrade_ = upgrade;
    pending_keep_ = http1_detail::Persistence(*version, head.headers, upgrade);
    if (encode_closed_ && !status->IsInformational() && !upgrade) {
      pending_keep_ = Http1KeepAlive::kClose;
    }
    pending_final_ = !status->IsInformational() || upgrade;
    if (bodyless) {
      phase_ = Phase::kHead;
      return {};
    }
    auto began = body_.Begin(framing, head.head_len, MaxHeader);
    if (!began.has_value()) {
      return std::unexpected(began.error());
    }
    phase_ = Phase::kBody;
    return {};
  }

  [[nodiscard]] Result<std::optional<Http1Decoded<Response>>> FinishResponse(http1_detail::BodyReady parts,
                                                                             std::size_t consumed) noexcept {
    if (pending_status_.AsU16() == 205 && !parts.body.Empty()) {
      ClearPartial();
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    Response response;
    response.status = pending_status_;
    response.version = pending_version_;
    response.headers = std::move(pending_headers_);
    response.body = std::move(parts.body);
    response.trailers = std::move(parts.trailers);
    const auto keep = pending_keep_;
    const bool final_response = pending_final_;
    ClearPartial();
    if (final_response) {
      decode_closed_ = encode_closed_ || keep != Http1KeepAlive::kKeepAlive;
    }
    Http1Decoded<Response> decoded;
    decoded.message = std::move(response);
    decoded.keep_alive = keep;
    decoded.consumed = consumed;
    return std::optional<Http1Decoded<Response>>(std::move(decoded));
  }

  [[nodiscard]] std::string_view FormatTarget(const Request& req) noexcept {
    if (req.method == Method::kOptions && req.uri.PathAndQuery() == "/*") {
      return "*";
    }
    if (req.method != Method::kConnect) {
      return req.uri.PathAndQuery();
    }
    const auto authority = req.uri.Authority();
    if (http1_detail::AuthorityHasPort(authority)) {
      return authority;
    }
    const auto port = req.uri.EffectivePort();
    std::array<char, 5> rev{};
    std::size_t digits = 0;
    auto value = port;
    do {
      rev[digits++] = static_cast<char>('0' + static_cast<unsigned>(value % 10U));
      value = static_cast<std::uint16_t>(value / 10U);
    } while (value > 0 && digits < rev.size());
    if (authority.size() + 1 + digits > connect_target_.size()) {
      connect_len_ = 0;
      return {};
    }
    std::memcpy(connect_target_.data(), authority.data(), authority.size());
    connect_target_[authority.size()] = ':';
    for (std::size_t i = 0; i < digits; ++i) {
      connect_target_[authority.size() + 1 + i] = rev[digits - 1 - i];
    }
    connect_len_ = authority.size() + 1 + digits;
    return {connect_target_.data(), connect_len_};
  }

  bool encode_closed_{false};
  bool decode_closed_{false};
  std::array<char, 2048> connect_target_{};
  std::size_t connect_len_{0};
  Phase phase_{Phase::kHead};
  http1_detail::HeadAccum<MaxHeader> head_acc_{};
  http1_detail::BodyFeed<MaxBody, MaxHeader> body_{};
  Version pending_version_{Version::kHttp11};
  StatusCode pending_status_{};
  Headers<> pending_headers_{};
  Http1KeepAlive pending_keep_{Http1KeepAlive::kKeepAlive};
  bool pending_upgrade_{false};
  bool pending_final_{false};
};

template <std::size_t MaxHeader = 8192, std::size_t MaxBody = 16384>
class Http1ServerCodec {
 public:
  [[nodiscard]] bool EncodeClosed() const noexcept { return encode_closed_; }
  [[nodiscard]] bool DecodeClosed() const noexcept { return decode_closed_; }

  [[nodiscard]] Result<std::optional<Http1Decoded<Request>>> DecodeRequest(std::span<const std::uint8_t> in) noexcept {
    if (encode_closed_ || decode_closed_) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    std::size_t used = 0;
    if (phase_ == Phase::kHead) {
      auto ready = head_acc_.Push(in);
      if (!ready.has_value()) {
        ClearPartial();
        return std::unexpected(ready.error());
      }
      if (!ready->has_value()) {
        return std::optional<Http1Decoded<Request>>{};
      }
      used = (*ready)->consumed;
      auto opened = OpenRequest((*ready)->head);
      head_acc_.Reset();
      if (!opened.has_value()) {
        ClearPartial();
        return std::unexpected(opened.error());
      }
      if (phase_ == Phase::kHead) {
        return FinishRequest(http1_detail::BodyReady{}, used);
      }
      in = in.subspan(used);
    }
    auto pushed = body_.Push(in);
    if (!pushed.has_value()) {
      ClearPartial();
      return std::unexpected(pushed.error());
    }
    if (!pushed->has_value()) {
      return std::optional<Http1Decoded<Request>>{};
    }
    return FinishRequest(std::move(**pushed), used + (*pushed)->consumed);
  }

  [[nodiscard]] Result<BytesMut<MaxHeader + MaxBody + 64>> EncodeResponse(const Response& resp,
                                                                          Method request_method = Method::kGet) noexcept {
    if (encode_closed_) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    if (resp.body.Size() > MaxBody) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1MessageTooLarge));
    }
    if (resp.version != Version::kHttp11 && resp.version != Version::kHttp10) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    auto status = StatusCode::FromU16(resp.status.AsU16());
    if (!status.has_value()) {
      return std::unexpected(status.error());
    }
    const bool status_bodyless =
        status->IsInformational() || status->AsU16() == StatusCode::kNoContent || status->AsU16() == 304;
    if ((status_bodyless || status->AsU16() == 205) && !resp.body.Empty()) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    http1_detail::HeadWriter<MaxHeader> head;
    auto version = head.Add(VersionAsStr(resp.version));
    if (!version.has_value()) {
      return std::unexpected(version.error());
    }
    auto sp = head.Add(" ");
    if (!sp.has_value()) {
      return std::unexpected(sp.error());
    }
    const auto code = status->AsU16();
    const std::array<char, 3> digits{
        static_cast<char>('0' + static_cast<unsigned>(code / 100U)),
        static_cast<char>('0' + static_cast<unsigned>((code / 10U) % 10U)),
        static_cast<char>('0' + static_cast<unsigned>(code % 10U)),
    };
    auto number = head.Add(std::string_view(digits.data(), digits.size()));
    if (!number.has_value()) {
      return std::unexpected(number.error());
    }
    auto gap = head.Add(" ");
    if (!gap.has_value()) {
      return std::unexpected(gap.error());
    }
    auto phrase = head.Add(status->ReasonPhrase());
    if (!phrase.has_value()) {
      return std::unexpected(phrase.error());
    }
    auto line = head.AddCrLf();
    if (!line.has_value()) {
      return std::unexpected(line.error());
    }
    auto fields = head.AddHeaders(resp.headers);
    if (!fields.has_value()) {
      return std::unexpected(fields.error());
    }
    auto framing = http1_detail::MessageFraming(resp.headers, resp.version);
    if (!framing.has_value()) {
      return std::unexpected(framing.error());
    }
    auto status_ok = http1_detail::ValidateStatusFraming(*status, *framing);
    if (!status_ok.has_value()) {
      return std::unexpected(status_ok.error());
    }
    if (!status_bodyless) {
      auto length = head.AddLength(*framing, resp.body.Size());
      if (!length.has_value()) {
        return std::unexpected(length.error());
      }
    }
    auto blank = head.AddCrLf();
    if (!blank.has_value()) {
      return std::unexpected(blank.error());
    }
    if (head.Size() > MaxHeader) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1MessageTooLarge));
    }
    const bool suppress = status_bodyless || request_method == Method::kHead;
    const http1_detail::Framing written = suppress ? http1_detail::Framing{} : *framing;
    const auto payload = suppress ? std::span<const std::uint8_t>{} : resp.body.Span();
    auto framed = http1_detail::Assemble<MaxHeader + MaxBody + 64>(head.Bytes(), payload, written);
    if (!framed.has_value()) {
      return framed;
    }
    const bool upgrade = status->AsU16() == StatusCode::kSwitchingProtocols;
    if (!status->IsInformational() || upgrade) {
      const auto keep = http1_detail::Persistence(resp.version, resp.headers, upgrade);
      // A request decoded later must not block a response that was already queued.
      encode_closed_ = keep != Http1KeepAlive::kKeepAlive;
    }
    return framed;
  }

  void Reset() noexcept {
    encode_closed_ = false;
    decode_closed_ = false;
    ClearPartial();
  }

 private:
  enum class Phase : std::uint8_t { kHead, kBody };

  void ClearPartial() noexcept {
    phase_ = Phase::kHead;
    head_acc_.Reset();
    body_.Reset();
    pending_headers_ = {};
    pending_uri_ = {};
    pending_keep_ = Http1KeepAlive::kKeepAlive;
  }

  [[nodiscard]] Result<void> OpenRequest(const http1_detail::Head& head) noexcept {
    const auto start = head.start;
    const auto sp1 = start.find(' ');
    const auto sp2 = (sp1 == std::string_view::npos) ? sp1 : start.find(' ', sp1 + 1);
    if (sp1 == std::string_view::npos || sp2 == std::string_view::npos || start.find(' ', sp2 + 1) != std::string_view::npos) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    auto method = ParseMethod(start.substr(0, sp1));
    if (!method.has_value()) {
      return std::unexpected(method.error());
    }
    const auto target = start.substr(sp1 + 1, sp2 - (sp1 + 1));
    auto version = ParseHttp1Version(start.substr(sp2 + 1));
    if (!version.has_value()) {
      return std::unexpected(version.error());
    }
    if (target.empty()) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    for (char c : target) {
      const auto b = static_cast<unsigned char>(c);
      if (b <= 0x20U || b == 0x7fU || b == '#') {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
      }
    }
    auto uri = http1_detail::RequestTarget(*method, target, *version, head.headers);
    if (!uri.has_value()) {
      return std::unexpected(uri.error());
    }
    auto framing = http1_detail::MessageFraming(head.headers, *version);
    if (!framing.has_value()) {
      return std::unexpected(framing.error());
    }
    auto upgrade_body = http1_detail::ValidateUpgradeFraming(head.headers, *framing, 0);
    if (!upgrade_body.has_value()) {
      return std::unexpected(upgrade_body.error());
    }
    const bool upgrade = http1_detail::HasToken(head.headers, "upgrade", "websocket");
    pending_method_ = *method;
    pending_uri_ = std::move(*uri);
    pending_version_ = *version;
    pending_headers_ = head.headers;
    pending_keep_ = http1_detail::Persistence(*version, head.headers, upgrade);
    if (upgrade) {
      phase_ = Phase::kHead;
      return {};
    }
    auto began = body_.Begin(*framing, head.head_len, MaxHeader);
    if (!began.has_value()) {
      return std::unexpected(began.error());
    }
    phase_ = Phase::kBody;
    return {};
  }

  [[nodiscard]] Result<std::optional<Http1Decoded<Request>>> FinishRequest(http1_detail::BodyReady parts,
                                                                           std::size_t consumed) noexcept {
    Request request;
    request.method = pending_method_;
    request.uri = std::move(pending_uri_);
    request.version = pending_version_;
    request.headers = std::move(pending_headers_);
    request.body = std::move(parts.body);
    request.trailers = std::move(parts.trailers);
    const auto keep = pending_keep_;
    ClearPartial();
    decode_closed_ = keep != Http1KeepAlive::kKeepAlive;
    Http1Decoded<Request> decoded;
    decoded.message = std::move(request);
    decoded.keep_alive = keep;
    decoded.consumed = consumed;
    return std::optional<Http1Decoded<Request>>(std::move(decoded));
  }

  bool encode_closed_{false};
  bool decode_closed_{false};
  Phase phase_{Phase::kHead};
  http1_detail::HeadAccum<MaxHeader> head_acc_{};
  http1_detail::BodyFeed<MaxBody, MaxHeader> body_{};
  Method pending_method_{Method::kGet};
  Uri pending_uri_{};
  Version pending_version_{Version::kHttp11};
  Headers<> pending_headers_{};
  Http1KeepAlive pending_keep_{Http1KeepAlive::kKeepAlive};
};

}  // namespace nexora
