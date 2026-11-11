/** @file @brief RFC 3986 URI parser, normalizer, and redirect resolver. */
#pragma once

#include <cstdint>
#include <nexora/http/detail/uri_parse.hpp>
#include <optional>
#include <string_view>

namespace nexora {

class Uri {
 public:
  constexpr Uri() noexcept {
    static_cast<void>(buf_.Append("http://localhost/"));
    authority_off_ = 7;
    authority_len_ = 9;
    host_off_ = 7;
    host_len_ = 9;
    path_off_ = 16;
    path_len_ = 1;
    path_and_query_len_ = 1;
  }

  [[nodiscard]] static constexpr Result<Uri> Parse(std::string_view raw) noexcept {
    const auto hash_pos = raw.find('#');
    const std::string_view without_fragment = (hash_pos == std::string_view::npos) ? raw : raw.substr(0uz, hash_pos);

    const auto scheme_sep = without_fragment.find("://");
    if (scheme_sep == std::string_view::npos) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
    }
    const std::string_view scheme_raw = without_fragment.substr(0uz, scheme_sep);
    nexora::Scheme scheme = nexora::Scheme::kHttp;
    if (AsciiEqualsIgnoreCase(scheme_raw, "http")) {
      scheme = nexora::Scheme::kHttp;
    } else if (AsciiEqualsIgnoreCase(scheme_raw, "https")) {
      scheme = nexora::Scheme::kHttps;
    } else if (AsciiEqualsIgnoreCase(scheme_raw, "ws")) {
      scheme = nexora::Scheme::kWs;
    } else if (AsciiEqualsIgnoreCase(scheme_raw, "wss")) {
      scheme = nexora::Scheme::kWss;
    } else {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
    }

    const std::string_view remainder = without_fragment.substr(scheme_sep + 3uz);
    const auto slash_pos = remainder.find('/');
    const auto q_pos = remainder.find('?');

    std::string_view authority_raw = remainder;
    std::string_view path_raw = "/";
    std::optional<std::string_view> query_raw;

    if (slash_pos != std::string_view::npos && (q_pos == std::string_view::npos || slash_pos < q_pos)) {
      authority_raw = remainder.substr(0uz, slash_pos);
      const std::string_view tail = remainder.substr(slash_pos);
      const auto tail_q = tail.find('?');
      if (tail_q != std::string_view::npos) {
        path_raw = tail.substr(0uz, tail_q);
        query_raw = tail.substr(tail_q + 1uz);
      } else {
        path_raw = tail;
      }
    } else if (q_pos != std::string_view::npos) {
      authority_raw = remainder.substr(0uz, q_pos);
      query_raw = remainder.substr(q_pos + 1uz);
    }

    auto auth_res = detail::ParseUriAuthority(authority_raw, scheme);
    if (!auth_res.has_value()) return std::unexpected(auth_res.error());
    if (path_raw.empty() || !path_raw.starts_with('/') || !detail::IsValidRequestChars(path_raw)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
    }
    if (query_raw.has_value() && !detail::IsValidRequestChars(*query_raw)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
    }
    return BuildUri(scheme, auth_res->host, auth_res->port, auth_res->explicit_port, auth_res->ipv6_literal, path_raw,
                    query_raw);
  }

  [[nodiscard]] constexpr nexora::Scheme Scheme() const noexcept { return scheme_; }
  [[nodiscard]] constexpr std::string_view Host() const noexcept { return buf_.Subview(host_off_, host_len_); }
  [[nodiscard]] constexpr std::uint16_t Port() const noexcept { return port_; }
  [[nodiscard]] constexpr std::uint16_t EffectivePort() const noexcept { return port_; }
  [[nodiscard]] constexpr std::optional<std::uint16_t> ExplicitPort() const noexcept { return explicit_port_; }
  [[nodiscard]] constexpr std::string_view Authority() const noexcept { return buf_.Subview(authority_off_, authority_len_); }
  [[nodiscard]] constexpr std::string_view Path() const noexcept { return buf_.Subview(path_off_, path_len_); }
  [[nodiscard]] constexpr std::optional<std::string_view> Query() const noexcept {
    return has_query_ ? std::optional<std::string_view>(buf_.Subview(query_off_, query_len_)) : std::nullopt;
  }
  [[nodiscard]] constexpr std::string_view PathAndQuery() const noexcept {
    return buf_.Subview(path_off_, path_and_query_len_);
  }
  [[nodiscard]] constexpr std::string_view AsStr() const noexcept { return buf_.View(); }
  [[nodiscard]] constexpr bool IsTls() const noexcept { return SchemeIsTls(scheme_); }
  [[nodiscard]] constexpr bool IsWebSocket() const noexcept { return SchemeIsWebSocket(scheme_); }

  [[nodiscard]] constexpr Result<Uri> ResolveRedirect(std::string_view location) const noexcept {
    if (detail::HasUriScheme(location)) {
      auto parsed = Parse(location);
      return parsed.has_value() ? parsed->WithNormalizedDotSegments() : parsed;
    }
    const auto hash_pos = location.find('#');
    const std::string_view without_fragment = (hash_pos == std::string_view::npos) ? location : location.substr(0uz, hash_pos);
    if (without_fragment.empty()) return *this;
    if (without_fragment.starts_with("//")) {
      detail::UriText<kMaxUriLength> abs;
      if (!abs.Append(SchemeAsStr(scheme_)) || !abs.PushBack(':') || !abs.Append(without_fragment)) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
      }
      auto parsed = Parse(abs.View());
      return parsed.has_value() ? parsed->WithNormalizedDotSegments() : parsed;
    }

    std::string_view ref_path = without_fragment;
    std::optional<std::string_view> ref_query;
    if (const auto q_pos = without_fragment.find('?'); q_pos != std::string_view::npos) {
      ref_path = without_fragment.substr(0uz, q_pos);
      ref_query = without_fragment.substr(q_pos + 1uz);
    }

    detail::UriText<kMaxUriLength> merged_path;
    std::optional<std::string_view> merged_query = ref_query;
    if (ref_path.empty()) {
      if (!merged_path.Append(Path())) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
      }
      merged_query = ref_query.has_value() ? ref_query : Query();
    } else if (ref_path.starts_with('/')) {
      auto norm = detail::RemoveDotSegments(ref_path);
      if (!norm.has_value()) return std::unexpected(norm.error());
      merged_path = *norm;
    } else {
      auto rel = detail::MergeRelativePath(Path(), ref_path);
      if (!rel.has_value()) return std::unexpected(rel.error());
      auto norm = detail::RemoveDotSegments(rel->View());
      if (!norm.has_value()) return std::unexpected(norm.error());
      merged_path = *norm;
    }

    if ((merged_query.has_value() && !detail::IsValidRequestChars(*merged_query)) ||
        !detail::IsValidRequestChars(merged_path.View())) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
    }
    return BuildUri(scheme_, Host(), port_, explicit_port_, ipv6_literal_, merged_path.View(), merged_query);
  }

  [[nodiscard]] friend constexpr bool operator==(const Uri& a, const Uri& b) noexcept { return a.AsStr() == b.AsStr(); }

 private:
  [[nodiscard]] static constexpr Result<Uri> BuildUri(nexora::Scheme scheme, std::string_view host_in, std::uint16_t port,
                                                      std::optional<std::uint16_t> explicit_port, bool ipv6_literal,
                                                      std::string_view path_in,
                                                      std::optional<std::string_view> query_in) noexcept {
    Uri u;
    u.buf_ = {};
    u.scheme_ = scheme;
    u.port_ = port;
    u.explicit_port_ = explicit_port;
    u.ipv6_literal_ = ipv6_literal;

    if (!u.buf_.Append(SchemeAsStr(scheme)) || !u.buf_.Append("://")) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
    }
    u.authority_off_ = u.buf_.Size();
    if (ipv6_literal && !u.buf_.PushBack('[')) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
    }
    u.host_off_ = u.buf_.Size();
    if (!u.buf_.Append(host_in)) return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
    u.host_len_ = static_cast<std::uint16_t>(host_in.size());
    u.buf_.LowercaseRange(u.host_off_, u.host_len_);
    if (ipv6_literal && !u.buf_.PushBack(']')) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
    }
    if (explicit_port.has_value()) {
      const auto port_text = detail::FormatDecimalU16(*explicit_port);
      if (!u.buf_.PushBack(':') || !u.buf_.Append(port_text.View())) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
      }
    }
    u.authority_len_ = static_cast<std::uint16_t>(u.buf_.Size() - u.authority_off_);
    u.path_off_ = u.buf_.Size();
    if (!u.buf_.Append(path_in)) return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
    u.path_len_ = static_cast<std::uint16_t>(path_in.size());
    if (query_in.has_value()) {
      if (!u.buf_.PushBack('?')) return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
      u.query_off_ = u.buf_.Size();
      if (!u.buf_.Append(*query_in)) return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
      u.query_len_ = static_cast<std::uint16_t>(query_in->size());
      u.has_query_ = true;
    } else {
      u.query_off_ = u.buf_.Size();
      u.query_len_ = 0;
      u.has_query_ = false;
    }
    u.path_and_query_len_ = static_cast<std::uint16_t>(u.buf_.Size() - u.path_off_);
    return u;
  }

  [[nodiscard]] constexpr Result<Uri> WithNormalizedDotSegments() const noexcept {
    auto norm = detail::RemoveDotSegments(Path());
    if (!norm.has_value()) return std::unexpected(norm.error());
    return BuildUri(scheme_, Host(), port_, explicit_port_, ipv6_literal_, norm->View(), Query());
  }

  detail::UriText<kMaxUriLength> buf_{};
  std::uint16_t authority_off_{0};
  std::uint16_t authority_len_{0};
  std::uint16_t host_off_{0};
  std::uint16_t host_len_{0};
  std::uint16_t path_off_{0};
  std::uint16_t path_len_{0};
  std::uint16_t query_off_{0};
  std::uint16_t query_len_{0};
  std::uint16_t path_and_query_len_{0};
  std::uint16_t port_{80};
  std::optional<std::uint16_t> explicit_port_{};
  nexora::Scheme scheme_{nexora::Scheme::kHttp};
  bool ipv6_literal_{false};
  bool has_query_{false};
};

}  // namespace nexora
