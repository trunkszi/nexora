/** @file @brief C++26 P2996 static reflection bindings for HTTP headers and REST requests. */
#pragma once

#include <array>
#include <charconv>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <meta>
#include <nexora/bytes/bytes.hpp>
#include <nexora/bytes/scan.hpp>
#include <nexora/error/runtime_error.hpp>
#include <nexora/http/headers.hpp>
#include <nexora/http/message.hpp>
#include <nexora/http/uri.hpp>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace nexora {

template <std::size_t Capacity = 128>
struct AttrText {
  std::array<char, Capacity> bytes{};
  std::size_t len{0};

  constexpr AttrText() noexcept = default;

  consteval AttrText(std::string_view sv) {
    if (sv.size() > Capacity) detail::InvalidHeaderName();
    len = sv.size();
    for (std::size_t i = 0uz; i < sv.size(); ++i) bytes[i] = sv[i];
  }

  [[nodiscard]] constexpr std::string_view View() const noexcept { return {bytes.data(), len}; }
  [[nodiscard]] constexpr bool empty() const noexcept { return len == 0; }
};

struct HeaderAttr {
  AttrText<64> name{};
  bool required{false};
  AttrText<128> default_value{};
  bool has_default{false};
};

[[nodiscard]] consteval HeaderAttr HeaderName(std::string_view name, bool required = false, std::string_view default_value = "",
                                              bool has_default = false) {
  return HeaderAttr{
      .name = AttrText<64>(ValidateHeaderNameLiteral(name)),
      .required = required,
      .default_value = AttrText<128>(ValidateHeaderValueLiteral(default_value)),
      .has_default = has_default,
  };
}

[[nodiscard]] consteval HeaderAttr HeaderWithDefault(std::string_view name, std::string_view default_value) {
  return HeaderName(name, false, default_value, true);
}

struct RestRoute {
  Method method{Method::kGet};
  AttrText<128> path{std::string_view("/")};
};

struct PathParam {};
struct QueryParam {
  AttrText<64> name{};
};
struct HeaderParam {
  AttrText<64> name{};
};
struct BodyParam {};

inline constexpr PathParam kPathParam{};
inline constexpr BodyParam kBodyParam{};

[[nodiscard]] consteval RestRoute Route(Method method, std::string_view path) {
  return RestRoute{.method = method, .path = AttrText<128>(path)};
}

[[nodiscard]] consteval QueryParam QueryField(std::string_view name = "") { return QueryParam{.name = AttrText<64>(name)}; }

[[nodiscard]] consteval HeaderParam HeaderFieldAttr(std::string_view name = "") {
  const std::string_view checked = name.empty() ? name : ValidateHeaderNameLiteral(name);
  return HeaderParam{.name = AttrText<64>(checked)};
}

namespace detail {

void DuplicateReflectedHeader();
void InvalidRestRoutePlaceholders();

[[nodiscard]] constexpr char LowerAsciiChar(char c) noexcept {
  return (c >= 'A' && c <= 'Z') ? static_cast<char>(c | 0x20) : c;
}

template <typename T>
struct IsStdOptional : std::false_type {};

template <typename U>
struct IsStdOptional<std::optional<U>> : std::true_type {
  using ValueType = U;
};

template <typename Annotation, std::meta::info entity>
[[nodiscard]] consteval std::size_t AnnotationCount() {
  std::size_t count = 0uz;
  template for (constexpr auto note : std::define_static_array(std::meta::annotations_of(entity))) {
    constexpr auto val = std::meta::constant_of(note);
    if constexpr (std::meta::remove_cv(std::meta::type_of(val)) == ^^Annotation) ++count;
  }
  return count;
}

template <typename Annotation, std::meta::info entity>
[[nodiscard]] consteval Annotation ExtractAnnotation() {
  Annotation result{};
  template for (constexpr auto note : std::define_static_array(std::meta::annotations_of(entity))) {
    constexpr auto val = std::meta::constant_of(note);
    if constexpr (std::meta::remove_cv(std::meta::type_of(val)) == ^^Annotation) {
      result = std::meta::extract<Annotation>(val);
    }
  }
  return result;
}

template <std::meta::info member>
[[nodiscard]] consteval AttrText<64> ResolvedHeaderName() {
  AttrText<64> raw_text{std::meta::identifier_of(member)};
  bool from_ident = true;
  if constexpr (AnnotationCount<HeaderAttr, member>() > 0uz) {
    constexpr HeaderAttr attr = ExtractAnnotation<HeaderAttr, member>();
    if (!attr.name.empty()) {
      raw_text = attr.name;
      from_ident = false;
    }
  }
  if constexpr (AnnotationCount<HeaderParam, member>() > 0uz) {
    constexpr HeaderParam attr = ExtractAnnotation<HeaderParam, member>();
    if (!attr.name.empty()) {
      raw_text = attr.name;
      from_ident = false;
    }
  }
  AttrText<64> out{};
  const std::string_view raw = raw_text.View();
  if (raw.size() > 64uz) InvalidHeaderName();
  out.len = raw.size();
  for (std::size_t i = 0uz; i < raw.size(); ++i) {
    const char c = raw[i];
    out.bytes[i] = (from_ident && c == '_') ? '-' : LowerAsciiChar(c);
  }
  return out;
}

template <typename T>
struct IsHeaderText : std::false_type {};

template <std::size_t InlineCap, std::size_t MaxCap>
struct IsHeaderText<HeaderText<InlineCap, MaxCap>> : std::true_type {};

template <typename T>
[[nodiscard]] constexpr Result<HeaderValueText> FormatScalarValue(const T& val) {
  HeaderValueText out{};
  if constexpr (std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view> || IsHeaderText<T>::value) {
    if (!out.TryAssign(std::string_view(val))) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    }
    return out;
  } else if constexpr (std::is_same_v<T, bool>) {
    if (!out.TryAssign(val ? "true" : "false")) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    }
    return out;
  } else if constexpr (std::integral<T>) {
    std::array<char, 32> buf{};
    auto [ptr, ec] = std::to_chars(buf.data(), buf.data() + buf.size(), val);
    if (ec != std::errc{} || !out.TryAssign(std::string_view(buf.data(), static_cast<std::size_t>(ptr - buf.data())))) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    }
    return out;
  } else {
    static_assert(sizeof(T) == 0, "Unsupported reflected field type");
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidArgument));
  }
}

template <typename T>
[[nodiscard]] inline Result<T> ParseScalarValue(std::string_view raw) {
  if constexpr (std::is_same_v<T, std::string>) {
    if (!IsValidHeaderValue(raw)) return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
    return std::string(raw);
  } else if constexpr (IsHeaderText<T>::value) {
    if (!IsValidHeaderValue(raw)) return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
    T out{};
    if (!out.TryAssign(raw)) return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    return out;
  } else if constexpr (std::is_same_v<T, bool>) {
    if (raw == "true" || raw == "1") return true;
    if (raw == "false" || raw == "0") return false;
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
  } else if constexpr (std::integral<T>) {
    if (raw.empty()) return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
    T parsed{};
    auto [ptr, ec] = std::from_chars(raw.data(), raw.data() + raw.size(), parsed);
    if (ec != std::errc{} || ptr != raw.data() + raw.size()) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
    }
    return parsed;
  } else {
    static_assert(sizeof(T) == 0, "Unsupported reflected field type");
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
  }
}

[[nodiscard]] constexpr Result<UriText<kMaxUriLength>> PercentEncodeRfc3986(std::string_view value) noexcept {
  constexpr std::string_view hex_digits = "0123456789ABCDEF";
  UriText<kMaxUriLength> out{};
  for (char ch : value) {
    const auto b = static_cast<unsigned char>(ch);
    const bool unreserved = (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || ch == '-' ||
                            ch == '.' || ch == '_' || ch == '~';
    const bool ok =
        unreserved ? out.PushBack(ch)
                   : (out.PushBack('%') && out.PushBack(hex_digits[(b >> 4U) & 0x0fU]) && out.PushBack(hex_digits[b & 0x0fU]));
    if (!ok) return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
  }
  return out;
}

template <typename T>
inline constexpr auto kMembersOf =
    std::define_static_array(std::meta::nonstatic_data_members_of(^^T, std::meta::access_context::unchecked()));

template <typename T>
[[nodiscard]] consteval bool HasUniqueHeaderNames() {
  std::array<AttrText<64>, kMembersOf<T>.size()> names{};
  std::size_t idx = 0uz;
  template for (constexpr auto member : kMembersOf<T>) {
    names[idx] = ResolvedHeaderName<member>();
    if (!IsValidHeaderName(names[idx].View())) return false;
    if constexpr (AnnotationCount<HeaderAttr, member>() > 0uz) {
      constexpr HeaderAttr attr = ExtractAnnotation<HeaderAttr, member>();
      if (!IsValidHeaderValue(attr.default_value.View())) return false;
    }
    ++idx;
  }
  for (std::size_t i = 0uz; i < names.size(); ++i) {
    for (std::size_t j = i + 1uz; j < names.size(); ++j) {
      if (names[i].View() == names[j].View()) return false;
    }
  }
  return true;
}

template <typename T>
[[nodiscard]] consteval bool ValidateHeaderStructShape() {
  static_assert(std::is_class_v<T>, "Header reflection requires a struct or class type");
  template for (constexpr auto member : kMembersOf<T>) {
    static_assert(AnnotationCount<HeaderAttr, member>() <= 1uz, "At most one HeaderAttr annotation is allowed per member");
  }
  if (!HasUniqueHeaderNames<T>()) DuplicateReflectedHeader();
  static_assert(HasUniqueHeaderNames<T>(), "DuplicateReflectedHeader");
  return true;
}

template <typename T>
[[nodiscard]] consteval bool ValidateRoutePlaceholders(std::string_view route_path) {
  std::array<std::string_view, 32> seen{};
  std::size_t seen_count = 0uz;
  std::string_view tail = route_path;

  while (true) {
    const auto open = tail.find('{');
    if (open == std::string_view::npos) {
      if (tail.contains('}')) return false;
      break;
    }
    if (tail.substr(0uz, open).contains('}')) return false;
    tail.remove_prefix(open + 1uz);
    const auto close = tail.find('}');
    if (close == std::string_view::npos || close == 0uz) return false;
    const std::string_view placeholder = tail.substr(0uz, close);
    if (placeholder.contains('{') || seen_count >= seen.size()) return false;
    for (std::size_t i = 0uz; i < seen_count; ++i) {
      if (seen[i] == placeholder) return false;
    }
    seen[seen_count++] = placeholder;
    bool matched_member = false;
    template for (constexpr auto member : kMembersOf<T>) {
      if constexpr (AnnotationCount<PathParam, member>() > 0uz) {
        if (std::meta::identifier_of(member) == placeholder) matched_member = true;
      }
    }
    if (!matched_member) return false;
    tail.remove_prefix(close + 1uz);
  }

  std::size_t path_param_members = 0uz;
  template for (constexpr auto member : kMembersOf<T>) {
    if constexpr (AnnotationCount<PathParam, member>() > 0uz) ++path_param_members;
  }
  return path_param_members == seen_count;
}

template <typename T>
[[nodiscard]] consteval bool ValidateRestStructShape() {
  static_assert(std::is_class_v<T>, "REST request reflection requires a struct or class type");
  static_assert(AnnotationCount<RestRoute, ^^T>() == 1uz,
                "REST request struct must have exactly one [[=Route(method, path)]] annotation");
  constexpr RestRoute route = ExtractAnnotation<RestRoute, ^^T>();
  static_assert(!route.path.empty() && route.path.View().starts_with('/') && !route.path.View().contains('?') &&
                    !route.path.View().contains('#'),
                "REST route path must start with '/' and exclude query or fragment");
  if (!ValidateRoutePlaceholders<T>(route.path.View())) InvalidRestRoutePlaceholders();
  static_assert(ValidateRoutePlaceholders<T>(route.path.View()), "InvalidRestRoutePlaceholders");

  std::size_t body_count = 0uz;
  template for (constexpr auto member : kMembersOf<T>) {
    using RawMemberType = [:std::meta::type_of(member):];
    using MemberType = std::remove_cvref_t<RawMemberType>;
    constexpr std::size_t placements = AnnotationCount<PathParam, member>() + AnnotationCount<QueryParam, member>() +
                                       AnnotationCount<HeaderParam, member>() + AnnotationCount<BodyParam, member>();
    static_assert(placements <= 1uz, "A field can have at most one REST parameter placement");
    if constexpr (AnnotationCount<PathParam, member>() > 0uz) {
      static_assert(!IsStdOptional<MemberType>::value, "REST path parameters cannot be std::optional");
    }
    if constexpr (AnnotationCount<BodyParam, member>() > 0uz) ++body_count;
  }
  if (body_count > 1uz) {
    InvalidRestRoutePlaceholders();
    return false;
  }
  return true;
}

}  // namespace detail

template <std::size_t MaxFields = 64, typename T>
[[nodiscard]] Result<Headers<MaxFields>> ReflectToHeaders(const T& input) {
  static_assert(detail::ValidateHeaderStructShape<T>());
  Headers<MaxFields> headers;

  template for (constexpr auto member : detail::kMembersOf<T>) {
    using RawMemberType = [:std::meta::type_of(member):];
    using MemberType = std::remove_cvref_t<RawMemberType>;
    constexpr AttrText<64> hdr_name = detail::ResolvedHeaderName<member>();
    if constexpr (detail::IsStdOptional<MemberType>::value) {
      const auto& opt_val = input.[:member:];
      if (opt_val.has_value()) {
        const auto formatted = detail::FormatScalarValue(*opt_val);
        if (!formatted.has_value()) return std::unexpected(formatted.error());
        if (auto res = headers.Set(hdr_name.View(), formatted->View()); !res.has_value()) {
          return std::unexpected(res.error());
        }
      }
    } else {
      const auto formatted = detail::FormatScalarValue(input.[:member:]);
      if (!formatted.has_value()) return std::unexpected(formatted.error());
      if (auto res = headers.Set(hdr_name.View(), formatted->View()); !res.has_value()) {
        return std::unexpected(res.error());
      }
    }
  }
  return headers;
}

template <typename T, std::size_t MaxFields = 64>
[[nodiscard]] Result<T> ReflectFromHeaders(const Headers<MaxFields>& headers) {
  static_assert(detail::ValidateHeaderStructShape<T>());
  T output{};

  template for (constexpr auto member : detail::kMembersOf<T>) {
    using RawMemberType = [:std::meta::type_of(member):];
    using MemberType = std::remove_cvref_t<RawMemberType>;
    constexpr bool has_attr = detail::AnnotationCount<HeaderAttr, member>() > 0uz;
    constexpr HeaderAttr attr = has_attr ? detail::ExtractAnnotation<HeaderAttr, member>() : HeaderAttr{};
    constexpr AttrText<64> hdr_name = detail::ResolvedHeaderName<member>();
    const auto found = headers.Get(hdr_name.View());

    if constexpr (detail::IsStdOptional<MemberType>::value) {
      using InnerType = typename detail::IsStdOptional<MemberType>::ValueType;
      if (found.has_value()) {
        auto parsed = detail::ParseScalarValue<InnerType>(*found);
        if (!parsed.has_value()) return std::unexpected(parsed.error());
        output.[:member:] = std::move(*parsed);
      } else if (attr.has_default) {
        auto parsed = detail::ParseScalarValue<InnerType>(attr.default_value.View());
        if (!parsed.has_value()) return std::unexpected(parsed.error());
        output.[:member:] = std::move(*parsed);
      } else if (attr.required) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
      } else {
        output.[:member:] = std::nullopt;
      }
    } else {
      std::string_view raw_val{};
      if (found.has_value()) {
        raw_val = *found;
      } else if (attr.has_default) {
        raw_val = attr.default_value.View();
      } else {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
      }
      auto parsed = detail::ParseScalarValue<MemberType>(raw_val);
      if (!parsed.has_value()) return std::unexpected(parsed.error());
      output.[:member:] = std::move(*parsed);
    }
  }
  return output;
}

template <typename T>
[[nodiscard]] constexpr Result<detail::UriText<kMaxUriLength>> BuildRestPathAndQuery(const T& req_struct) {
  static_assert(detail::ValidateRestStructShape<T>());
  constexpr RestRoute route = detail::ExtractAnnotation<RestRoute, ^^T>();

  detail::UriText<kMaxUriLength> path_out;
  std::string_view tail = route.path.View();
  while (true) {
    const auto open = tail.find('{');
    if (open == std::string_view::npos) {
      if (!path_out.Append(tail)) return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
      break;
    }
    if (!path_out.Append(tail.substr(0uz, open))) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    }
    tail.remove_prefix(open + 1uz);
    const auto close = tail.find('}');
    if (close == std::string_view::npos) {
      if (!path_out.Append(tail)) return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
      break;
    }
    const std::string_view param_name = tail.substr(0uz, close);
    tail.remove_prefix(close + 1uz);

    template for (constexpr auto member : detail::kMembersOf<T>) {
      if constexpr (detail::AnnotationCount<PathParam, member>() > 0uz) {
        if (std::meta::identifier_of(member) == param_name) {
          const auto formatted = detail::FormatScalarValue(req_struct.[:member:]);
          if (!formatted.has_value()) return std::unexpected(formatted.error());
          const auto encoded = detail::PercentEncodeRfc3986(formatted->View());
          if (!encoded.has_value()) return std::unexpected(encoded.error());
          if (!path_out.Append(encoded->View())) {
            return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
          }
        }
      }
    }
  }

  bool query_started = false;
  template for (constexpr auto member : detail::kMembersOf<T>) {
    if constexpr (detail::AnnotationCount<QueryParam, member>() > 0uz) {
      using RawMemberType = [:std::meta::type_of(member):];
      using MemberType = std::remove_cvref_t<RawMemberType>;
      constexpr QueryParam query_attr = detail::ExtractAnnotation<QueryParam, member>();
      constexpr std::string_view ident = std::meta::identifier_of(member);
      const std::string_view q_name = query_attr.name.empty() ? ident : query_attr.name.View();
      const auto enc_name = detail::PercentEncodeRfc3986(q_name);
      if (!enc_name.has_value()) return std::unexpected(enc_name.error());

      std::optional<HeaderValueText> fmt_val;
      if constexpr (detail::IsStdOptional<MemberType>::value) {
        if (req_struct.[:member:].has_value()) {
          auto fv = detail::FormatScalarValue(*req_struct.[:member:]);
          if (!fv.has_value()) return std::unexpected(fv.error());
          fmt_val = std::move(*fv);
        }
      } else {
        auto fv = detail::FormatScalarValue(req_struct.[:member:]);
        if (!fv.has_value()) return std::unexpected(fv.error());
        fmt_val = std::move(*fv);
      }
      if (fmt_val.has_value()) {
        const auto enc_val = detail::PercentEncodeRfc3986(fmt_val->View());
        if (!enc_val.has_value()) return std::unexpected(enc_val.error());
        if (!path_out.PushBack(query_started ? '&' : '?') || !path_out.Append(enc_name->View()) || !path_out.PushBack('=') ||
            !path_out.Append(enc_val->View())) {
          return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
        }
        query_started = true;
      }
    }
  }
  return path_out;
}

template <typename T>
[[nodiscard]] Result<Request> BuildRestRequest(const T& req_struct, std::string_view base_url) {
  static_assert(detail::ValidateRestStructShape<T>());
  constexpr RestRoute route = detail::ExtractAnnotation<RestRoute, ^^T>();

  if (base_url.contains('?') || base_url.contains('#')) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
  }
  auto base_check = Uri::Parse(base_url);
  if (!base_check.has_value()) return std::unexpected(base_check.error());

  std::string_view trimmed_base = base_url;
  while (trimmed_base.ends_with('/')) trimmed_base.remove_suffix(1uz);
  const auto pq = BuildRestPathAndQuery(req_struct);
  if (!pq.has_value()) return std::unexpected(pq.error());
  detail::UriText<kMaxUriLength> full_url;
  if (!full_url.Append(trimmed_base) || !full_url.Append(pq->View())) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidUri));
  }

  auto parsed_uri = Uri::Parse(full_url.View());
  if (!parsed_uri.has_value()) return std::unexpected(parsed_uri.error());

  Request req(route.method, std::move(*parsed_uri));

  template for (constexpr auto member : detail::kMembersOf<T>) {
    using RawMemberType = [:std::meta::type_of(member):];
    using MemberType = std::remove_cvref_t<RawMemberType>;
    if constexpr (detail::AnnotationCount<HeaderParam, member>() > 0uz || detail::AnnotationCount<HeaderAttr, member>() > 0uz) {
      constexpr AttrText<64> hdr_name = detail::ResolvedHeaderName<member>();
      if constexpr (detail::IsStdOptional<MemberType>::value) {
        const auto& opt_val = req_struct.[:member:];
        if (opt_val.has_value()) {
          const auto fmt_val = detail::FormatScalarValue(*opt_val);
          if (!fmt_val.has_value()) return std::unexpected(fmt_val.error());
          if (auto res = req.SetHeader(hdr_name.View(), fmt_val->View()); !res.has_value()) {
            return std::unexpected(res.error());
          }
        }
      } else {
        const auto fmt_val = detail::FormatScalarValue(req_struct.[:member:]);
        if (!fmt_val.has_value()) return std::unexpected(fmt_val.error());
        if (auto res = req.SetHeader(hdr_name.View(), fmt_val->View()); !res.has_value()) {
          return std::unexpected(res.error());
        }
      }
    } else if constexpr (detail::AnnotationCount<BodyParam, member>() > 0uz) {
      if constexpr (std::is_same_v<MemberType, Bytes>) {
        req.body = req_struct.[:member:];
      } else if constexpr (std::is_same_v<MemberType, std::string> || std::is_same_v<MemberType, std::string_view>) {
        req.body = Bytes::CopyFromString(req_struct.[:member:]);
      } else if constexpr (detail::IsStdOptional<MemberType>::value) {
        if (req_struct.[:member:].has_value()) {
          req.body = Bytes::CopyFromString(*req_struct.[:member:]);
        }
      }
    }
  }
  return req;
}

template <typename T>
[[nodiscard]] Result<Request> ReflectToRequest(const T& req_struct, std::string_view base_url) {
  return BuildRestRequest(req_struct, base_url);
}

}  // namespace nexora
