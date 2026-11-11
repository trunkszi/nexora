/** @file @brief Owned inline-first HTTP header fields, HeaderText, and Headers container. */
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <nexora/bytes/scan.hpp>
#include <nexora/error/runtime_error.hpp>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <uarch/primitives.hpp>
#include <utility>

namespace nexora {

template <std::size_t InlineCap, std::size_t MaxCap = InlineCap>
class HeaderText {
  static_assert(InlineCap > 0 && MaxCap >= InlineCap && MaxCap <= 65535);

 public:
  constexpr HeaderText() noexcept = default;

  constexpr HeaderText(const HeaderText& other) : len_(other.len_) { CopyFrom(other); }

  constexpr HeaderText& operator=(const HeaderText& other) {
    if (this != &other) {
      len_ = other.len_;
      CopyFrom(other);
    }
    return *this;
  }

  constexpr HeaderText(HeaderText&& other) noexcept : len_(other.len_) { MoveFrom(std::move(other)); }

  constexpr HeaderText& operator=(HeaderText&& other) noexcept {
    if (this != &other) {
      len_ = other.len_;
      MoveFrom(std::move(other));
    }
    return *this;
  }

  [[nodiscard]] constexpr Result<void> TryAssign(std::string_view sv) {
    if (sv.size() > MaxCap) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    }
    len_ = static_cast<std::uint16_t>(sv.size());
    if (sv.size() <= InlineCap) {
      overflow_.clear();
      if consteval {
        for (std::size_t i = 0uz; i < sv.size(); ++i) {
          inline_[i] = sv[i];
        }
      } else {
        if (!sv.empty()) std::memcpy(inline_.data(), sv.data(), sv.size());
      }
      return {};
    }
    overflow_.assign(sv.data(), sv.size());
    return {};
  }

  [[nodiscard]] constexpr Result<void> TryAssignLower(std::string_view sv) {
    if (auto assigned = TryAssign(sv); !assigned) {
      return assigned;
    }
    AsciiLowerInPlace(std::span<char>(data(), len_));
    return {};
  }

  [[nodiscard]] constexpr std::string_view View() const noexcept { return std::string_view(data(), len_); }

  [[nodiscard]] constexpr std::string_view AsStringView() const noexcept { return View(); }

  [[nodiscard]] constexpr operator std::string_view() const noexcept { return View(); }

  template <typename Self>
  [[nodiscard]] constexpr auto* data(this Self& self) noexcept {
    return (self.len_ <= InlineCap) ? self.inline_.data() : self.overflow_.data();
  }

  [[nodiscard]] constexpr std::size_t size() const noexcept { return len_; }
  [[nodiscard]] constexpr bool empty() const noexcept { return len_ == 0; }
  [[nodiscard]] static constexpr std::size_t InlineCapacity() noexcept { return InlineCap; }
  [[nodiscard]] static constexpr std::size_t Capacity() noexcept { return MaxCap; }

  constexpr void Clear() noexcept {
    len_ = 0;
    overflow_.clear();
  }

  [[nodiscard]] friend constexpr bool operator==(const HeaderText& a, const HeaderText& b) noexcept {
    return a.View() == b.View();
  }

  [[nodiscard]] friend constexpr bool operator==(const HeaderText& a, std::string_view b) noexcept { return a.View() == b; }

  [[nodiscard]] friend constexpr bool operator==(std::string_view a, const HeaderText& b) noexcept { return a == b.View(); }

  [[nodiscard]] friend constexpr bool operator==(const HeaderText& a, const char* b) noexcept {
    return a.View() == std::string_view(b != nullptr ? b : "");
  }

  [[nodiscard]] friend constexpr bool operator==(const char* a, const HeaderText& b) noexcept {
    return std::string_view(a != nullptr ? a : "") == b.View();
  }

 private:
  constexpr void CopyFrom(const HeaderText& other) {
    if (len_ <= InlineCap) {
      overflow_.clear();
      if consteval {
        for (std::size_t i = 0uz; i < len_; ++i) {
          inline_[i] = other.inline_[i];
        }
      } else {
        if (len_ > 0) std::memcpy(inline_.data(), other.inline_.data(), len_);
      }
      return;
    }
    overflow_ = other.overflow_;
  }

  constexpr void MoveFrom(HeaderText&& other) noexcept {
    if (len_ <= InlineCap) {
      overflow_.clear();
      if consteval {
        for (std::size_t i = 0uz; i < len_; ++i) {
          inline_[i] = other.inline_[i];
        }
      } else {
        if (len_ > 0) std::memcpy(inline_.data(), other.inline_.data(), len_);
      }
      other.len_ = 0;
      return;
    }
    overflow_ = std::move(other.overflow_);
    other.len_ = 0;
  }

  std::array<char, InlineCap> inline_{};
  std::string overflow_{};
  std::uint16_t len_{0};
};

template <std::size_t Cap>
using FixedHeaderText = HeaderText<Cap, Cap>;

using HeaderNameText = HeaderText<64, 256>;
using HeaderValueText = HeaderText<128, 8192>;

namespace detail {

// Non-constexpr functions invoked only on consteval validation failure to trigger a compile error.
void InvalidHeaderName();
void InvalidHeaderValue();
void InvalidHttp2HeaderName();

[[nodiscard]] constexpr Result<std::size_t> ParseContentLengthPart(std::string_view part) noexcept {
  const std::string_view trimmed = TrimAsciiWhitespace(part);
  if (trimmed.empty()) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
  }
  std::size_t acc = 0uz;
  constexpr std::size_t max_before_mul = std::numeric_limits<std::size_t>::max() / 10uz;
  for (char c : trimmed) {
    if (c < '0' || c > '9') {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
    }
    const auto digit = static_cast<std::size_t>(c - '0');
    if (acc > max_before_mul || (acc == max_before_mul && digit > (std::numeric_limits<std::size_t>::max() % 10uz))) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
    }
    acc = acc * 10uz + digit;
  }
  return acc;
}

}  // namespace detail

[[nodiscard]] consteval std::string_view ValidateHeaderNameLiteral(std::string_view name) {
  if (!IsValidHeaderName(name) || name.size() > HeaderNameText::Capacity()) {
    detail::InvalidHeaderName();
  }
  return name;
}

[[nodiscard]] consteval std::string_view ValidateHeaderValueLiteral(std::string_view value) {
  if (!IsValidHeaderValue(value) || value.size() > HeaderValueText::Capacity()) {
    detail::InvalidHeaderValue();
  }
  return value;
}

[[nodiscard]] consteval std::string_view ValidateHttp2HeaderNameLiteral(std::string_view name) {
  if (!IsValidHttp2HeaderName(name, true) || name.size() > HeaderNameText::Capacity()) {
    detail::InvalidHttp2HeaderName();
  }
  return name;
}

struct CheckedHeaderPair {
  std::string_view name{};
  std::string_view value{};

  consteval CheckedHeaderPair(std::string_view n, std::string_view v)
      : name(ValidateHeaderNameLiteral(n)), value(ValidateHeaderValueLiteral(v)) {}
};

struct CheckedHttp2HeaderPair {
  std::string_view name{};
  std::string_view value{};

  consteval CheckedHttp2HeaderPair(std::string_view n, std::string_view v)
      : name(ValidateHttp2HeaderNameLiteral(n)), value(ValidateHeaderValueLiteral(v)) {}
};

struct HeaderField {
  HeaderNameText name{};
  HeaderValueText value{};

  [[nodiscard]] friend constexpr bool operator==(const HeaderField& a, const HeaderField& b) noexcept = default;
};

template <std::size_t MaxFields = 64>
class Headers {
  static_assert(MaxFields > 0, "Headers MaxFields must be greater than zero");

 public:
  constexpr Headers() noexcept = default;

  [[nodiscard]] static constexpr std::size_t Capacity() noexcept { return MaxFields; }

  [[nodiscard]] constexpr Result<void> Add(std::string_view name, std::string_view value) {
    if (!IsValidHeaderName(name)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderName));
    }
    if (!IsValidHeaderValue(value)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
    }
    if (fields_.size() >= MaxFields) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    }
    HeaderField field{};
    if (!field.name.TryAssignLower(name) || !field.value.TryAssign(value)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    }
    byte_size_ += field.name.size() + field.value.size();
    fields_.push_back(std::move(field));
    return {};
  }

  [[nodiscard]] constexpr Result<void> Append(std::string_view name, std::string_view value) { return Add(name, value); }

  [[nodiscard]] constexpr Result<void> Set(std::string_view name, std::string_view value) {
    if (!IsValidHeaderName(name)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderName));
    }
    if (!IsValidHeaderValue(value)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidHeaderValue));
    }
    HeaderNameText lower_name{};
    HeaderValueText val_text{};
    if (!lower_name.TryAssignLower(name) || !val_text.TryAssign(value)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    }
    std::optional<std::size_t> first_match;
    std::size_t write_idx = 0uz;
    for (std::size_t read_idx = 0uz; read_idx < fields_.size(); ++read_idx) {
      if (fields_[read_idx].name == lower_name) {
        if (!first_match.has_value()) {
          first_match = write_idx;
          if (write_idx != read_idx) {
            fields_[write_idx] = std::move(fields_[read_idx]);
          }
          ++write_idx;
        } else {
          byte_size_ -= fields_[read_idx].name.size() + fields_[read_idx].value.size();
        }
      } else {
        if (write_idx != read_idx) {
          fields_[write_idx] = std::move(fields_[read_idx]);
        }
        ++write_idx;
      }
    }
    while (fields_.size() > write_idx) {
      fields_.pop_back();
    }
    if (first_match.has_value()) {
      byte_size_ -= fields_[*first_match].value.size();
      byte_size_ += val_text.size();
      fields_[*first_match].value = std::move(val_text);
    } else {
      if (fields_.size() >= MaxFields) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
      }
      byte_size_ += lower_name.size() + val_text.size();
      fields_.push_back(HeaderField{.name = std::move(lower_name), .value = std::move(val_text)});
    }
    return {};
  }

  [[nodiscard]] constexpr Result<void> Insert(std::string_view name, std::string_view value) { return Set(name, value); }

  [[nodiscard]] constexpr std::optional<std::string_view> Get(std::string_view name) const noexcept {
    for (const auto& field : fields_) {
      if (AsciiEqualsIgnoreCase(field.name.View(), name)) {
        return field.value.View();
      }
    }
    return std::nullopt;
  }

  [[nodiscard]] constexpr uarch::inplace_vector<std::string_view, MaxFields> GetAll(std::string_view name) const noexcept {
    uarch::inplace_vector<std::string_view, MaxFields> matches;
    for (const auto& field : fields_) {
      if (AsciiEqualsIgnoreCase(field.name.View(), name)) {
        matches.push_back(field.value.View());
      }
    }
    return matches;
  }

  [[nodiscard]] constexpr bool Contains(std::string_view name) const noexcept { return Get(name).has_value(); }

  [[nodiscard]] constexpr std::optional<HeaderValueText> Remove(std::string_view name) noexcept {
    std::optional<HeaderValueText> removed;
    std::size_t write_idx = 0uz;
    for (std::size_t read_idx = 0uz; read_idx < fields_.size(); ++read_idx) {
      if (AsciiEqualsIgnoreCase(fields_[read_idx].name.View(), name)) {
        byte_size_ -= fields_[read_idx].name.size() + fields_[read_idx].value.size();
        if (!removed.has_value()) {
          removed = std::move(fields_[read_idx].value);
        }
      } else {
        if (write_idx != read_idx) {
          fields_[write_idx] = std::move(fields_[read_idx]);
        }
        ++write_idx;
      }
    }
    while (fields_.size() > write_idx) {
      fields_.pop_back();
    }
    return removed;
  }

  [[nodiscard]] constexpr std::size_t Size() const noexcept { return fields_.size(); }
  [[nodiscard]] constexpr bool Empty() const noexcept { return fields_.empty(); }
  [[nodiscard]] constexpr std::size_t ByteSize() const noexcept { return byte_size_; }

  [[nodiscard]] constexpr std::span<const HeaderField> Fields() const noexcept { return {fields_.data(), fields_.size()}; }

  [[nodiscard]] constexpr auto begin() const noexcept { return fields_.begin(); }
  [[nodiscard]] constexpr auto end() const noexcept { return fields_.end(); }

  constexpr void Clear() noexcept {
    fields_.clear();
    byte_size_ = 0;
  }

  [[nodiscard]] constexpr Result<std::optional<std::size_t>> ContentLength() const noexcept {
    std::optional<std::size_t> resolved;
    for (const auto& field : fields_) {
      if (field.name.View() != "content-length") {
        continue;
      }
      const std::string_view raw = field.value.View();
      std::size_t start = 0uz;
      while (true) {
        const auto comma = raw.find(',', start);
        const std::string_view part = (comma == std::string_view::npos) ? raw.substr(start) : raw.substr(start, comma - start);
        auto parsed = detail::ParseContentLengthPart(part);
        if (!parsed.has_value()) {
          return std::unexpected(parsed.error());
        }
        if (resolved.has_value() && *resolved != *parsed) {
          return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ConflictingFraming));
        }
        resolved = *parsed;
        if (comma == std::string_view::npos) {
          break;
        }
        start = comma + 1uz;
      }
    }
    return resolved;
  }

  [[nodiscard]] constexpr bool IsChunked() const noexcept {
    std::optional<std::string_view> last_coding;
    for (const auto& field : fields_) {
      if (field.name.View() != "transfer-encoding") {
        continue;
      }
      const std::string_view raw = field.value.View();
      std::size_t start = 0uz;
      while (true) {
        const auto comma = raw.find(',', start);
        const std::string_view part = (comma == std::string_view::npos) ? raw.substr(start) : raw.substr(start, comma - start);
        const std::string_view coding = TrimAsciiWhitespace(part);
        if (coding.empty()) {
          return false;
        }
        last_coding = coding;
        if (comma == std::string_view::npos) {
          break;
        }
        start = comma + 1uz;
      }
    }
    return last_coding.has_value() && AsciiEqualsIgnoreCase(*last_coding, "chunked");
  }

  [[nodiscard]] friend constexpr bool operator==(const Headers& a, const Headers& b) noexcept { return a.fields_ == b.fields_; }

 private:
  uarch::inplace_vector<HeaderField, MaxFields> fields_{};
  std::size_t byte_size_{0};
};

template <std::size_t MaxFields = 64>
[[nodiscard]] constexpr Result<Headers<MaxFields>> MakeHeaders(std::initializer_list<CheckedHeaderPair> pairs) {
  if (pairs.size() > MaxFields) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
  }
  Headers<MaxFields> headers;
  for (const auto& pair : pairs) {
    if (auto res = headers.Add(pair.name, pair.value); !res.has_value()) {
      return std::unexpected(res.error());
    }
  }
  return headers;
}

template <std::size_t MaxFields = 64>
[[nodiscard]] constexpr Result<uarch::inplace_vector<HeaderField, MaxFields>> MakeHttp2Headers(
    std::initializer_list<CheckedHttp2HeaderPair> pairs) {
  if (pairs.size() > MaxFields) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
  }
  uarch::inplace_vector<HeaderField, MaxFields> out;
  for (const auto& pair : pairs) {
    HeaderField field{};
    if (!field.name.TryAssign(pair.name) || !field.value.TryAssign(pair.value)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    }
    out.push_back(std::move(field));
  }
  return out;
}

}  // namespace nexora
