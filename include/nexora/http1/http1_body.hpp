#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <nexora/http1/http1_framing.hpp>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

namespace nexora::http1_detail {

[[nodiscard]] inline Result<void> ValidateChunkExtensions(std::string_view extension) noexcept {
  std::string_view remaining = extension;
  while (true) {
    while (!remaining.empty() && (remaining.front() == ' ' || remaining.front() == '\t')) {
      remaining.remove_prefix(1);
    }
    std::size_t name_len = 0;
    while (name_len < remaining.size() && TokenByte(static_cast<unsigned char>(remaining[name_len]))) {
      ++name_len;
    }
    if (name_len == 0) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    remaining.remove_prefix(name_len);
    while (!remaining.empty() && (remaining.front() == ' ' || remaining.front() == '\t')) {
      remaining.remove_prefix(1);
    }
    if (!remaining.empty() && remaining.front() == '=') {
      remaining.remove_prefix(1);
      while (!remaining.empty() && (remaining.front() == ' ' || remaining.front() == '\t')) {
        remaining.remove_prefix(1);
      }
      if (!remaining.empty() && remaining.front() == '"') {
        remaining.remove_prefix(1);
        bool closed = false;
        while (!remaining.empty()) {
          const char byte = remaining.front();
          remaining.remove_prefix(1);
          if (byte == '"') {
            closed = true;
            break;
          }
          if (byte == '\\') {
            if (remaining.empty() || !IsValidHeaderValue(remaining.substr(0, 1))) {
              return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
            }
            remaining.remove_prefix(1);
          } else if (!IsValidHeaderValue(std::string_view(&byte, 1))) {
            return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
          }
        }
        if (!closed) {
          return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
        }
      } else {
        std::size_t value_len = 0;
        while (value_len < remaining.size() && TokenByte(static_cast<unsigned char>(remaining[value_len]))) {
          ++value_len;
        }
        if (value_len == 0) {
          return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
        }
        remaining.remove_prefix(value_len);
      }
    }
    while (!remaining.empty() && (remaining.front() == ' ' || remaining.front() == '\t')) {
      remaining.remove_prefix(1);
    }
    if (remaining.empty()) {
      return {};
    }
    if (remaining.front() != ';') {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    remaining.remove_prefix(1);
  }
}

[[nodiscard]] inline bool ForbiddenTrailer(std::string_view name) noexcept {
  return AsciiEqualsIgnoreCase(name, "content-length") || AsciiEqualsIgnoreCase(name, "transfer-encoding") ||
         AsciiEqualsIgnoreCase(name, "host") || AsciiEqualsIgnoreCase(name, "connection") ||
         AsciiEqualsIgnoreCase(name, "upgrade");
}

[[nodiscard]] inline Result<std::size_t> ParseChunkSize(std::string_view size_line) noexcept {
  const auto semi = size_line.find(';');
  std::string_view size_text = (semi == std::string_view::npos) ? size_line : size_line.substr(0, semi);
  while (!size_text.empty() && (size_text.back() == ' ' || size_text.back() == '\t')) {
    size_text.remove_suffix(1);
  }
  if (size_text.empty()) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
  }
  std::size_t size = 0;
  for (char c : size_text) {
    unsigned digit = 0;
    if (c >= '0' && c <= '9') {
      digit = static_cast<unsigned>(c - '0');
    } else if (c >= 'a' && c <= 'f') {
      digit = static_cast<unsigned>(c - 'a') + 10U;
    } else if (c >= 'A' && c <= 'F') {
      digit = static_cast<unsigned>(c - 'A') + 10U;
    } else {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    if (size > (std::numeric_limits<std::size_t>::max() - digit) / 16U) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    size = size * 16U + digit;
  }
  if (semi != std::string_view::npos) {
    auto ext = ValidateChunkExtensions(size_line.substr(semi + 1));
    if (!ext.has_value()) {
      return std::unexpected(ext.error());
    }
  }
  return size;
}

struct HeadReady {
  Head head{};
  std::size_t consumed{0};
};

template <std::size_t MaxHeader>
class HeadAccum {
 public:
  void Reset() noexcept { len_ = 0; }

  [[nodiscard]] Result<std::optional<HeadReady>> Push(std::span<const std::uint8_t> in) noexcept {
    std::size_t used = 0;
    while (used < in.size()) {
      if (len_ >= MaxHeader) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1MessageTooLarge));
      }
      buf_[len_++] = in[used++];
      if (len_ >= 4 && buf_[len_ - 4] == static_cast<std::uint8_t>('\r') && buf_[len_ - 3] == static_cast<std::uint8_t>('\n') &&
          buf_[len_ - 2] == static_cast<std::uint8_t>('\r') && buf_[len_ - 1] == static_cast<std::uint8_t>('\n')) {
        auto parsed = ParseHead(std::span<const std::uint8_t>(buf_.data(), len_), MaxHeader);
        if (!parsed.has_value()) {
          return std::unexpected(parsed.error());
        }
        if (!parsed->has_value()) {
          return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
        }
        HeadReady ready;
        ready.head = std::move(**parsed);
        ready.consumed = used;
        return std::optional<HeadReady>(std::move(ready));
      }
    }
    return std::optional<HeadReady>{};
  }

 private:
  std::array<std::uint8_t, MaxHeader> buf_{};
  std::size_t len_{0};
};

struct BodyReady {
  Bytes body{};
  Headers<> trailers{};
  std::size_t consumed{0};
};

template <std::size_t MaxBody, std::size_t MaxMeta>
class BodyFeed {
 public:
  void Reset() noexcept {
    phase_ = Phase::kIdle;
    expect_ = 0;
    body_len_ = 0;
    line_len_ = 0;
    meta_ = 0;
    max_meta_ = 0;
    crlf_ = 0;
    trailers_ = Headers<>{};
  }

  [[nodiscard]] bool Finished() const noexcept { return phase_ == Phase::kDone; }

  [[nodiscard]] Result<void> Begin(Framing framing, std::size_t head_len, std::size_t max_meta) noexcept {
    Reset();
    if (head_len > max_meta) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1MessageTooLarge));
    }
    meta_ = head_len;
    max_meta_ = max_meta;
    if (framing.kind == Framing::Kind::kAbsent) {
      phase_ = Phase::kDone;
      return {};
    }
    if (framing.kind == Framing::Kind::kLength) {
      if (framing.length > MaxBody) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1MessageTooLarge));
      }
      expect_ = framing.length;
      phase_ = expect_ == 0 ? Phase::kDone : Phase::kLength;
      return {};
    }
    phase_ = Phase::kLine;
    return {};
  }

  [[nodiscard]] Result<std::optional<BodyReady>> Push(std::span<const std::uint8_t> in) noexcept {
    std::size_t used = 0;
    while (phase_ != Phase::kDone) {
      if (phase_ == Phase::kLength || phase_ == Phase::kData) {
        const std::size_t avail = in.size() - used;
        const std::size_t take = expect_ < avail ? expect_ : avail;
        if (take > 0) {
          std::memcpy(body_.data() + body_len_, in.data() + used, take);
          body_len_ += take;
          used += take;
          expect_ -= take;
        }
        if (expect_ > 0) {
          return std::optional<BodyReady>{};
        }
        phase_ = phase_ == Phase::kLength ? Phase::kDone : Phase::kCrlf;
        if (phase_ == Phase::kCrlf) {
          crlf_ = 0;
        }
        continue;
      }
      if (phase_ == Phase::kCrlf) {
        while (crlf_ < 2) {
          if (used >= in.size()) {
            return std::optional<BodyReady>{};
          }
          const auto byte = in[used++];
          const auto want = crlf_ == 0 ? static_cast<std::uint8_t>('\r') : static_cast<std::uint8_t>('\n');
          if (byte != want) {
            return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
          }
          ++crlf_;
        }
        phase_ = Phase::kLine;
        continue;
      }
      if (phase_ == Phase::kLine || phase_ == Phase::kTrailer) {
        bool got = false;
        while (used < in.size()) {
          if (meta_ + line_len_ + 1 > max_meta_ || line_len_ >= line_.size()) {
            return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1MessageTooLarge));
          }
          line_[line_len_++] = in[used++];
          if (line_len_ >= 2 && line_[line_len_ - 2] == static_cast<std::uint8_t>('\r') &&
              line_[line_len_ - 1] == static_cast<std::uint8_t>('\n')) {
            got = true;
            break;
          }
        }
        if (!got) {
          return std::optional<BodyReady>{};
        }
        meta_ += line_len_;
        const std::size_t text_len = line_len_ - 2;
        const std::string_view text(reinterpret_cast<const char*>(line_.data()), text_len);
        line_len_ = 0;
        if (phase_ == Phase::kLine) {
          auto size = ParseChunkSize(text);
          if (!size.has_value()) {
            return std::unexpected(size.error());
          }
          if (*size > MaxBody - body_len_) {
            return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1MessageTooLarge));
          }
          if (*size == 0) {
            phase_ = Phase::kTrailer;
          } else {
            expect_ = *size;
            phase_ = Phase::kData;
          }
        } else if (text_len == 0) {
          phase_ = Phase::kDone;
        } else {
          auto field = ParseField(text);
          if (!field.has_value()) {
            return std::unexpected(field.error());
          }
          if (ForbiddenTrailer(field->first)) {
            return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
          }
          auto added = trailers_.Add(field->first, field->second);
          if (!added.has_value()) {
            return std::unexpected(added.error());
          }
        }
        continue;
      }
      return std::unexpected(Error::FromProto(ProtoErrorCode::kHttp1ParseError));
    }
    BodyReady ready;
    ready.body = Bytes::CopyFromSlice(std::span<const std::uint8_t>(body_.data(), body_len_));
    ready.trailers = std::move(trailers_);
    ready.consumed = used;
    Reset();
    return std::optional<BodyReady>(std::move(ready));
  }

 private:
  enum class Phase : std::uint8_t { kIdle, kLength, kLine, kData, kCrlf, kTrailer, kDone };

  Phase phase_{Phase::kIdle};
  std::size_t expect_{0};
  std::size_t body_len_{0};
  std::size_t line_len_{0};
  std::size_t meta_{0};
  std::size_t max_meta_{0};
  std::uint8_t crlf_{0};
  std::array<std::uint8_t, MaxBody> body_{};
  std::array<std::uint8_t, MaxMeta> line_{};
  Headers<> trailers_{};
};

}  // namespace nexora::http1_detail
