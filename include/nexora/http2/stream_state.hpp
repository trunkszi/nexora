/** @file @brief Stream phase packed into one reflected word and fixed-capacity inline pseudo-header text. */
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <nexora/http/message.hpp>
#include <nexora/http2/frame.hpp>
#include <string>
#include <string_view>
#include <uarch/core/bits/bit_word.hpp>
#include <vector>

namespace nexora {

namespace detail {

struct Http2TextTraits : std::char_traits<char> {};

}  // namespace detail

template <std::size_t Cap>
class Http2InlineText : private std::basic_string_view<char, detail::Http2TextTraits> {
  static_assert(Cap > 0 && Cap <= 65535);
  using Base = std::basic_string_view<char, detail::Http2TextTraits>;

 public:
  using Base::begin;
  using Base::contains;
  using Base::data;
  using Base::empty;
  using Base::end;
  using Base::ends_with;
  using Base::find;
  using Base::find_first_of;
  using Base::npos;
  using Base::size;
  using Base::starts_with;

  constexpr Http2InlineText() noexcept : Base() {}

  // Supports conditional expressions such as `asterisk ? "/" : event.path` without heap allocation.
  constexpr Http2InlineText(const char* text) noexcept : Base() {
    if (text != nullptr) {
      const std::string_view sv(text);
      const std::size_t n = std::min<std::size_t>(sv.size(), Cap);
      CopyChars(sv.data(), n);
    }
  }

  constexpr Http2InlineText(const Http2InlineText& other) noexcept : Base(other) {
    CopyChars(other.storage_.data(), other.len_);
  }

  constexpr Http2InlineText& operator=(const Http2InlineText& other) noexcept {
    if (this != &other) {
      CopyChars(other.storage_.data(), other.len_);
    }
    return *this;
  }

  constexpr Http2InlineText(Http2InlineText&& other) noexcept : Base() {
    CopyChars(other.storage_.data(), other.len_);
    other.Clear();
  }

  constexpr Http2InlineText& operator=(Http2InlineText&& other) noexcept {
    if (this != &other) {
      CopyChars(other.storage_.data(), other.len_);
      other.Clear();
    }
    return *this;
  }

  [[nodiscard]] constexpr Result<void> Assign(std::string_view sv) noexcept {
    if (sv.size() > Cap) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kBufferOverflow));
    }
    CopyChars(sv.data(), sv.size());
    return {};
  }

  constexpr void Clear() noexcept {
    len_ = 0;
    Base::operator=(Base{});
  }

  [[nodiscard]] constexpr std::string_view View() const noexcept { return {storage_.data(), len_}; }
  [[nodiscard]] constexpr operator std::string_view() const noexcept { return View(); }
  [[nodiscard]] constexpr const char* Data() const noexcept { return storage_.data(); }
  [[nodiscard]] constexpr std::size_t Size() const noexcept { return len_; }
  [[nodiscard]] constexpr bool Empty() const noexcept { return len_ == 0; }
  [[nodiscard]] static constexpr std::size_t Capacity() noexcept { return Cap; }

  [[nodiscard]] friend constexpr bool operator==(const Http2InlineText& a, const Http2InlineText& b) noexcept {
    return a.View() == b.View();
  }
  [[nodiscard]] friend constexpr bool operator==(const Http2InlineText& a, std::string_view b) noexcept {
    return a.View() == b;
  }
  [[nodiscard]] friend constexpr bool operator==(std::string_view a, const Http2InlineText& b) noexcept {
    return a == b.View();
  }
  [[nodiscard]] friend constexpr bool operator==(const Http2InlineText& a, const char* b) noexcept {
    return a.View() == std::string_view(b != nullptr ? b : "");
  }
  [[nodiscard]] friend constexpr bool operator==(const char* a, const Http2InlineText& b) noexcept {
    return std::string_view(a != nullptr ? a : "") == b.View();
  }

  [[nodiscard]] friend std::string operator+(const Http2InlineText& lhs, std::string_view rhs) {
    std::string out;
    out.reserve(lhs.Size() + rhs.size());
    out.append(lhs.View());
    out.append(rhs);
    return out;
  }

  [[nodiscard]] friend std::string operator+(std::string&& lhs, const Http2InlineText& rhs) {
    lhs.append(rhs.View());
    return std::move(lhs);
  }

 private:
  constexpr void CopyChars(const char* src, std::size_t n) noexcept {
    len_ = static_cast<std::uint16_t>(n);
    if consteval {
      for (std::size_t i = 0; i < n; ++i) {
        storage_[i] = src[i];
      }
    } else {
      if (n > 0) {
        std::memcpy(storage_.data(), src, n);
      }
    }
    Base::operator=(Base{storage_.data(), len_});
  }

  std::array<char, Cap> storage_{};
  std::uint16_t len_{0};
};

using Http2SchemeText = Http2InlineText<32>;
using Http2AuthorityText = Http2InlineText<256>;
using Http2PathText = Http2InlineText<2048>;

enum class StreamPhase : std::uint8_t {
  kFree = 0,
  kLocal = 1,
  kOpen = 2,
  kHalfLocal = 3,
  kHalfRemote = 4,
  kClosed = 5,
};

struct StreamWordSpec {
  using Word = std::uint64_t;
  StreamPhase phase[[= uarch::bits::Field{0, 3}]];
  bool local_end[[= uarch::bits::Flag{3}]];
  bool remote_end[[= uarch::bits::Flag{4}]];
  bool headers_received[[= uarch::bits::Flag{5}]];
  bool trailers_received[[= uarch::bits::Flag{6}]];
  bool has_content_length[[= uarch::bits::Flag{7}]];
  bool rst_sent[[= uarch::bits::Flag{8}]];
  bool rst_received[[= uarch::bits::Flag{9}]];
  bool sent_headers[[= uarch::bits::Flag{10}]];
};

using StreamWord = uarch::bits::BitWord<StreamWordSpec>;

struct Stream {
  std::uint32_t id{0};
  StreamWord word{};
  StatusCode status{200};
  Method method{Method::kPost};
  Http2PathText path{};
  Http2SchemeText scheme{};
  Http2AuthorityText authority{};
  std::int64_t send_window{kHttp2DefaultWindowSize};
  std::int64_t recv_window{kHttp2DefaultWindowSize};
  std::uint64_t content_length{0};
  std::uint64_t data_bytes{0};
  std::vector<std::uint8_t> body{};

  void Reset(std::uint32_t stream_id, std::int64_t initial_send, std::int64_t initial_recv) noexcept {
    id = stream_id;
    word = {};
    status = StatusCode{200};
    method = Method::kPost;
    path.Clear();
    scheme.Clear();
    authority.Clear();
    send_window = initial_send;
    recv_window = initial_recv;
    content_length = 0;
    data_bytes = 0;
    body.clear();
  }

  [[nodiscard]] StreamPhase Phase() const noexcept { return word.get<^^StreamWordSpec::phase>(); }

  void SetPhase(StreamPhase phase) noexcept { word = word.with<^^StreamWordSpec::phase>(phase); }

  [[nodiscard]] bool EndedOut() const noexcept { return word.test<^^StreamWordSpec::local_end>(); }
  [[nodiscard]] bool EndedIn() const noexcept { return word.test<^^StreamWordSpec::remote_end>(); }
  [[nodiscard]] bool SentHeaders() const noexcept { return word.test<^^StreamWordSpec::sent_headers>(); }
  [[nodiscard]] bool GotHeaders() const noexcept { return word.test<^^StreamWordSpec::headers_received>(); }
  [[nodiscard]] bool GotTrailers() const noexcept { return word.test<^^StreamWordSpec::trailers_received>(); }
  [[nodiscard]] bool HasLength() const noexcept { return word.test<^^StreamWordSpec::has_content_length>(); }
  [[nodiscard]] bool RstSent() const noexcept { return word.test<^^StreamWordSpec::rst_sent>(); }
  [[nodiscard]] bool RstReceived() const noexcept { return word.test<^^StreamWordSpec::rst_received>(); }
  [[nodiscard]] bool WasReset() const noexcept { return RstSent() || RstReceived(); }

  void MarkSentHeaders() noexcept { word = word.with<^^StreamWordSpec::sent_headers>(true); }
  void MarkGotHeaders() noexcept { word = word.with<^^StreamWordSpec::headers_received>(true); }
  void MarkGotTrailers() noexcept { word = word.with<^^StreamWordSpec::trailers_received>(true); }
  void MarkLength() noexcept { word = word.with<^^StreamWordSpec::has_content_length>(true); }

  void MarkClosed() noexcept {
    SetPhase(StreamPhase::kClosed);
    word = word.with<^^StreamWordSpec::local_end>(true).with<^^StreamWordSpec::remote_end>(true);
  }

  void MarkRstSent() noexcept {
    MarkClosed();
    word = word.with<^^StreamWordSpec::rst_sent>(true);
  }

  void MarkRstReceived() noexcept {
    MarkClosed();
    word = word.with<^^StreamWordSpec::rst_received>(true);
  }
};

}  // namespace nexora
