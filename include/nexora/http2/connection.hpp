/** @file @brief Sans-IO HTTP/2 connection: streamed data events and optional coalesced bodies. */
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <nexora/http/message.hpp>
#include <nexora/http2/frame.hpp>
#include <nexora/http2/hpack.hpp>
#include <nexora/http2/stream_state.hpp>
#include <optional>
#include <span>
#include <string_view>
#include <uarch/core/bits/bitmap64.hpp>
#include <utility>
#include <vector>

namespace nexora {

enum class Http2Role : std::uint8_t { kClient = 0, kServer = 1 };

/** @brief Bytes accepted from one `FeedBytes` call, pause status, or connection error. */
struct Http2Read {
  std::size_t consumed{0};
  std::size_t attempted{0};
  Error failure{};
  bool ok{true};
  bool paused{false};

  [[nodiscard]] static constexpr Http2Read Ok(std::size_t count, std::size_t total, bool is_paused = false) noexcept {
    return Http2Read{count, total, {}, true, is_paused};
  }
  [[nodiscard]] static constexpr Http2Read Fail(Error err, std::size_t total = 0) noexcept {
    return Http2Read{0, total, err, false, false};
  }
  [[nodiscard]] constexpr bool Ok() const noexcept { return ok; }
  [[nodiscard]] constexpr std::size_t Consumed() const noexcept { return consumed; }
  [[nodiscard]] constexpr bool Paused() const noexcept { return paused; }
  [[nodiscard]] constexpr bool Complete() const noexcept { return ok && !paused && consumed == attempted; }
  [[nodiscard]] explicit constexpr operator bool() const noexcept { return Complete(); }
  [[nodiscard]] constexpr std::size_t operator*() const noexcept { return consumed; }
  [[nodiscard]] constexpr Error ErrorValue() const noexcept {
    if (!ok) {
      return failure;
    }
    if (!Complete()) {
      return Error::FromProto(ProtoErrorCode::kBufferOverflow);
    }
    return failure;
  }
  [[nodiscard]] constexpr operator Result<void>() const noexcept {
    if (Complete()) {
      return {};
    }
    return std::unexpected(ErrorValue());
  }
};

[[nodiscard]] inline bool Http2ValueBoundary(std::string_view value) noexcept {
  if (value.empty()) {
    return false;
  }
  const auto lead = static_cast<unsigned char>(value.front());
  const auto tail = static_cast<unsigned char>(value.back());
  return lead == 0x20U || lead == 0x09U || tail == 0x20U || tail == 0x09U;
}

/** @brief Single-owner byte payload or zero-allocation borrow of the connection data slab. */
class Http2Bytes {
 public:
  Http2Bytes() noexcept = default;
  Http2Bytes(const Http2Bytes&) = delete ("single-owner payload; move or AssignCopy instead");
  Http2Bytes& operator=(const Http2Bytes&) = delete ("single-owner payload; move or AssignCopy instead");
  Http2Bytes(Http2Bytes&& other) noexcept
      : owned_(std::move(other.owned_)), view_(owned_.empty() ? other.view_ : std::span<const std::uint8_t>{owned_}) {
    other.view_ = {};
  }
  Http2Bytes& operator=(Http2Bytes&& other) noexcept {
    if (this != &other) {
      owned_ = std::move(other.owned_);
      view_ = owned_.empty() ? other.view_ : std::span<const std::uint8_t>{owned_};
      other.owned_.clear();
      other.view_ = {};
    }
    return *this;
  }

  void SetView(std::span<const std::uint8_t> view) noexcept {
    owned_.clear();
    view_ = view;
  }

  void AssignOwned(std::vector<std::uint8_t>&& owned) noexcept {
    if (owned.empty()) {
      Clear();
      return;
    }
    owned_ = std::move(owned);
    view_ = owned_;
  }

  void AssignCopy(std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) {
      Clear();
      return;
    }
    AssignOwned(std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
  }

  [[nodiscard]] std::span<const std::uint8_t> Span() const noexcept { return view_; }
  [[nodiscard]] operator std::span<const std::uint8_t>() const noexcept { return view_; }
  [[nodiscard]] std::size_t size() const noexcept { return view_.size(); }
  [[nodiscard]] bool empty() const noexcept { return view_.empty(); }
  [[nodiscard]] const std::uint8_t* data() const noexcept { return view_.data(); }
  [[nodiscard]] const std::uint8_t& operator[](std::size_t index) const noexcept { return view_[index]; }
  [[nodiscard]] const std::uint8_t& Back() const noexcept { return view_.back(); }
  // Pointer iterators would model a contiguous range. GCC then prefers
  // span's range constructor over operator span under -Wconversion.
  void Clear() noexcept {
    owned_.clear();
    view_ = {};
  }

 private:
  std::vector<std::uint8_t> owned_{};
  std::span<const std::uint8_t> view_{};
};

struct Http2Event {
  enum class Kind : std::uint8_t {
    kNone,
    kHeaders,
    kData,
    kTrailers,
    kMessageComplete,
    kStreamReset,
    kWindowUpdate,
    kSettingsAck,
    kPingAck,
    kGoaway,
  };

  Kind kind{Kind::kNone};
  std::uint32_t stream_id{0};
  StatusCode status{200};
  Method method{Method::kPost};
  Http2PathText path{};
  Http2SchemeText scheme{};
  Http2AuthorityText authority{};
  Headers<> headers{};
  Http2Bytes data{};
  std::span<const std::uint8_t> data_view{};
  std::uint32_t flow_control_bytes{0};
  bool end_stream{false};
  Http2ErrorCode error_code{Http2ErrorCode::kNoError};
  std::uint32_t last_stream_id{0};

  Http2Event() noexcept = default;
  Http2Event(const Http2Event&) = delete ("Http2Event owns move-only payload; use std::move");
  Http2Event& operator=(const Http2Event&) = delete ("Http2Event owns move-only payload; use std::move");
  Http2Event(Http2Event&& other) noexcept
      : kind(other.kind),
        stream_id(other.stream_id),
        status(other.status),
        method(other.method),
        path(std::move(other.path)),
        scheme(std::move(other.scheme)),
        authority(std::move(other.authority)),
        headers(std::move(other.headers)),
        data(std::move(other.data)),
        data_view(other.data_view.empty() ? std::span<const std::uint8_t>{} : data.Span()),
        flow_control_bytes(other.flow_control_bytes),
        end_stream(other.end_stream),
        error_code(other.error_code),
        last_stream_id(other.last_stream_id) {
    other.data_view = {};
    other.flow_control_bytes = 0;
  }
  Http2Event& operator=(Http2Event&& other) noexcept {
    if (this != &other) {
      kind = other.kind;
      stream_id = other.stream_id;
      status = other.status;
      method = other.method;
      path = std::move(other.path);
      scheme = std::move(other.scheme);
      authority = std::move(other.authority);
      headers = std::move(other.headers);
      data = std::move(other.data);
      data_view = other.data_view.empty() ? std::span<const std::uint8_t>{} : data.Span();
      flow_control_bytes = other.flow_control_bytes;
      end_stream = other.end_stream;
      error_code = other.error_code;
      last_stream_id = other.last_stream_id;
      other.data_view = {};
      other.flow_control_bytes = 0;
    }
    return *this;
  }

  [[nodiscard]] std::span<const std::uint8_t> Payload() const noexcept { return data_view.empty() ? data.Span() : data_view; }

  [[nodiscard]] std::span<const std::byte> PayloadBytes() const noexcept { return std::as_bytes(Payload()); }

  void Reset() noexcept {
    kind = Kind::kNone;
    stream_id = 0;
    status = StatusCode{200};
    method = Method::kPost;
    path.Clear();
    scheme.Clear();
    authority.Clear();
    headers.Clear();
    data.Clear();
    data_view = {};
    flow_control_bytes = 0;
    end_stream = false;
    error_code = Http2ErrorCode::kNoError;
    last_stream_id = 0;
  }
};

/** @brief Per-connection buffer and body-assembly bounds. Sized once at construction. */
struct Http2Limits {
  std::size_t io_buffer_bytes{65536};
  std::size_t header_block_bytes{65536};
  std::size_t max_coalesced_body_bytes{262144};
  bool coalesce_message_body{true};
};

/** @brief Borrow of the front queued event. Valid until `ConsumeEvent` or `PollEvent`. */
struct Http2EventView {
  Http2Event::Kind kind{Http2Event::Kind::kNone};
  std::uint32_t stream_id{0};
  StatusCode status{200};
  Method method{Method::kPost};
  std::string_view path{};
  std::string_view scheme{};
  std::string_view authority{};
  const Headers<>* headers{nullptr};
  std::span<const std::uint8_t> data{};
  std::uint32_t flow_control_bytes{0};
  bool end_stream{false};
  Http2ErrorCode error_code{Http2ErrorCode::kNoError};
  std::uint32_t last_stream_id{0};
};

/** @brief RFC 9113 connection. Send windows are signed so a SETTINGS shrink can go negative. */
class Http2Connection {
 public:
  static constexpr std::size_t kStreamCap = 64;
  static constexpr std::uint32_t kStreamIdLimit = 0x7fffffffU;
  static constexpr std::uint32_t kMaxRapidResetBurst = 128;

  explicit Http2Connection(Http2Role role, Http2Settings local_settings = {}, Http2Limits limits = {}) noexcept;
  Http2Connection(const Http2Connection&) = delete ("Http2Connection owns pinned frame buffers; allocate on heap");
  Http2Connection& operator=(const Http2Connection&) = delete ("Http2Connection owns pinned frame buffers; allocate on heap");
  Http2Connection(Http2Connection&&) = delete ("Http2Connection owns pinned frame buffers; allocate on heap");
  Http2Connection& operator=(Http2Connection&&) = delete ("Http2Connection owns pinned frame buffers; allocate on heap");

  [[nodiscard]] Result<void> InitiateHandshake() noexcept;
  [[nodiscard]] Result<std::uint32_t> OpenStream() noexcept;
  [[nodiscard]] Result<void> SubmitRequestHeaders(std::uint32_t stream_id, Method method, std::string_view scheme,
                                                  std::string_view authority, std::string_view path, const Headers<>& headers,
                                                  bool end_stream) noexcept;
  [[nodiscard]] Result<void> SubmitResponseHeaders(std::uint32_t stream_id, StatusCode status, const Headers<>& headers,
                                                   bool end_stream) noexcept;
  [[nodiscard]] Result<std::size_t> SubmitData(std::uint32_t stream_id, std::span<const std::uint8_t> data,
                                               bool end_stream) noexcept;
  [[nodiscard]] Result<void> SubmitTrailers(std::uint32_t stream_id, const Headers<>& trailers) noexcept;
  [[nodiscard]] Result<void> SubmitRstStream(std::uint32_t stream_id, Http2ErrorCode error_code) noexcept;
  [[nodiscard]] Result<void> SubmitWindowUpdate(std::uint32_t stream_id, std::uint32_t increment) noexcept;
  [[nodiscard]] Result<void> SubmitPing(std::uint64_t opaque_data, bool ack = false) noexcept;
  [[nodiscard]] Result<void> SubmitGoaway(std::uint32_t last_stream_id, Http2ErrorCode error_code) noexcept;
  [[nodiscard]] Http2Read FeedBytes(std::span<const std::uint8_t> wire_bytes) noexcept;
  [[nodiscard]] bool IsIngressPaused() const noexcept;
  [[nodiscard]] std::optional<Http2Event> PollEvent() noexcept;
  [[nodiscard]] std::optional<Http2EventView> PeekEventView() const noexcept;
  void ConsumeEvent() noexcept;
  [[nodiscard]] std::uint32_t ActiveStreamCount() const noexcept;
  [[nodiscard]] std::uint64_t ResetStreamCount() const noexcept;
  [[nodiscard]] std::uint64_t WindowUpdateCount() const noexcept;
  [[nodiscard]] std::span<const std::uint8_t> PendingOutput() const noexcept;
  void ConsumeOutput(std::size_t bytes) noexcept;
  [[nodiscard]] std::int64_t ConnectionSendWindow() const noexcept;
  [[nodiscard]] std::int64_t ConnectionRecvWindow() const noexcept;
  [[nodiscard]] std::int64_t StreamSendWindow(std::uint32_t stream_id) const noexcept;
  [[nodiscard]] std::size_t DataArenaCapacity() const noexcept;
  [[nodiscard]] std::size_t DataArenaUsed() const noexcept;

 private:
  static constexpr std::size_t kEventCap = 80;
  static constexpr std::size_t kFieldScratchCap = 80;

  struct PinnedBytes {
    std::vector<std::uint8_t> storage{};

    [[nodiscard]] static PinnedBytes Allocate(std::size_t bytes) noexcept {
      PinnedBytes pinned;
      pinned.storage.resize(bytes);
      return pinned;
    }

    [[nodiscard]] std::uint8_t* data() noexcept { return storage.data(); }
    [[nodiscard]] const std::uint8_t* data() const noexcept { return storage.data(); }
    [[nodiscard]] std::size_t size() const noexcept { return storage.size(); }
    [[nodiscard]] std::span<std::uint8_t> Span() noexcept { return {storage.data(), storage.size()}; }
    [[nodiscard]] std::uint8_t& operator[](std::size_t index) noexcept { return storage[index]; }
    [[nodiscard]] const std::uint8_t& operator[](std::size_t index) const noexcept { return storage[index]; }
  };

  template <typename T = void>
  [[nodiscard]] static Result<T> Err(ProtoErrorCode code) noexcept {
    return std::unexpected(Error::FromProto(code));
  }

  [[nodiscard]] static Http2Settings ClampLocal(Http2Role role, Http2Settings settings, Http2Limits limits) noexcept;
  [[nodiscard]] Result<void> Broken() const noexcept;
  [[nodiscard]] static Http2ErrorCode WireOf(ProtoErrorCode code) noexcept;
  [[nodiscard]] Result<void> PeerFail(ProtoErrorCode code) noexcept;
  [[nodiscard]] Result<void> PeerFailHttp2(Http2ErrorCode code) noexcept;
  template <typename T>
  [[nodiscard]] Result<T> PeerFailAs(ProtoErrorCode code) noexcept {
    auto failed = PeerFail(code);
    return std::unexpected(failed.error());
  }
  [[nodiscard]] Stream* Find(std::uint32_t stream_id) noexcept;
  [[nodiscard]] const Stream* Find(std::uint32_t stream_id) const noexcept;
  [[nodiscard]] Stream* Allocate(std::uint32_t stream_id) noexcept;
  [[nodiscard]] bool CanAllocate() const noexcept;
  [[nodiscard]] std::uint32_t CountActive(bool local_ids) const noexcept;
  [[nodiscard]] std::size_t LocalAbove(std::uint32_t last_stream_id) const noexcept;
  void LocalEnd(Stream& slot, bool end_stream) noexcept;
  static void RemoteEnd(Stream& slot) noexcept;
  void CreditReset() noexcept;
  [[nodiscard]] bool OmitsBody(const Stream& slot) const noexcept;
  [[nodiscard]] static bool ConnectionSpecific(std::string_view name, std::string_view value) noexcept;
  [[nodiscard]] static Result<std::size_t> PushField(std::span<HeaderField> fields, std::size_t count, std::string_view name,
                                                     std::string_view value) noexcept;
  [[nodiscard]] static Result<std::size_t> AppendHeaders(std::span<HeaderField> fields, std::size_t count,
                                                         const Headers<>& headers) noexcept;
  [[nodiscard]] static Result<std::uint64_t> ParseContentLength(std::string_view value) noexcept;
  [[nodiscard]] Result<void> WriteBytes(std::span<const std::uint8_t> bytes) noexcept;
  [[nodiscard]] Result<void> WriteFrame(Http2FrameType type, std::uint8_t flags, std::uint32_t stream_id,
                                        std::span<const std::uint8_t> payload) noexcept;
  [[nodiscard]] Result<void> WriteRst(std::uint32_t stream_id, Http2ErrorCode code) noexcept;
  [[nodiscard]] std::size_t OutputFree() const noexcept;
  [[nodiscard]] Result<void> EmitHeaders(std::uint32_t stream_id, std::span<const HeaderField> fields,
                                         bool end_stream) noexcept;
  [[nodiscard]] Result<void> PushEvent(Http2Event&& event) noexcept;
  void DropFront() noexcept;
  [[nodiscard]] static Http2Event Fill(const Stream& slot) noexcept;
  [[nodiscard]] Result<void> PushComplete(Stream& slot) noexcept;
  void DropIn(std::size_t bytes) noexcept;
  [[nodiscard]] std::uint8_t SlotsFor(const Http2FrameHeader& header) const noexcept;
  [[nodiscard]] std::size_t FramesNeeded(const Http2FrameHeader& header, std::span<const std::uint8_t> payload) const noexcept;
  [[nodiscard]] std::size_t ControlBytesNeeded(const Http2FrameHeader& header,
                                               std::span<const std::uint8_t> payload) const noexcept;
  [[nodiscard]] bool WouldOverflowWindow(std::int64_t delta) const noexcept;
  [[nodiscard]] bool PeerStream(std::uint32_t stream_id) const noexcept;
  [[nodiscard]] bool LocalStream(std::uint32_t stream_id) const noexcept;
  [[nodiscard]] static bool SettingListed(std::span<const std::uint8_t> payload, Http2SettingId id) noexcept;
  [[nodiscard]] Result<void> ApplyWindowDelta(std::int64_t delta) noexcept;
  [[nodiscard]] Result<void> OnSettings(std::span<const std::uint8_t> payload, bool ack) noexcept;
  [[nodiscard]] Result<void> OnWindow(std::uint32_t stream_id, std::span<const std::uint8_t> payload) noexcept;
  [[nodiscard]] Result<void> OnData(const Http2FrameHeader& header, std::span<const std::uint8_t> payload) noexcept;
  [[nodiscard]] Result<StatusCode> ParseStatus(std::string_view text) noexcept;
  [[nodiscard]] Result<void> OnHeaders(Stream& slot, std::span<const HeaderField> fields, bool end_stream) noexcept;
  [[nodiscard]] Result<void> FinishHeaders(std::uint32_t stream_id, bool end_stream) noexcept;
  [[nodiscard]] Result<void> BufferHeader(std::uint32_t stream_id, std::span<const std::uint8_t> fragment, bool first,
                                          bool end_stream, bool end_headers) noexcept;
  [[nodiscard]] Result<void> AdmitHeaders(std::uint32_t stream_id, std::span<const std::uint8_t> fragment, bool end_stream,
                                          bool end_headers) noexcept;
  [[nodiscard]] Result<std::span<const std::uint8_t>> StripFrame(const Http2FrameHeader& header,
                                                                 std::span<const std::uint8_t> payload, bool priority) noexcept;
  [[nodiscard]] Result<void> HandleFrame(const Http2FrameHeader& header, std::span<const std::uint8_t> payload) noexcept;
  [[nodiscard]] Result<void> DrainInput() noexcept;
  [[nodiscard]] Result<void> FailLength(Stream& slot, std::size_t added, bool end_stream) noexcept;
  [[nodiscard]] bool KnownClosed(std::uint32_t stream_id) const noexcept;
  [[nodiscard]] Result<void> NoteConnRecv(std::uint32_t framed) noexcept;
  [[nodiscard]] bool DataFits(const Http2FrameHeader& header) const noexcept;
  [[nodiscard]] std::span<const std::uint8_t> StageData(std::span<const std::uint8_t> body) noexcept;
  [[nodiscard]] std::size_t BytesWanted() const noexcept;
  static void BindPayload(Http2Event& event) noexcept;

  Http2Role role_;
  Http2Settings local_{};
  Http2Settings peer_{};
  std::uint32_t next_id_;
  std::uint32_t last_peer_{0};
  std::uint32_t evicted_peer_{0};
  std::uint32_t goaway_last_sent_{0};
  std::uint32_t peer_rsts_{0};
  bool preface_done_;
  bool peer_settings_received_{false};
  bool ingress_paused_{false};
  bool handshake_{false};
  bool broken_{false};
  bool goaway_sent_{false};
  bool goaway_recv_{false};
  bool cont_open_{false};
  bool cont_end_{false};
  bool drop_after_decode_{false};
  bool refuse_rst_{false};
  std::uint8_t empty_cont_{0};
  Error broken_error_{};
  std::uint32_t cont_stream_{0};
  std::int64_t conn_send_{kHttp2DefaultWindowSize};
  std::int64_t conn_recv_{kHttp2DefaultWindowSize};
  HpackEncoder encoder_{};
  HpackDecoder decoder_;
  uarch::bits::Bitmap64 active_{};
  std::array<Stream, kStreamCap> streams_{};
  Http2Limits limits_{};
  PinnedBytes in_{};
  PinnedBytes out_{};
  PinnedBytes tx_block_{};
  PinnedBytes rx_block_{};
  // Borrowed DATA payloads alias this slab until the event queue drains and the next FeedBytes runs.
  PinnedBytes data_arena_{};
  std::size_t data_used_{0};
  std::uint64_t reset_frames_{0};
  std::uint64_t window_updates_{0};
  std::size_t in_len_{0};
  std::size_t out_begin_{0};
  std::size_t out_end_{0};
  std::size_t rx_len_{0};
  // Header blocks and decoded fields use inline capacity, so they live on heap slabs allocated once.
  std::unique_ptr<std::array<Http2Event, kEventCap>> events_{};
  std::unique_ptr<std::array<HeaderField, kFieldScratchCap>> tx_fields_{};
  std::unique_ptr<std::array<HeaderField, kFieldScratchCap>> rx_fields_{};
  std::size_t ev_read_{0};
  std::size_t ev_count_{0};
};

}  // namespace nexora

#include <nexora/http2/connection_headers.hpp>
#include <nexora/http2/connection_rx.hpp>
#include <nexora/http2/connection_submit.hpp>
#include <nexora/http2/connection_tx.hpp>
