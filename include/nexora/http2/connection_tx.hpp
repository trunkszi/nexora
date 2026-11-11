/** @file @brief HTTP/2 send path. */
#pragma once

#include <algorithm>
#include <cstring>
#include <nexora/http2/connection.hpp>
#include <utility>

namespace nexora {

[[nodiscard]] inline Http2Limits NormalizeLimits(Http2Limits limits) noexcept {
  constexpr std::size_t min_io_bytes = std::size_t{kHttp2DefaultMaxFrameSize} + kHttp2FrameHeaderSize;
  if (limits.io_buffer_bytes < min_io_bytes) {
    limits.io_buffer_bytes = min_io_bytes;
  }
  if (limits.header_block_bytes < 4096) {
    limits.header_block_bytes = 4096;
  }
  return limits;
}

// Both roles refuse PUSH_PROMISE, so neither advertises server push.
inline Http2Settings Http2Connection::ClampLocal([[maybe_unused]] Http2Role role, Http2Settings settings,
                                                 Http2Limits limits) noexcept {
  const auto normalized = NormalizeLimits(limits);
  settings.enable_push = 0;
  if (settings.max_concurrent_streams > kStreamCap) {
    settings.max_concurrent_streams = static_cast<std::uint32_t>(kStreamCap);
  }
  if (settings.header_table_size > HpackTable::kMaxBytes) {
    settings.header_table_size = static_cast<std::uint32_t>(HpackTable::kMaxBytes);
  }
  const auto max_rx_payload = std::min<std::size_t>(0x00ffffffuz, normalized.io_buffer_bytes - kHttp2FrameHeaderSize);
  auto frame_max = std::min<std::size_t>(settings.max_frame_size, max_rx_payload);
  if (frame_max < kHttp2DefaultMaxFrameSize) {
    frame_max = kHttp2DefaultMaxFrameSize;
  }
  settings.max_frame_size = static_cast<std::uint32_t>(frame_max);
  return settings;
}

inline Http2Connection::Http2Connection(Http2Role role, Http2Settings local_settings, Http2Limits limits) noexcept
    : role_(role),
      local_(ClampLocal(role, local_settings, limits)),
      next_id_(role == Http2Role::kClient ? 1U : 2U),
      preface_done_(role == Http2Role::kClient),
      decoder_(local_.header_table_size),
      limits_(NormalizeLimits(limits)),
      in_(PinnedBytes::Allocate(limits_.io_buffer_bytes)),
      out_(PinnedBytes::Allocate(limits_.io_buffer_bytes)),
      tx_block_(PinnedBytes::Allocate(limits_.header_block_bytes)),
      rx_block_(PinnedBytes::Allocate(limits_.header_block_bytes)),
      data_arena_(PinnedBytes::Allocate(
          std::max<std::size_t>(std::size_t{65536}, static_cast<std::size_t>(local_.max_frame_size) * 4U))),
      events_(std::make_unique<std::array<Http2Event, kEventCap>>()),
      tx_fields_(std::make_unique<std::array<HeaderField, kFieldScratchCap>>()),
      rx_fields_(std::make_unique<std::array<HeaderField, kFieldScratchCap>>()) {}

inline Result<void> Http2Connection::Broken() const noexcept { return std::unexpected(broken_error_); }

inline Http2ErrorCode Http2Connection::WireOf(ProtoErrorCode code) noexcept {
  switch (code) {
    case ProtoErrorCode::kHttp2FlowControlError:
      return Http2ErrorCode::kFlowControlError;
    case ProtoErrorCode::kHttp2FrameSizeError:
      return Http2ErrorCode::kFrameSizeError;
    case ProtoErrorCode::kHttp2CompressionError:
      return Http2ErrorCode::kCompressionError;
    case ProtoErrorCode::kHttp2StreamClosed:
      return Http2ErrorCode::kStreamClosed;
    case ProtoErrorCode::kHttp2RefusedStream:
      return Http2ErrorCode::kRefusedStream;
    case ProtoErrorCode::kHttp2Cancel:
      return Http2ErrorCode::kCancel;
    default:
      return Http2ErrorCode::kProtocolError;
  }
}

inline Result<void> Http2Connection::PeerFailHttp2(Http2ErrorCode code) noexcept {
  if (broken_) {
    return Broken();
  }
  if (!goaway_sent_) {
    std::array<std::uint8_t, 8> payload{};
    WriteU32(std::span<std::uint8_t>(payload.data(), 4), last_peer_ & kStreamIdLimit);
    WriteU32(std::span<std::uint8_t>(payload.data() + 4, 4), std::to_underlying(code));
    if (WriteFrame(Http2FrameType::kGoaway, 0, 0, payload)) {
      goaway_sent_ = true;
      goaway_last_sent_ = last_peer_ & kStreamIdLimit;
    }
  }
  broken_ = true;
  broken_error_ = Error::FromHttp2(code);
  return Broken();
}

inline Result<void> Http2Connection::PeerFail(ProtoErrorCode code) noexcept {
  if (broken_) {
    return Broken();
  }
  if (!goaway_sent_) {
    std::array<std::uint8_t, 8> payload{};
    WriteU32(std::span<std::uint8_t>(payload.data(), 4), last_peer_ & kStreamIdLimit);
    WriteU32(std::span<std::uint8_t>(payload.data() + 4, 4), std::to_underlying(WireOf(code)));
    if (WriteFrame(Http2FrameType::kGoaway, 0, 0, payload)) {
      goaway_sent_ = true;
      goaway_last_sent_ = last_peer_ & kStreamIdLimit;
    }
  }
  broken_ = true;
  broken_error_ = Error::FromProto(code);
  return Broken();
}

inline Stream* Http2Connection::Find(std::uint32_t stream_id) noexcept {
  auto bits = active_;
  while (const auto index = bits.pop_lowest_one()) {
    if (streams_[*index].id == stream_id) {
      return &streams_[*index];
    }
  }
  return nullptr;
}

inline const Stream* Http2Connection::Find(std::uint32_t stream_id) const noexcept {
  auto bits = active_;
  while (const auto index = bits.pop_lowest_one()) {
    if (streams_[*index].id == stream_id) {
      return &streams_[*index];
    }
  }
  return nullptr;
}

inline bool Http2Connection::CanAllocate() const noexcept {
  if (active_.lowest_zero().has_value()) {
    return true;
  }
  auto bits = active_;
  while (const auto index = bits.pop_lowest_one()) {
    if (streams_[*index].Phase() == StreamPhase::kClosed) {
      return true;
    }
  }
  return false;
}

inline Stream* Http2Connection::Allocate(std::uint32_t stream_id) noexcept {
  std::optional<std::uint32_t> slot = active_.lowest_zero();
  if (!slot) {
    auto bits = active_;
    while (const auto index = bits.pop_lowest_one()) {
      if (streams_[*index].Phase() == StreamPhase::kClosed) {
        slot = index;
        break;
      }
    }
  }
  if (!slot) {
    return nullptr;
  }
  auto& stored = streams_[*slot];
  if (stored.Phase() == StreamPhase::kClosed && PeerStream(stored.id)) {
    evicted_peer_ = std::max(evicted_peer_, stored.id);
  }
  stored.Reset(stream_id, static_cast<std::int64_t>(peer_.initial_window_size),
               static_cast<std::int64_t>(local_.initial_window_size));
  active_ = active_.set(*slot);
  return &stored;
}

inline std::uint32_t Http2Connection::CountActive(bool local_ids) const noexcept {
  std::uint32_t total = 0;
  auto bits = active_;
  while (const auto index = bits.pop_lowest_one()) {
    const auto& slot = streams_[*index];
    const auto phase = slot.Phase();
    if (phase == StreamPhase::kFree || phase == StreamPhase::kClosed) {
      continue;
    }
    if (LocalStream(slot.id) == local_ids) {
      ++total;
    }
  }
  return total;
}

inline std::size_t Http2Connection::LocalAbove(std::uint32_t last_stream_id) const noexcept {
  std::size_t total = 0;
  auto bits = active_;
  while (const auto index = bits.pop_lowest_one()) {
    const auto& slot = streams_[*index];
    const auto phase = slot.Phase();
    if (phase == StreamPhase::kFree || phase == StreamPhase::kClosed) {
      continue;
    }
    if (LocalStream(slot.id) && slot.id > last_stream_id) {
      ++total;
    }
  }
  return total;
}

inline void Http2Connection::CreditReset() noexcept { peer_rsts_ = peer_rsts_ >= 2U ? peer_rsts_ - 2U : 0U; }

inline bool Http2Connection::OmitsBody(const Stream& slot) const noexcept {
  // Inbound bytes on a server are the request, so a stored response status never exempts them.
  if (role_ != Http2Role::kClient) {
    return false;
  }
  if (slot.method == Method::kHead) {
    return true;
  }
  const auto code = slot.status.AsU16();
  return slot.status.IsInformational() || code == 204 || code == 304;
}

inline void Http2Connection::LocalEnd(Stream& slot, bool end_stream) noexcept {
  const auto phase = slot.Phase();
  if (!end_stream) {
    if (phase == StreamPhase::kLocal) {
      slot.SetPhase(StreamPhase::kOpen);
    }
    return;
  }
  // Peer END_STREAM must not pay debt down: a reset attack sends it immediately before RST.
  if (!slot.EndedOut() && slot.EndedIn() && !slot.WasReset()) {
    CreditReset();
  }
  slot.word = slot.word.with<^^StreamWordSpec::local_end>(true);
  if (phase == StreamPhase::kLocal || phase == StreamPhase::kOpen) {
    slot.SetPhase(StreamPhase::kHalfLocal);
  } else if (phase == StreamPhase::kHalfRemote) {
    slot.SetPhase(StreamPhase::kClosed);
  }
}

inline void Http2Connection::RemoteEnd(Stream& slot) noexcept {
  const auto phase = slot.Phase();
  slot.word = slot.word.with<^^StreamWordSpec::remote_end>(true);
  if (phase == StreamPhase::kOpen || phase == StreamPhase::kLocal) {
    slot.SetPhase(StreamPhase::kHalfRemote);
  } else if (phase == StreamPhase::kHalfLocal) {
    slot.SetPhase(StreamPhase::kClosed);
  }
}

inline bool Http2Connection::ConnectionSpecific(std::string_view name, std::string_view value) noexcept {
  return name == "connection" || name == "keep-alive" || name == "proxy-connection" || name == "transfer-encoding" ||
         name == "upgrade" || (name == "te" && value != "trailers");
}

inline Result<std::size_t> Http2Connection::PushField(std::span<HeaderField> fields, std::size_t count, std::string_view name,
                                                      std::string_view value) noexcept {
  if (name.empty() || !IsValidHeaderValue(value) || Http2ValueBoundary(value)) {
    return Err<std::size_t>(ProtoErrorCode::kHttp2ProtocolError);
  }
  if (count >= fields.size()) {
    return Err<std::size_t>(ProtoErrorCode::kBufferOverflow);
  }
  if (!fields[count].name.TryAssign(name) || !fields[count].value.TryAssign(value)) {
    return Err<std::size_t>(ProtoErrorCode::kBufferOverflow);
  }
  return count + 1U;
}

inline Result<std::size_t> Http2Connection::AppendHeaders(std::span<HeaderField> fields, std::size_t count,
                                                          const Headers<>& headers) noexcept {
  for (const auto& field : headers.Fields()) {
    if (!IsValidHttp2HeaderName(field.name, false) || ConnectionSpecific(field.name, field.value)) {
      return Err<std::size_t>(ProtoErrorCode::kHttp2ProtocolError);
    }
    auto added = PushField(fields, count, field.name, field.value);
    if (!added) {
      return added;
    }
    count = *added;
  }
  return count;
}

inline Result<std::uint64_t> Http2Connection::ParseContentLength(std::string_view value) noexcept {
  if (value.empty()) {
    return Err<std::uint64_t>(ProtoErrorCode::kHttp2ProtocolError);
  }
  std::uint64_t parsed = 0;
  for (const char ch : value) {
    if (ch < '0' || ch > '9') {
      return Err<std::uint64_t>(ProtoErrorCode::kHttp2ProtocolError);
    }
    const auto digit = static_cast<std::uint64_t>(ch - '0');
    if (parsed > (std::uint64_t{0xffffffffffffffffULL} - digit) / 10U) {
      return Err<std::uint64_t>(ProtoErrorCode::kHttp2ProtocolError);
    }
    parsed = parsed * 10U + digit;
  }
  return parsed;
}

inline Result<void> Http2Connection::WriteBytes(std::span<const std::uint8_t> bytes) noexcept {
  if (bytes.empty()) {
    return {};
  }
  if (out_begin_ > 0 && out_end_ + bytes.size() > out_.size()) {
    std::memmove(out_.data(), out_.data() + out_begin_, out_end_ - out_begin_);
    out_end_ -= out_begin_;
    out_begin_ = 0;
  }
  if (bytes.size() > out_.size() - out_end_) {
    return Err(ProtoErrorCode::kBufferOverflow);
  }
  std::memcpy(out_.data() + out_end_, bytes.data(), bytes.size());
  out_end_ += bytes.size();
  return {};
}

inline Result<void> Http2Connection::WriteFrame(Http2FrameType type, std::uint8_t flags, std::uint32_t stream_id,
                                                std::span<const std::uint8_t> payload) noexcept {
  if (payload.size() > 0x00ffffffU) {
    return Err(ProtoErrorCode::kHttp2FrameSizeError);
  }
  if (kHttp2FrameHeaderSize + payload.size() > OutputFree()) {
    return Err(ProtoErrorCode::kBufferOverflow);
  }
  std::array<std::uint8_t, kHttp2FrameHeaderSize> header{};
  Http2FrameHeader fields{static_cast<std::uint32_t>(payload.size()), type, flags, stream_id};
  EncodeFrameHeader(fields, header);
  if (auto wrote = WriteBytes(header); !wrote) {
    return wrote;
  }
  return WriteBytes(payload);
}

inline Result<void> Http2Connection::WriteRst(std::uint32_t stream_id, Http2ErrorCode code) noexcept {
  std::array<std::uint8_t, 4> payload{};
  WriteU32(payload, std::to_underlying(code));
  if (auto wrote = WriteFrame(Http2FrameType::kRstStream, 0, stream_id, payload); !wrote) {
    return wrote;
  }
  ++reset_frames_;
  return {};
}

inline std::size_t Http2Connection::OutputFree() const noexcept { return out_.size() - (out_end_ - out_begin_); }

inline Result<void> Http2Connection::EmitHeaders(std::uint32_t stream_id, std::span<const HeaderField> fields,
                                                 bool end_stream) noexcept {
  const auto limit = static_cast<std::size_t>(peer_.max_frame_size);
  if (limit == 0) {
    return Err(ProtoErrorCode::kHttp2ProtocolError);
  }
  auto trial = encoder_;
  auto encoded = trial.Encode(fields, tx_block_.Span());
  if (!encoded) {
    return std::unexpected(encoded.error());
  }
  const auto total = *encoded;
  std::size_t wire = 0;
  for (std::size_t offset = 0;;) {
    const auto remain = total - offset;
    const auto chunk = remain > limit ? limit : remain;
    wire += kHttp2FrameHeaderSize + chunk;
    offset += chunk;
    if (offset >= total) {
      break;
    }
  }
  if (OutputFree() < wire) {
    return Err(ProtoErrorCode::kBufferOverflow);
  }
  encoder_ = trial;
  std::size_t offset = 0;
  while (true) {
    const auto remain = total - offset;
    const auto chunk = remain > limit ? limit : remain;
    const bool last = offset + chunk == total;
    std::uint8_t flags = 0;
    if (last) {
      flags = static_cast<std::uint8_t>(flags | std::to_underlying(Http2FrameFlags::kEndHeaders));
    }
    if (offset == 0 && end_stream) {
      flags = static_cast<std::uint8_t>(flags | std::to_underlying(Http2FrameFlags::kEndStream));
    }
    const auto type = offset == 0 ? Http2FrameType::kHeaders : Http2FrameType::kContinuation;
    if (auto wrote = WriteFrame(type, flags, stream_id, std::span<const std::uint8_t>(tx_block_.data() + offset, chunk));
        !wrote) {
      return wrote;
    }
    offset += chunk;
    if (last) {
      return {};
    }
  }
}

inline Result<void> Http2Connection::PushEvent(Http2Event&& event) noexcept {
  if (!events_ || ev_count_ >= kEventCap) {
    return Err(ProtoErrorCode::kBufferOverflow);
  }
  (*events_)[(ev_read_ + ev_count_) % kEventCap] = std::move(event);
  ++ev_count_;
  return {};
}

inline Http2Event Http2Connection::Fill(const Stream& slot) noexcept {
  Http2Event event;
  event.stream_id = slot.id;
  event.status = slot.status;
  event.method = slot.method;
  event.path = slot.path;
  event.scheme = slot.scheme;
  event.authority = slot.authority;
  return event;
}

inline Result<void> Http2Connection::PushComplete(Stream& slot) noexcept {
  // The client ends the request before the response, so this completion is its half of the cycle.
  if (role_ == Http2Role::kClient && slot.EndedOut() && !slot.WasReset()) {
    CreditReset();
  }
  auto event = Fill(slot);
  event.kind = Http2Event::Kind::kMessageComplete;
  event.end_stream = true;
  if (!slot.body.empty()) {
    event.data.AssignOwned(std::move(slot.body));
    slot.body.clear();
  }
  BindPayload(event);
  return PushEvent(std::move(event));
}

inline void Http2Connection::DropIn(std::size_t bytes) noexcept {
  if (bytes >= in_len_) {
    in_len_ = 0;
    return;
  }
  std::memmove(in_.data(), in_.data() + bytes, in_len_ - bytes);
  in_len_ -= bytes;
}

}  // namespace nexora
