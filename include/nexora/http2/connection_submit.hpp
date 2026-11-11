/** @file @brief HTTP/2 submit and byte-queue API. */
#pragma once

#include <algorithm>
#include <cstring>
#include <nexora/http2/connection.hpp>

namespace nexora {

inline Result<void> Http2Connection::InitiateHandshake() noexcept {
  if (broken_) {
    return Broken();
  }
  if (handshake_) {
    return {};
  }
  handshake_ = true;
  if (role_ == Http2Role::kClient) {
    if (auto wrote = WriteBytes(kHttp2ClientPreface); !wrote) {
      return wrote;
    }
  }
  std::array<std::uint8_t, 36> payload{};
  auto size = EncodeSettingsPayload(local_, payload);
  if (!size) {
    return std::unexpected(size.error());
  }
  return WriteFrame(Http2FrameType::kSettings, 0, 0, std::span<const std::uint8_t>(payload.data(), *size));
}

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
inline Result<std::uint32_t> Http2Connection::OpenStream() noexcept {
  if (broken_) {
    return std::unexpected(broken_error_);
  }
  if (goaway_recv_) {
    return Err<std::uint32_t>(ProtoErrorCode::kHttp2RefusedStream);
  }
  if (next_id_ == 0 || next_id_ > kStreamIdLimit) {
    return Err<std::uint32_t>(ProtoErrorCode::kHttp2StreamClosed);
  }
  if (CountActive(true) >= peer_.max_concurrent_streams) {
    return Err<std::uint32_t>(ProtoErrorCode::kHttp2RefusedStream);
  }
  auto* slot = Allocate(next_id_);
  if (slot == nullptr) {
    return Err<std::uint32_t>(ProtoErrorCode::kHttp2RefusedStream);
  }
  slot->SetPhase(StreamPhase::kLocal);
  const auto id = next_id_;
  const auto advanced = next_id_ + 2U;
  next_id_ = advanced < id || advanced > kStreamIdLimit ? 0U : advanced;
  return id;
}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

inline Result<void> Http2Connection::SubmitRequestHeaders(std::uint32_t stream_id, Method method, std::string_view scheme,
                                                          std::string_view authority, std::string_view path,
                                                          const Headers<>& headers, bool end_stream) noexcept {
  if (role_ != Http2Role::kClient) {
    return Err(ProtoErrorCode::kInvalidArgument);
  }
  auto* slot = Find(stream_id);
  if (slot == nullptr || slot->Phase() != StreamPhase::kLocal) {
    return Err(ProtoErrorCode::kHttp2StreamClosed);
  }
  if (scheme.size() > Http2SchemeText::Capacity() || authority.size() > Http2AuthorityText::Capacity() ||
      path.size() > Http2PathText::Capacity()) {
    return Err(ProtoErrorCode::kBufferOverflow);
  }
  auto& fields = *tx_fields_;
  std::size_t count = 0;
  auto method_field = PushField(fields, count, ":method", MethodAsStr(method));
  if (!method_field) {
    return std::unexpected(method_field.error());
  }
  count = *method_field;
  auto scheme_field = PushField(fields, count, ":scheme", scheme);
  if (!scheme_field) {
    return std::unexpected(scheme_field.error());
  }
  count = *scheme_field;
  auto path_field = PushField(fields, count, ":path", path);
  if (!path_field) {
    return std::unexpected(path_field.error());
  }
  count = *path_field;
  auto authority_field = PushField(fields, count, ":authority", authority);
  if (!authority_field) {
    return std::unexpected(authority_field.error());
  }
  count = *authority_field;
  auto extra = AppendHeaders(fields, count, headers);
  if (!extra) {
    return std::unexpected(extra.error());
  }
  if (auto wrote = EmitHeaders(stream_id, std::span<const HeaderField>(fields.data(), *extra), end_stream); !wrote) {
    return wrote;
  }
  if (!slot->scheme.Assign(scheme) || !slot->authority.Assign(authority) || !slot->path.Assign(path)) {
    return Err(ProtoErrorCode::kBufferOverflow);
  }
  slot->MarkSentHeaders();
  slot->method = method;
  LocalEnd(*slot, end_stream);
  return {};
}

inline Result<void> Http2Connection::SubmitResponseHeaders(std::uint32_t stream_id, StatusCode status, const Headers<>& headers,
                                                           bool end_stream) noexcept {
  if (role_ != Http2Role::kServer) {
    return Err(ProtoErrorCode::kInvalidArgument);
  }
  if (status.AsU16() == StatusCode::kSwitchingProtocols) {
    return Err(ProtoErrorCode::kHttp2ProtocolError);
  }
  auto* slot = Find(stream_id);
  if (slot == nullptr || slot->EndedOut() || (slot->SentHeaders() && !slot->status.IsInformational())) {
    return Err(ProtoErrorCode::kHttp2StreamClosed);
  }
  const auto phase = slot->Phase();
  if (phase != StreamPhase::kOpen && phase != StreamPhase::kHalfRemote) {
    return Err(ProtoErrorCode::kHttp2StreamClosed);
  }
  std::array<char, 3> digits{};
  const auto code = status.AsU16();
  digits[0] = static_cast<char>(static_cast<unsigned>('0') + (code / 100U) % 10U);
  digits[1] = static_cast<char>(static_cast<unsigned>('0') + (code / 10U) % 10U);
  digits[2] = static_cast<char>(static_cast<unsigned>('0') + code % 10U);
  auto& fields = *tx_fields_;
  auto count = PushField(fields, 0, ":status", std::string_view(digits.data(), digits.size()));
  if (!count) {
    return std::unexpected(count.error());
  }
  auto extra = AppendHeaders(fields, *count, headers);
  if (!extra) {
    return std::unexpected(extra.error());
  }
  if (auto wrote = EmitHeaders(stream_id, std::span<const HeaderField>(fields.data(), *extra), end_stream); !wrote) {
    return wrote;
  }
  slot->MarkSentHeaders();
  slot->status = status;
  LocalEnd(*slot, end_stream);
  return {};
}

inline Result<std::size_t> Http2Connection::SubmitData(std::uint32_t stream_id, std::span<const std::uint8_t> data,
                                                       bool end_stream) noexcept {
  if (broken_) {
    return std::unexpected(broken_error_);
  }
  auto* slot = Find(stream_id);
  if (slot == nullptr || !slot->SentHeaders() || slot->EndedOut()) {
    return Err<std::size_t>(ProtoErrorCode::kHttp2StreamClosed);
  }
  const auto phase = slot->Phase();
  if (phase != StreamPhase::kOpen && phase != StreamPhase::kHalfRemote) {
    return Err<std::size_t>(ProtoErrorCode::kHttp2StreamClosed);
  }
  const auto out_free = OutputFree();
  if (data.empty()) {
    if (!end_stream) {
      return 0U;
    }
    if (out_free < kHttp2FrameHeaderSize) {
      return Err<std::size_t>(ProtoErrorCode::kBufferOverflow);
    }
    if (auto wrote = WriteFrame(Http2FrameType::kData, std::to_underlying(Http2FrameFlags::kEndStream), stream_id, {});
        !wrote) {
      return std::unexpected(wrote.error());
    }
    LocalEnd(*slot, true);
    return 0U;
  }
  if (out_free <= kHttp2FrameHeaderSize) {
    return 0U;
  }
  auto credit = conn_send_ < slot->send_window ? conn_send_ : slot->send_window;
  const auto frame_cap = static_cast<std::int64_t>(peer_.max_frame_size);
  if (frame_cap < credit) {
    credit = frame_cap;
  }
  if (credit <= 0) {
    return 0U;
  }
  const auto out_cap = out_free - kHttp2FrameHeaderSize;
  auto size = data.size();
  if (size > out_cap) {
    size = out_cap;
  }
  if (static_cast<std::int64_t>(size) > credit) {
    size = static_cast<std::size_t>(credit);
  }
  const bool finish = end_stream && size == data.size();
  const auto flags = finish ? std::to_underlying(Http2FrameFlags::kEndStream) : std::uint8_t{0};
  if (auto wrote = WriteFrame(Http2FrameType::kData, flags, stream_id, data.first(size)); !wrote) {
    return std::unexpected(wrote.error());
  }
  conn_send_ -= static_cast<std::int64_t>(size);
  slot->send_window -= static_cast<std::int64_t>(size);
  LocalEnd(*slot, finish);
  return size;
}

inline Result<void> Http2Connection::SubmitTrailers(std::uint32_t stream_id, const Headers<>& trailers) noexcept {
  auto* slot = Find(stream_id);
  if (slot == nullptr || !slot->SentHeaders() || slot->EndedOut()) {
    return Err(ProtoErrorCode::kHttp2StreamClosed);
  }
  auto& fields = *tx_fields_;
  auto count = AppendHeaders(fields, 0, trailers);
  if (!count) {
    return std::unexpected(count.error());
  }
  if (auto wrote = EmitHeaders(stream_id, std::span<const HeaderField>(fields.data(), *count), true); !wrote) {
    return wrote;
  }
  LocalEnd(*slot, true);
  return {};
}

inline Result<void> Http2Connection::SubmitRstStream(std::uint32_t stream_id, Http2ErrorCode error_code) noexcept {
  auto* slot = Find(stream_id);
  const auto phase = slot == nullptr ? StreamPhase::kFree : slot->Phase();
  if (slot == nullptr || phase == StreamPhase::kClosed || phase == StreamPhase::kFree) {
    return Err(ProtoErrorCode::kHttp2StreamClosed);
  }
  if (auto wrote = WriteRst(stream_id, error_code); !wrote) {
    return wrote;
  }
  slot->MarkRstSent();
  return {};
}

inline Result<void> Http2Connection::SubmitWindowUpdate(std::uint32_t stream_id, std::uint32_t increment) noexcept {
  if (increment == 0) {
    return Err(ProtoErrorCode::kHttp2ProtocolError);
  }
  auto* window = &conn_recv_;
  if (stream_id != 0) {
    auto* slot = Find(stream_id);
    const auto phase = slot == nullptr ? StreamPhase::kFree : slot->Phase();
    if (slot == nullptr || phase == StreamPhase::kFree || phase == StreamPhase::kLocal || phase == StreamPhase::kClosed) {
      return Err(ProtoErrorCode::kHttp2StreamClosed);
    }
    window = &slot->recv_window;
  }
  const auto inc = static_cast<std::int64_t>(increment);
  if (*window > kHttp2MaxWindow - inc) {
    return Err(ProtoErrorCode::kHttp2FlowControlError);
  }
  std::array<std::uint8_t, 4> payload{};
  WriteU32(payload, increment);
  if (auto wrote = WriteFrame(Http2FrameType::kWindowUpdate, 0, stream_id, payload); !wrote) {
    return wrote;
  }
  *window += inc;
  ++window_updates_;
  return {};
}

inline Result<void> Http2Connection::SubmitPing(std::uint64_t opaque_data, bool ack) noexcept {
  std::array<std::uint8_t, 8> payload{};
  for (int shift = 7; shift >= 0; --shift) {
    payload[static_cast<std::size_t>(7 - shift)] = static_cast<std::uint8_t>((opaque_data >> (shift * 8)) & 0xffU);
  }
  const auto flags = ack ? std::to_underlying(Http2FrameFlags::kAck) : std::uint8_t{0};
  return WriteFrame(Http2FrameType::kPing, flags, 0, payload);
}

inline Result<void> Http2Connection::SubmitGoaway(std::uint32_t last_stream_id, Http2ErrorCode error_code) noexcept {
  if (goaway_sent_) {
    return Err(ProtoErrorCode::kHttp2ProtocolError);
  }
  std::array<std::uint8_t, 8> payload{};
  const auto last = last_stream_id & kStreamIdLimit;
  WriteU32(std::span<std::uint8_t>(payload.data(), 4), last);
  WriteU32(std::span<std::uint8_t>(payload.data() + 4, 4), std::to_underlying(error_code));
  if (auto wrote = WriteFrame(Http2FrameType::kGoaway, 0, 0, payload); !wrote) {
    return wrote;
  }
  goaway_sent_ = true;
  goaway_last_sent_ = last;
  return {};
}

inline std::size_t Http2Connection::BytesWanted() const noexcept {
  if (!preface_done_) {
    return in_len_ >= kHttp2ClientPreface.size() ? 0 : kHttp2ClientPreface.size() - in_len_;
  }
  if (in_len_ < kHttp2FrameHeaderSize) {
    return kHttp2FrameHeaderSize - in_len_;
  }
  auto header = DecodeFrameHeader(std::span<const std::uint8_t>(in_.data(), kHttp2FrameHeaderSize));
  if (!header) {
    return 0;
  }
  const auto total = kHttp2FrameHeaderSize + static_cast<std::size_t>(header->length);
  return in_len_ >= total ? 0 : total - in_len_;
}

inline bool Http2Connection::IsIngressPaused() const noexcept { return ingress_paused_; }

inline Http2Read Http2Connection::FeedBytes(std::span<const std::uint8_t> wire_bytes) noexcept {
  if (broken_) {
    return Http2Read::Fail(broken_error_, wire_bytes.size());
  }
  std::size_t taken = 0;
  while (true) {
    const auto before = in_len_;
    auto drained = DrainInput();
    if (!drained) {
      return Http2Read::Fail(drained.error(), wire_bytes.size());
    }
    if (ingress_paused_) {
      return Http2Read::Ok(taken, wire_bytes.size(), true);
    }
    if (taken >= wire_bytes.size()) {
      return Http2Read::Ok(taken, wire_bytes.size(), false);
    }
    const auto need = BytesWanted();
    const auto room = in_.size() - in_len_;
    const auto chunk = std::min(need, std::min(room, wire_bytes.size() - taken));
    if (chunk == 0) {
      if (need > 0 && room == 0 && in_len_ == before) {
        return Http2Read::Fail(Error::FromProto(ProtoErrorCode::kBufferOverflow), wire_bytes.size());
      }
      return Http2Read::Ok(taken, wire_bytes.size(), false);
    }
    std::memcpy(in_.data() + in_len_, wire_bytes.data() + taken, chunk);
    in_len_ += chunk;
    taken += chunk;
  }
}

inline void Http2Connection::DropFront() noexcept {
  if (!events_ || ev_count_ == 0) {
    return;
  }
  (*events_)[ev_read_].Reset();
  ev_read_ = (ev_read_ + 1U) % kEventCap;
  --ev_count_;
}

inline std::optional<Http2Event> Http2Connection::PollEvent() noexcept {
  if (!events_ || ev_count_ == 0) {
    return std::nullopt;
  }
  std::optional<Http2Event> event(std::move((*events_)[ev_read_]));
  DropFront();
  return event;
}

inline std::optional<Http2EventView> Http2Connection::PeekEventView() const noexcept {
  if (!events_ || ev_count_ == 0) {
    return std::nullopt;
  }
  const Http2Event& event = (*events_)[ev_read_];
  return Http2EventView{event.kind,       event.stream_id,  event.status,        event.method,    event.path,
                        event.scheme,     event.authority,  &event.headers,      event.Payload(), event.flow_control_bytes,
                        event.end_stream, event.error_code, event.last_stream_id};
}

inline void Http2Connection::ConsumeEvent() noexcept { DropFront(); }

inline std::uint32_t Http2Connection::ActiveStreamCount() const noexcept { return active_.count(); }

inline std::uint64_t Http2Connection::ResetStreamCount() const noexcept { return reset_frames_; }

inline std::uint64_t Http2Connection::WindowUpdateCount() const noexcept { return window_updates_; }

inline std::span<const std::uint8_t> Http2Connection::PendingOutput() const noexcept {
  return {out_.data() + out_begin_, out_end_ - out_begin_};
}

inline void Http2Connection::ConsumeOutput(std::size_t bytes) noexcept {
  const auto pending = out_end_ - out_begin_;
  if (bytes > pending) {
    bytes = pending;
  }
  out_begin_ += bytes;
  if (out_begin_ == out_end_) {
    out_begin_ = 0;
    out_end_ = 0;
  }
}

inline std::int64_t Http2Connection::ConnectionSendWindow() const noexcept { return conn_send_; }

inline std::int64_t Http2Connection::ConnectionRecvWindow() const noexcept { return conn_recv_; }

inline std::size_t Http2Connection::DataArenaCapacity() const noexcept { return data_arena_.size(); }

inline std::size_t Http2Connection::DataArenaUsed() const noexcept { return data_used_; }

inline std::int64_t Http2Connection::StreamSendWindow(std::uint32_t stream_id) const noexcept {
  const auto* slot = Find(stream_id);
  return slot == nullptr ? 0 : slot->send_window;
}

}  // namespace nexora
