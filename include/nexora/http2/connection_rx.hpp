/** @file @brief HTTP/2 receive path. */
#pragma once

#include <cstring>
#include <nexora/http2/connection.hpp>

namespace nexora {

inline std::uint8_t Http2Connection::SlotsFor(const Http2FrameHeader& header) const noexcept {
  const bool end_stream = header.Has(Http2FrameFlags::kEndStream);
  const bool end_headers = header.Has(Http2FrameFlags::kEndHeaders);
  switch (header.type) {
    case Http2FrameType::kData:
      return end_stream ? std::uint8_t{2} : std::uint8_t{1};
    case Http2FrameType::kHeaders:
      return end_headers ? (end_stream ? std::uint8_t{2} : std::uint8_t{1}) : std::uint8_t{0};
    case Http2FrameType::kContinuation:
      if (!end_headers) {
        return 0;
      }
      return cont_end_ ? std::uint8_t{2} : std::uint8_t{1};
    case Http2FrameType::kRstStream:
    case Http2FrameType::kGoaway:
    case Http2FrameType::kWindowUpdate:
      return 1;
    case Http2FrameType::kSettings:
    case Http2FrameType::kPing:
      return end_stream ? std::uint8_t{1} : std::uint8_t{0};
    default:
      return 0;
  }
}

inline std::size_t Http2Connection::FramesNeeded(const Http2FrameHeader& header,
                                                 std::span<const std::uint8_t> payload) const noexcept {
  if (header.type == Http2FrameType::kGoaway && payload.size() >= 8) {
    return 1U + LocalAbove(ReadU32(payload) & kStreamIdLimit);
  }
  return SlotsFor(header);
}

inline std::size_t Http2Connection::ControlBytesNeeded(const Http2FrameHeader& header,
                                                       std::span<const std::uint8_t> payload) const noexcept {
  if (cont_open_) {
    if (header.type == Http2FrameType::kContinuation && header.stream_id == cont_stream_ &&
        header.Has(Http2FrameFlags::kEndHeaders) && refuse_rst_) {
      return kHttp2FrameHeaderSize + 4uz;
    }
    return 0uz;
  }
  if (header.type == Http2FrameType::kSettings) {
    if (header.stream_id != 0 || header.Has(Http2FrameFlags::kAck)) {
      return 0uz;
    }
    auto updated = ApplySettingsPayload(peer_, payload);
    if (!updated) {
      return 0uz;
    }
    if (role_ == Http2Role::kClient && SettingListed(payload, Http2SettingId::kEnablePush) && updated->enable_push != 0) {
      return 0uz;
    }
    const auto delta =
        static_cast<std::int64_t>(updated->initial_window_size) - static_cast<std::int64_t>(peer_.initial_window_size);
    return WouldOverflowWindow(delta) ? 0uz : kHttp2FrameHeaderSize;
  }
  if (!peer_settings_received_) {
    return 0uz;
  }
  if (header.type == Http2FrameType::kPing) {
    if (header.stream_id == 0 && payload.size() == 8 && !header.Has(Http2FrameFlags::kAck)) {
      return kHttp2FrameHeaderSize + 8uz;
    }
    return 0uz;
  }
  if (header.type == Http2FrameType::kHeaders && header.Has(Http2FrameFlags::kEndHeaders) && header.stream_id != 0 &&
      Find(header.stream_id) == nullptr && !KnownClosed(header.stream_id) && role_ == Http2Role::kServer &&
      PeerStream(header.stream_id) && header.stream_id > last_peer_) {
    const bool above_goaway = goaway_sent_ && header.stream_id > goaway_last_sent_;
    const bool crowded = CountActive(false) >= local_.max_concurrent_streams || !CanAllocate();
    if (above_goaway || crowded) {
      return kHttp2FrameHeaderSize + 4uz;
    }
  }
  return 0uz;
}

inline bool Http2Connection::PeerStream(std::uint32_t stream_id) const noexcept {
  const bool odd = (stream_id & 1U) != 0;
  return role_ == Http2Role::kServer ? odd : !odd;
}

inline bool Http2Connection::LocalStream(std::uint32_t stream_id) const noexcept {
  const bool odd = (stream_id & 1U) != 0;
  return role_ == Http2Role::kClient ? odd : !odd;
}

inline bool Http2Connection::SettingListed(std::span<const std::uint8_t> payload, Http2SettingId id) noexcept {
  for (std::size_t i = 0; i + 5 < payload.size(); i += 6) {
    const auto got = LoadBe16(payload.data() + i);
    if (got == std::to_underlying(id)) {
      return true;
    }
  }
  return false;
}

inline Result<std::span<const std::uint8_t>> Http2Connection::StripFrame(const Http2FrameHeader& header,
                                                                         std::span<const std::uint8_t> payload,
                                                                         bool priority) noexcept {
  if (header.Has(Http2FrameFlags::kPadded)) {
    if (payload.empty() || std::size_t{payload[0]} >= payload.size()) {
      return PeerFailAs<std::span<const std::uint8_t>>(ProtoErrorCode::kHttp2ProtocolError);
    }
    payload = payload.subspan(1, payload.size() - 1U - payload[0]);
  }
  if (priority && header.Has(Http2FrameFlags::kPriorityFlag)) {
    if (payload.size() < 5) {
      return PeerFailAs<std::span<const std::uint8_t>>(ProtoErrorCode::kHttp2ProtocolError);
    }
    payload = payload.subspan(5);
  }
  return payload;
}

inline bool Http2Connection::KnownClosed(std::uint32_t stream_id) const noexcept {
  if (stream_id == 0 || !LocalStream(stream_id)) {
    return false;
  }
  return next_id_ == 0 || stream_id < next_id_;
}

inline Result<void> Http2Connection::NoteConnRecv(std::uint32_t framed) noexcept {
  const auto bytes = static_cast<std::int64_t>(framed);
  if (bytes > conn_recv_) {
    return PeerFail(ProtoErrorCode::kHttp2FlowControlError);
  }
  conn_recv_ -= bytes;
  return {};
}

inline bool Http2Connection::DataFits(const Http2FrameHeader& header) const noexcept {
  if (limits_.coalesce_message_body || header.type != Http2FrameType::kData) {
    return true;
  }
  return data_used_ + static_cast<std::size_t>(header.length) <= data_arena_.size();
}

inline std::span<const std::uint8_t> Http2Connection::StageData(std::span<const std::uint8_t> body) noexcept {
  auto* dest = data_arena_.data() + data_used_;
  if (!body.empty()) {
    std::memcpy(dest, body.data(), body.size());
  }
  data_used_ += body.size();
  return {dest, body.size()};
}

inline void Http2Connection::BindPayload(Http2Event& event) noexcept { event.data_view = event.data.Span(); }

inline bool Http2Connection::WouldOverflowWindow(std::int64_t delta) const noexcept {
  if (delta <= 0) {
    return false;
  }
  auto bits = active_;
  while (const auto index = bits.pop_lowest_one()) {
    const auto phase = streams_[*index].Phase();
    if (phase == StreamPhase::kClosed || phase == StreamPhase::kFree) {
      continue;
    }
    if (streams_[*index].send_window > kHttp2MaxWindow - delta) {
      return true;
    }
  }
  return false;
}

inline Result<void> Http2Connection::ApplyWindowDelta(std::int64_t delta) noexcept {
  if (WouldOverflowWindow(delta)) {
    return PeerFail(ProtoErrorCode::kHttp2FlowControlError);
  }
  auto bits = active_;
  while (const auto index = bits.pop_lowest_one()) {
    const auto phase = streams_[*index].Phase();
    if (phase == StreamPhase::kClosed || phase == StreamPhase::kFree) {
      continue;
    }
    streams_[*index].send_window += delta;
  }
  return {};
}

inline Result<void> Http2Connection::OnSettings(std::span<const std::uint8_t> payload, bool ack) noexcept {
  if (ack) {
    if (!payload.empty()) {
      return PeerFail(ProtoErrorCode::kHttp2FrameSizeError);
    }
    auto event = Http2Event{};
    event.kind = Http2Event::Kind::kSettingsAck;
    return PushEvent(std::move(event));
  }
  auto updated = ApplySettingsPayload(peer_, payload);
  if (!updated) {
    return PeerFail(static_cast<ProtoErrorCode>(updated.error().code));
  }
  if (role_ == Http2Role::kClient && SettingListed(payload, Http2SettingId::kEnablePush) && updated->enable_push != 0) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  const auto delta =
      static_cast<std::int64_t>(updated->initial_window_size) - static_cast<std::int64_t>(peer_.initial_window_size);
  if (auto applied = ApplyWindowDelta(delta); !applied) {
    return applied;
  }
  encoder_.SetMaxTableSize(updated->header_table_size);
  peer_ = *updated;
  peer_settings_received_ = true;
  return WriteFrame(Http2FrameType::kSettings, std::to_underlying(Http2FrameFlags::kAck), 0, {});
}

inline Result<void> Http2Connection::OnWindow(std::uint32_t stream_id, std::span<const std::uint8_t> payload) noexcept {
  if (payload.size() != 4) {
    return PeerFail(ProtoErrorCode::kHttp2FrameSizeError);
  }
  const auto increment = ReadU32(payload) & kStreamIdLimit;
  if (increment == 0) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  const auto inc = static_cast<std::int64_t>(increment);
  if (stream_id == 0) {
    if (conn_send_ > kHttp2MaxWindow - inc) {
      return PeerFail(ProtoErrorCode::kHttp2FlowControlError);
    }
    conn_send_ += inc;
  } else if (auto* slot = Find(stream_id); slot == nullptr) {
    if ((PeerStream(stream_id) && stream_id <= last_peer_) || KnownClosed(stream_id)) {
      return {};
    }
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  } else if (slot->Phase() == StreamPhase::kClosed) {
    return {};
  } else if (slot->Phase() == StreamPhase::kLocal || slot->Phase() == StreamPhase::kFree) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  } else if (slot->send_window > kHttp2MaxWindow - inc) {
    return PeerFail(ProtoErrorCode::kHttp2FlowControlError);
  } else {
    slot->send_window += inc;
  }
  ++window_updates_;
  auto event = Http2Event{};
  event.kind = Http2Event::Kind::kWindowUpdate;
  event.stream_id = stream_id;
  return PushEvent(std::move(event));
}

inline Result<void> Http2Connection::FailLength(Stream& slot, std::size_t added, bool end_stream) noexcept {
  if (role_ == Http2Role::kClient) {
    const auto code = slot.status.AsU16();
    const bool empty_body = code == 204 || code == 304 || slot.method == Method::kHead;
    if (empty_body && added != 0) {
      return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
    }
  }
  if (!slot.HasLength() || OmitsBody(slot)) {
    return {};
  }
  if (slot.data_bytes + added > slot.content_length) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  if (end_stream && slot.data_bytes + added != slot.content_length) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  return {};
}

inline Result<void> Http2Connection::OnData(const Http2FrameHeader& header, std::span<const std::uint8_t> payload) noexcept {
  if (header.stream_id == 0) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  auto* found = Find(header.stream_id);
  if (found == nullptr) {
    if ((PeerStream(header.stream_id) && header.stream_id <= last_peer_) || KnownClosed(header.stream_id)) {
      return NoteConnRecv(header.length);
    }
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  if (found->RstSent()) {
    return NoteConnRecv(header.length);
  }
  if (found->Phase() == StreamPhase::kClosed || found->EndedIn()) {
    return PeerFail(ProtoErrorCode::kHttp2StreamClosed);
  }
  if (!found->GotHeaders()) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  auto body = StripFrame(header, payload, false);
  if (!body) {
    return std::unexpected(body.error());
  }
  const bool end_stream = header.Has(Http2FrameFlags::kEndStream);
  if (auto length = FailLength(*found, body->size(), end_stream); !length) {
    return length;
  }
  const auto framed = static_cast<std::int64_t>(header.length);
  if (framed > conn_recv_ || framed > found->recv_window) {
    return PeerFail(ProtoErrorCode::kHttp2FlowControlError);
  }
  conn_recv_ -= framed;
  found->recv_window -= framed;
  if (limits_.coalesce_message_body && found->body.size() + body->size() > limits_.max_coalesced_body_bytes) {
    return PeerFail(ProtoErrorCode::kBufferOverflow);
  }
  found->data_bytes += body->size();
  if (limits_.coalesce_message_body) {
    found->body.insert(found->body.end(), body->begin(), body->end());
  }
  Http2Event event;
  event.stream_id = found->id;
  event.kind = Http2Event::Kind::kData;
  event.flow_control_bytes = header.length;
  event.end_stream = end_stream;
  if (limits_.coalesce_message_body) {
    event.data.AssignCopy(*body);
  } else {
    event.data.SetView(StageData(*body));
  }
  BindPayload(event);
  if (auto pushed = PushEvent(std::move(event)); !pushed) {
    return pushed;
  }
  if (!end_stream) {
    return {};
  }
  if (auto done = PushComplete(*found); !done) {
    return done;
  }
  RemoteEnd(*found);
  return {};
}

inline Result<void> Http2Connection::HandleFrame(const Http2FrameHeader& header,
                                                 std::span<const std::uint8_t> payload) noexcept {
  if (header.type != Http2FrameType::kContinuation) {
    empty_cont_ = 0;
  }
  if (cont_open_ && header.type != Http2FrameType::kContinuation) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  if (!peer_settings_received_ && (header.type != Http2FrameType::kSettings || header.Has(Http2FrameFlags::kAck))) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  switch (header.type) {
    case Http2FrameType::kData:
      return OnData(header, payload);
    case Http2FrameType::kHeaders: {
      auto fragment = StripFrame(header, payload, true);
      if (!fragment) {
        return std::unexpected(fragment.error());
      }
      return AdmitHeaders(header.stream_id, *fragment, header.Has(Http2FrameFlags::kEndStream),
                          header.Has(Http2FrameFlags::kEndHeaders));
    }
    case Http2FrameType::kContinuation:
      return BufferHeader(header.stream_id, payload, false, cont_end_, header.Has(Http2FrameFlags::kEndHeaders));
    case Http2FrameType::kRstStream: {
      if (payload.size() != 4 || header.stream_id == 0) {
        return PeerFail(ProtoErrorCode::kHttp2FrameSizeError);
      }
      ++reset_frames_;
      auto* slot = Find(header.stream_id);
      const auto phase = slot == nullptr ? StreamPhase::kFree : slot->Phase();
      if (slot == nullptr || phase == StreamPhase::kLocal) {
        if (slot == nullptr &&
            ((PeerStream(header.stream_id) && header.stream_id <= last_peer_) || KnownClosed(header.stream_id))) {
          return {};
        }
        return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
      }
      if (++peer_rsts_ > kMaxRapidResetBurst) {
        return PeerFailHttp2(Http2ErrorCode::kEnhanceYourCalm);
      }
      auto event = Http2Event{};
      event.kind = Http2Event::Kind::kStreamReset;
      event.stream_id = header.stream_id;
      event.error_code = Http2ErrorCodeFromU32(ReadU32(payload));
      slot->MarkRstReceived();
      return PushEvent(std::move(event));
    }
    case Http2FrameType::kSettings:
      if (header.stream_id != 0) {
        return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
      }
      return OnSettings(payload, header.Has(Http2FrameFlags::kAck));
    case Http2FrameType::kPing: {
      if (header.stream_id != 0 || payload.size() != 8) {
        return PeerFail(ProtoErrorCode::kHttp2FrameSizeError);
      }
      if (!header.Has(Http2FrameFlags::kAck)) {
        return WriteFrame(Http2FrameType::kPing, std::to_underlying(Http2FrameFlags::kAck), 0, payload);
      }
      auto event = Http2Event{};
      event.kind = Http2Event::Kind::kPingAck;
      return PushEvent(std::move(event));
    }
    case Http2FrameType::kGoaway: {
      if (header.stream_id != 0 || payload.size() < 8) {
        return PeerFail(ProtoErrorCode::kHttp2FrameSizeError);
      }
      const auto last = ReadU32(payload) & kStreamIdLimit;
      auto event = Http2Event{};
      event.kind = Http2Event::Kind::kGoaway;
      event.last_stream_id = last;
      event.error_code = Http2ErrorCodeFromU32(ReadU32(payload.subspan(4)));
      goaway_recv_ = true;
      if (auto pushed = PushEvent(std::move(event)); !pushed) {
        return pushed;
      }
      auto bits = active_;
      while (const auto index = bits.pop_lowest_one()) {
        auto& slot = streams_[*index];
        const auto phase = slot.Phase();
        if (phase == StreamPhase::kFree || phase == StreamPhase::kClosed) {
          continue;
        }
        if (!LocalStream(slot.id) || slot.id <= last) {
          continue;
        }
        auto reset = Fill(slot);
        reset.kind = Http2Event::Kind::kStreamReset;
        reset.error_code = Http2ErrorCode::kRefusedStream;
        slot.MarkRstReceived();
        if (auto pushed = PushEvent(std::move(reset)); !pushed) {
          return pushed;
        }
      }
      return {};
    }
    case Http2FrameType::kWindowUpdate:
      return OnWindow(header.stream_id, payload);
    case Http2FrameType::kPriority:
      if (payload.size() != 5 || header.stream_id == 0) {
        return PeerFail(ProtoErrorCode::kHttp2FrameSizeError);
      }
      return {};
    case Http2FrameType::kPushPromise:
      return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
    default:
      return {};
  }
}

inline Result<void> Http2Connection::DrainInput() noexcept {
  ingress_paused_ = false;
  if (!preface_done_) {
    if (in_len_ < kHttp2ClientPreface.size()) {
      return {};
    }
    for (std::size_t i = 0; i < kHttp2ClientPreface.size(); ++i) {
      if (in_[i] != kHttp2ClientPreface[i]) {
        return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
      }
    }
    DropIn(kHttp2ClientPreface.size());
    preface_done_ = true;
  }
  if (ev_count_ == 0) {
    data_used_ = 0;
  }
  while (in_len_ >= kHttp2FrameHeaderSize) {
    auto header = DecodeFrameHeader(std::span<const std::uint8_t>(in_.data(), kHttp2FrameHeaderSize));
    if (!header) {
      return std::unexpected(header.error());
    }
    if (header->length > local_.max_frame_size) {
      return PeerFail(ProtoErrorCode::kHttp2FrameSizeError);
    }
    const auto total = kHttp2FrameHeaderSize + static_cast<std::size_t>(header->length);
    if (in_len_ < total) {
      return {};
    }
    const auto payload = std::span<const std::uint8_t>(in_.data() + kHttp2FrameHeaderSize, header->length);
    if (ev_count_ + FramesNeeded(*header, payload) > kEventCap || !DataFits(*header) ||
        OutputFree() < ControlBytesNeeded(*header, payload)) {
      ingress_paused_ = true;
      return {};
    }
    auto handled = HandleFrame(*header, payload);
    DropIn(total);
    if (!handled) {
      return handled;
    }
  }
  return {};
}

}  // namespace nexora
