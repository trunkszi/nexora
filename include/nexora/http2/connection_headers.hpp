/** @file @brief HTTP/2 header-block admission after HPACK decode. */
#pragma once

#include <algorithm>
#include <cstring>
#include <nexora/http2/connection.hpp>

namespace nexora {

inline Result<StatusCode> Http2Connection::ParseStatus(std::string_view text) noexcept {
  if (text.size() != 3) {
    return PeerFailAs<StatusCode>(ProtoErrorCode::kHttp2ProtocolError);
  }
  std::uint16_t value = 0;
  for (const char ch : text) {
    if (ch < '0' || ch > '9') {
      return PeerFailAs<StatusCode>(ProtoErrorCode::kHttp2ProtocolError);
    }
    value = static_cast<std::uint16_t>(value * 10U + static_cast<unsigned>(ch - '0'));
  }
  auto status = StatusCode::FromU16(value);
  if (!status) {
    return PeerFailAs<StatusCode>(ProtoErrorCode::kHttp2ProtocolError);
  }
  return *status;
}

inline Result<void> Http2Connection::OnHeaders(Stream& slot, std::span<const HeaderField> fields, bool end_stream) noexcept {
  const bool trailers = slot.GotHeaders();
  if (trailers && (!end_stream || slot.GotTrailers() || slot.EndedIn())) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  const bool request = !trailers && role_ == Http2Role::kServer;
  const bool response = !trailers && role_ == Http2Role::kClient;
  auto event = Fill(slot);
  event.kind = trailers ? Http2Event::Kind::kTrailers : Http2Event::Kind::kHeaders;
  event.end_stream = end_stream;
  bool regular = false;
  bool saw_method = false;
  bool saw_scheme = false;
  bool saw_path = false;
  bool saw_status = false;
  bool saw_authority = false;
  bool saw_length = false;
  std::uint64_t length_value = 0;
  for (const auto& field : fields) {
    const std::string_view name = field.name;
    const std::string_view value = field.value;
    if (Http2ValueBoundary(value)) {
      return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
    }
    if (name.starts_with(':')) {
      if (trailers || regular) {
        return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
      }
      if (name == ":status") {
        if (request || saw_status) {
          return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
        }
        auto status = ParseStatus(value);
        if (!status) {
          return std::unexpected(status.error());
        }
        event.status = *status;
        saw_status = true;
      } else if (name == ":method" || name == ":scheme" || name == ":path" || name == ":authority") {
        if (response) {
          return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
        }
        if (name == ":method") {
          if (saw_method) {
            return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
          }
          auto method = ParseMethod(value);
          if (!method) {
            return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
          }
          event.method = *method;
          saw_method = true;
        } else if (name == ":path") {
          if (saw_path) {
            return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
          }
          if (!event.path.Assign(value)) {
            return PeerFail(ProtoErrorCode::kBufferOverflow);
          }
          saw_path = true;
        } else if (name == ":scheme") {
          if (saw_scheme) {
            return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
          }
          if (!event.scheme.Assign(value)) {
            return PeerFail(ProtoErrorCode::kBufferOverflow);
          }
          saw_scheme = true;
        } else if (saw_authority) {
          return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
        } else {
          if (!event.authority.Assign(value)) {
            return PeerFail(ProtoErrorCode::kBufferOverflow);
          }
          saw_authority = true;
        }
      } else {
        return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
      }
    } else {
      regular = true;
      if (!IsValidHttp2HeaderName(name, false) || ConnectionSpecific(name, value)) {
        return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
      }
      if (!trailers && name == "content-length") {
        if (saw_length) {
          return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
        }
        auto parsed = ParseContentLength(value);
        if (!parsed) {
          return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
        }
        length_value = *parsed;
        saw_length = true;
      }
      if (auto added = event.headers.Add(name, value); !added) {
        return PeerFail(ProtoErrorCode::kBufferOverflow);
      }
    }
  }
  if (request && (!saw_method || !saw_scheme || !saw_path)) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  if (request && saw_path && event.path.empty() && (event.scheme == "http" || event.scheme == "https")) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  if (response && !saw_status) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  if (saw_status && event.status.AsU16() == StatusCode::kSwitchingProtocols) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  const bool informational = saw_status && event.status.IsInformational();
  if (informational && end_stream) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  if (!trailers) {
    if (saw_status) {
      slot.status = event.status;
    }
    if (!informational) {
      if (saw_method) {
        slot.method = event.method;
      }
      if (saw_path) {
        slot.path = event.path;
      }
      if (saw_scheme) {
        slot.scheme = event.scheme;
      }
      if (saw_authority) {
        slot.authority = event.authority;
      }
      if (saw_length) {
        slot.content_length = length_value;
        slot.MarkLength();
      }
      slot.MarkGotHeaders();
    }
    const auto code = slot.status.AsU16();
    if (role_ == Http2Role::kClient && (code == 204 || code == 304) && slot.data_bytes != 0) {
      return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
    }
    if (saw_length && end_stream && !OmitsBody(slot) && length_value != slot.data_bytes) {
      return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
    }
  } else {
    if (slot.HasLength() && !OmitsBody(slot) && slot.data_bytes != slot.content_length) {
      return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
    }
    slot.MarkGotTrailers();
  }
  Headers<> carried = std::move(event.headers);
  event = Fill(slot);
  event.headers = std::move(carried);
  event.end_stream = end_stream;
  event.kind = trailers ? Http2Event::Kind::kTrailers : Http2Event::Kind::kHeaders;
  if (auto pushed = PushEvent(std::move(event)); !pushed) {
    return pushed;
  }
  if (!end_stream) {
    return {};
  }
  if (auto done = PushComplete(slot); !done) {
    return done;
  }
  RemoteEnd(slot);
  return {};
}

inline Result<void> Http2Connection::FinishHeaders(std::uint32_t stream_id, bool end_stream) noexcept {
  auto count = decoder_.Decode(std::span<const std::uint8_t>(rx_block_.data(), rx_len_), *rx_fields_);
  rx_len_ = 0;
  const bool drop = drop_after_decode_;
  const bool refuse = refuse_rst_;
  drop_after_decode_ = false;
  refuse_rst_ = false;
  if (!count) {
    return PeerFail(ProtoErrorCode::kHttp2CompressionError);
  }
  const auto fields = std::span<const HeaderField>(rx_fields_->data(), *count);
  std::uint64_t listed = 0;
  for (const auto& field : fields) {
    listed += field.name.size() + field.value.size() + 32U;
    if (listed > local_.max_header_list_size) {
      return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
    }
  }
  if (drop) {
    return {};
  }
  if (refuse) {
    if (auto wrote = WriteRst(stream_id, Http2ErrorCode::kRefusedStream); !wrote) {
      return wrote;
    }
    if (auto* slot = Allocate(stream_id)) {
      slot->MarkRstSent();
    } else if (PeerStream(stream_id)) {
      evicted_peer_ = std::max(evicted_peer_, stream_id);
    }
    return {};
  }
  auto* slot = Find(stream_id);
  if (slot == nullptr) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  return OnHeaders(*slot, fields, end_stream);
}

inline Result<void> Http2Connection::BufferHeader(std::uint32_t stream_id, std::span<const std::uint8_t> fragment, bool first,
                                                  bool end_stream, bool end_headers) noexcept {
  if (first) {
    cont_stream_ = stream_id;
    cont_end_ = end_stream;
    empty_cont_ = 0;
  } else if (!cont_open_ || stream_id != cont_stream_) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  } else if (fragment.empty()) {
    if (++empty_cont_ >= 2) {
      return PeerFailHttp2(Http2ErrorCode::kEnhanceYourCalm);
    }
  } else {
    empty_cont_ = 0;
  }
  if (rx_len_ + fragment.size() > rx_block_.size()) {
    return PeerFail(ProtoErrorCode::kBufferOverflow);
  }
  if (!fragment.empty()) {
    std::memcpy(rx_block_.data() + rx_len_, fragment.data(), fragment.size());
    rx_len_ += fragment.size();
  }
  cont_open_ = !end_headers;
  if (!end_headers) {
    return {};
  }
  cont_open_ = false;
  return FinishHeaders(stream_id, cont_end_);
}

inline Result<void> Http2Connection::AdmitHeaders(std::uint32_t stream_id, std::span<const std::uint8_t> fragment,
                                                  bool end_stream, bool end_headers) noexcept {
  if (stream_id == 0) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  if (auto* slot = Find(stream_id); slot != nullptr) {
    if (slot->RstSent()) {
      drop_after_decode_ = true;
      return BufferHeader(stream_id, fragment, true, end_stream, end_headers);
    }
    if (slot->EndedIn() || slot->Phase() == StreamPhase::kClosed) {
      return PeerFail(ProtoErrorCode::kHttp2StreamClosed);
    }
    return BufferHeader(stream_id, fragment, true, end_stream, end_headers);
  }
  if (KnownClosed(stream_id) || (PeerStream(stream_id) && stream_id <= evicted_peer_)) {
    drop_after_decode_ = true;
    return BufferHeader(stream_id, fragment, true, end_stream, end_headers);
  }
  if (role_ != Http2Role::kServer || !PeerStream(stream_id) || stream_id <= last_peer_) {
    return PeerFail(ProtoErrorCode::kHttp2ProtocolError);
  }
  last_peer_ = stream_id;
  const bool above_goaway = goaway_sent_ && stream_id > goaway_last_sent_;
  const bool crowded = CountActive(false) >= local_.max_concurrent_streams || !CanAllocate();
  Stream* slot = (above_goaway || crowded) ? nullptr : Allocate(stream_id);
  if (slot != nullptr) {
    slot->SetPhase(StreamPhase::kOpen);
  } else {
    refuse_rst_ = true;
  }
  return BufferHeader(stream_id, fragment, true, end_stream, end_headers);
}

}  // namespace nexora
