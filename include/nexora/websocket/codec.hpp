#pragma once

#include <openssl/rand.h>

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <nexora/bytes/bytes.hpp>
#include <nexora/error/proto_error.hpp>
#include <nexora/websocket/frame.hpp>
#include <nexora/websocket/utf8.hpp>
#include <optional>
#include <span>
#include <utility>

namespace nexora {

template <std::size_t MaxMessage = 8192>
class WebSocketCodec {
 public:
  explicit WebSocketCodec(WebSocketRole role = WebSocketRole::kClient) noexcept : role_(role) {}

  [[nodiscard]] static WebSocketCodec Client() noexcept { return WebSocketCodec(WebSocketRole::kClient); }
  [[nodiscard]] static WebSocketCodec Server() noexcept { return WebSocketCodec(WebSocketRole::kServer); }

  [[nodiscard]] WebSocketRole Role() const noexcept { return role_; }
  [[nodiscard]] bool Failed() const noexcept { return failed_; }
  [[nodiscard]] std::span<const std::uint8_t> PendingControl() const noexcept { return {pending_.data(), pending_len_}; }
  void ClearPendingControl() noexcept { pending_len_ = 0; }

  [[nodiscard]] Result<BytesMut<MaxMessage + 14>> EncodeMessage(const WebSocketMessage& message) noexcept {
    WebSocketFrame frame;
    frame.fin = true;
    if (message.kind == WebSocketMessageKind::kText) {
      frame.opcode = WebSocketOpcode::kText;
      frame.payload = message.payload;
    } else if (message.kind == WebSocketMessageKind::kBinary) {
      frame.opcode = WebSocketOpcode::kBinary;
      frame.payload = message.payload;
    } else if (message.kind == WebSocketMessageKind::kPing) {
      frame.opcode = WebSocketOpcode::kPing;
      frame.payload = message.payload;
    } else if (message.kind == WebSocketMessageKind::kPong) {
      frame.opcode = WebSocketOpcode::kPong;
      frame.payload = message.payload;
    } else {
      frame.opcode = WebSocketOpcode::kClose;
      std::array<std::uint8_t, 125> close_buf{};
      if (message.close_code.has_value()) {
        auto code = ws_detail::ValidateCloseCode(*message.close_code);
        if (!code.has_value()) {
          return std::unexpected(code.error());
        }
        if (message.payload.Size() > 123) {
          return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
        }
        const auto be = ws_detail::WireBigEndian(*message.close_code);
        std::memcpy(close_buf.data(), &be, sizeof(be));
        if (!message.payload.Empty()) {
          std::memcpy(close_buf.data() + 2, message.payload.Data(), message.payload.Size());
        }
        frame.payload = Bytes::CopyFromSlice(std::span<const std::uint8_t>(close_buf.data(), 2 + message.payload.Size()));
      }
    }
    return EncodeFrame(frame);
  }

  [[nodiscard]] Result<BytesMut<MaxMessage + 14>> EncodeFrame(const WebSocketFrame& frame) noexcept {
    auto ready = ValidateSend(frame.opcode);
    if (!ready.has_value()) {
      return std::unexpected(ready.error());
    }
    if (frame.payload.Size() > MaxMessage) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketPayloadTooLarge));
    }
    if (WebSocketIsControl(frame.opcode) && (!frame.fin || frame.payload.Size() > 125)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    if (frame.opcode == WebSocketOpcode::kClose) {
      auto close = ws_detail::ParseClose(frame.payload.Span());
      if (!close.has_value()) {
        return std::unexpected(close.error());
      }
    }
    Frag next;
    if (!WebSocketIsControl(frame.opcode)) {
      auto advanced =
          AdvanceFragment(out_active_, out_opcode_, out_size_, out_utf8_, frame.fin, frame.opcode, frame.payload.Span());
      if (!advanced.has_value()) {
        return std::unexpected(advanced.error());
      }
      next = *advanced;
    }
    const bool masked = role_ == WebSocketRole::kClient;
    std::array<std::uint8_t, 4> mask{};
    if (masked && RAND_bytes(mask.data(), 4) != 1) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    BytesMut<MaxMessage + 14> out;
    auto wired = WriteFrame(out.WritableSpan(), frame.fin, frame.opcode, frame.payload.Span(), masked, mask);
    if (!wired.has_value()) {
      return std::unexpected(wired.error());
    }
    auto committed = out.CommitWrite(*wired);
    if (!committed.has_value()) {
      return std::unexpected(committed.error());
    }
    if (frame.opcode == WebSocketOpcode::kClose) {
      close_sent_ = true;
      out_active_ = false;
    } else if (!WebSocketIsControl(frame.opcode)) {
      if (frame.fin) {
        out_active_ = false;
        out_size_ = 0;
        out_utf8_ = {};
      } else {
        out_active_ = true;
        out_opcode_ = next.opcode;
        out_size_ = next.size;
        out_utf8_ = next.utf8;
      }
    }
    return out;
  }

  [[nodiscard]] Result<WebSocketDecoded> DecodeMessage(std::span<const std::uint8_t> in) noexcept {
    if (failed_) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    std::size_t used = 0;
    while (true) {
      auto step = Ingest(in.subspan(used));
      if (!step.has_value()) {
        Fail();
        return std::unexpected(step.error());
      }
      used += step->taken;
      if (!step->done) {
        WebSocketDecoded decoded;
        decoded.consumed = used;
        return decoded;
      }
      auto message = HandleFrame();
      ArmHeader();
      if (!message.has_value()) {
        Fail();
        return std::unexpected(message.error());
      }
      if (message->has_value()) {
        WebSocketDecoded decoded;
        decoded.consumed = used;
        decoded.message = std::move(**message);
        return decoded;
      }
      if (used >= in.size()) {
        WebSocketDecoded decoded;
        decoded.consumed = used;
        return decoded;
      }
    }
  }

  void Reset() noexcept {
    close_sent_ = false;
    close_received_ = false;
    failed_ = false;
    in_active_ = false;
    out_active_ = false;
    in_opcode_ = WebSocketOpcode::kContinuation;
    out_opcode_ = WebSocketOpcode::kContinuation;
    in_size_ = 0;
    out_size_ = 0;
    in_utf8_ = {};
    out_utf8_ = {};
    incoming_len_ = 0;
    pending_len_ = 0;
    ArmHeader();
  }

 private:
  struct Frag {
    WebSocketOpcode opcode{WebSocketOpcode::kContinuation};
    std::size_t size{0};
    ws_detail::Utf8State utf8{};
  };

  struct Ingested {
    bool done{false};
    std::size_t taken{0};
  };

  void Fail() noexcept {
    failed_ = true;
    in_active_ = false;
    incoming_len_ = 0;
    out_active_ = false;
    ArmHeader();
  }

  void ArmHeader() noexcept {
    hdr_got_ = 0;
    hdr_need_ = 2;
    length_ready_ = false;
    mask_ready_ = false;
    pay_len_ = 0;
    pay_got_ = 0;
    short_len_ = 0;
  }

  [[nodiscard]] Result<void> ValidateSend(WebSocketOpcode opcode) const noexcept {
    if (failed_ && opcode != WebSocketOpcode::kClose) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    if ((close_sent_ && (opcode == WebSocketOpcode::kClose || !WebSocketIsControl(opcode))) ||
        (close_received_ && opcode != WebSocketOpcode::kClose)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    return {};
  }

  [[nodiscard]] Result<Frag> AdvanceFragment(bool active, WebSocketOpcode active_opcode, std::size_t active_size,
                                             ws_detail::Utf8State utf8, bool fin, WebSocketOpcode opcode,
                                             std::span<const std::uint8_t> payload) const noexcept {
    Frag next;
    if (active && opcode == WebSocketOpcode::kContinuation) {
      next.opcode = active_opcode;
    } else if (!active && (opcode == WebSocketOpcode::kText || opcode == WebSocketOpcode::kBinary)) {
      next.opcode = opcode;
    } else {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    if (active_size > MaxMessage || payload.size() > MaxMessage - active_size) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketPayloadTooLarge));
    }
    next.size = active_size + payload.size();
    if (next.opcode == WebSocketOpcode::kText) {
      const auto fed = ws_detail::FeedUtf8(active ? utf8 : ws_detail::Utf8State{}, payload, fin);
      if (!fed.ok) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketInvalidUtf8));
      }
      next.utf8 = fed;
    }
    return next;
  }

  [[nodiscard]] static Result<std::size_t> WriteFrame(std::span<std::uint8_t> dest, bool fin, WebSocketOpcode opcode,
                                                      std::span<const std::uint8_t> payload, bool masked,
                                                      std::array<std::uint8_t, 4> mask) noexcept {
    const auto len = payload.size();
    std::uint8_t short_len = 0;
    std::size_t header_len = 2;
    if (len < 126) {
      short_len = static_cast<std::uint8_t>(len);
    } else if (len <= std::numeric_limits<std::uint16_t>::max()) {
      short_len = 126;
      header_len = 4;
    } else {
      short_len = 127;
      header_len = 10;
    }
    if (masked) {
      header_len += 4;
    }
    if (dest.size() < header_len + len) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketPayloadTooLarge));
    }
    const auto word = WebSocketHeaderWord::ForFrame(fin, std::to_underlying(opcode), masked, short_len);
    dest[0] = static_cast<std::uint8_t>(word.raw & 0xffU);
    dest[1] = static_cast<std::uint8_t>((word.raw >> 8U) & 0xffU);
    if (short_len == 126) {
      const auto be = ws_detail::WireBigEndian(static_cast<std::uint16_t>(len));
      std::memcpy(dest.data() + 2, &be, sizeof(be));
    } else if (short_len == 127) {
      const auto be = ws_detail::WireBigEndian(static_cast<std::uint64_t>(len));
      std::memcpy(dest.data() + 2, &be, sizeof(be));
    }
    std::size_t cursor = short_len == 127 ? 10 : (short_len == 126 ? 4 : 2);
    if (masked) {
      std::memcpy(dest.data() + cursor, mask.data(), 4);
      cursor += 4;
    }
    if (len > 0) {
      std::memcpy(dest.data() + cursor, payload.data(), len);
      if (masked) {
        ApplyWebSocketMask(dest.subspan(cursor, len), mask);
      }
    }
    return cursor + len;
  }

  [[nodiscard]] Result<void> OpenHeader() noexcept {
    const WebSocketHeaderWord header{static_cast<std::uint64_t>(hdr_[0]) | (static_cast<std::uint64_t>(hdr_[1]) << 8U)};
    if (!header.ReservedClear()) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    auto opcode = ws_detail::ParseOpcode(header.OpcodeRaw());
    if (!opcode.has_value()) {
      return std::unexpected(opcode.error());
    }
    opcode_ = *opcode;
    fin_ = header.Fin();
    masked_ = header.Masked();
    if (masked_ != (role_ == WebSocketRole::kServer)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    control_ = WebSocketIsControl(opcode_);
    short_len_ = header.ShortLength();
    if (control_ && (!fin_ || short_len_ > 125)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    if (short_len_ < 126) {
      auto sized = AcceptLength(short_len_);
      if (!sized.has_value()) {
        return sized;
      }
      hdr_need_ = static_cast<std::uint8_t>(masked_ ? 6 : 2);
    } else {
      hdr_need_ = short_len_ == 126 ? 4 : 10;
    }
    return {};
  }

  [[nodiscard]] Result<void> AcceptLength(std::uint64_t len) noexcept {
    if (len > MaxMessage || (!control_ && len > MaxMessage - incoming_len_)) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketPayloadTooLarge));
    }
    pay_len_ = len;
    length_ready_ = true;
    return {};
  }

  [[nodiscard]] Result<void> NoteExtended() noexcept {
    if (short_len_ == 126) {
      std::uint16_t wire{};
      std::memcpy(&wire, hdr_.data() + 2, sizeof(wire));
      const auto len = static_cast<std::uint64_t>(ws_detail::WireBigEndian(wire));
      if (len < 126) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
      }
      auto sized = AcceptLength(len);
      if (!sized.has_value()) {
        return sized;
      }
      hdr_need_ = static_cast<std::uint8_t>(masked_ ? 8 : 4);
      return {};
    }
    if ((hdr_[2] & 0x80U) != 0) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    std::uint64_t wire{};
    std::memcpy(&wire, hdr_.data() + 2, sizeof(wire));
    const auto wide = ws_detail::WireBigEndian(wire);
    if (wide <= std::numeric_limits<std::uint16_t>::max()) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    auto sized = AcceptLength(wide);
    if (!sized.has_value()) {
      return sized;
    }
    hdr_need_ = static_cast<std::uint8_t>(masked_ ? 14 : 10);
    return {};
  }

  [[nodiscard]] Result<Ingested> Ingest(std::span<const std::uint8_t> in) noexcept {
    std::size_t used = 0;
    while (used < in.size() && (hdr_got_ < hdr_need_ || !length_ready_)) {
      if (hdr_got_ == 0 && close_received_) {
        return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
      }
      hdr_[hdr_got_++] = in[used++];
      if (hdr_got_ == 2) {
        auto opened = OpenHeader();
        if (!opened.has_value()) {
          return std::unexpected(opened.error());
        }
      } else if (!length_ready_ && ((short_len_ == 126 && hdr_got_ == 4) || (short_len_ == 127 && hdr_got_ == 10))) {
        auto extended = NoteExtended();
        if (!extended.has_value()) {
          return std::unexpected(extended.error());
        }
      }
    }
    if (hdr_got_ < hdr_need_ || !length_ready_) {
      return Ingested{false, used};
    }
    if (masked_ && pay_got_ == 0 && !mask_ready_) {
      std::memcpy(mask_.data(), hdr_.data() + (hdr_need_ - 4), 4);
      mask_ready_ = true;
      if (!control_) {
        frame_base_ = incoming_len_;
      }
    }
    if (!masked_ && pay_got_ == 0 && !control_ && frame_base_ != incoming_len_) {
      frame_base_ = incoming_len_;
    }
    const std::uint64_t need = pay_len_ - pay_got_;
    const std::size_t avail = in.size() - used;
    const std::size_t take = need < avail ? static_cast<std::size_t>(need) : avail;
    if (take > 0) {
      auto* dest = control_ ? control_buf_.data() + pay_got_ : incoming_.data() + incoming_len_;
      std::memcpy(dest, in.data() + used, take);
      if (masked_) {
        const std::array<std::uint8_t, 4> turned{
            mask_[pay_got_ & 3U],
            mask_[(pay_got_ + 1U) & 3U],
            mask_[(pay_got_ + 2U) & 3U],
            mask_[(pay_got_ + 3U) & 3U],
        };
        ApplyWebSocketMask(std::span<std::uint8_t>(dest, take), turned);
      }
      if (!control_) {
        incoming_len_ += take;
      }
      pay_got_ += take;
      used += take;
    }
    return Ingested{pay_got_ == pay_len_, used};
  }

  [[nodiscard]] Result<std::optional<WebSocketMessage>> HandleFrame() noexcept {
    const auto payload =
        control_ ? std::span<const std::uint8_t>(control_buf_.data(), static_cast<std::size_t>(pay_len_))
                 : std::span<const std::uint8_t>(incoming_.data() + frame_base_, static_cast<std::size_t>(pay_len_));
    if (opcode_ == WebSocketOpcode::kPing || opcode_ == WebSocketOpcode::kPong) {
      if (opcode_ == WebSocketOpcode::kPing) {
        auto queued = QueuePong(payload);
        if (!queued.has_value()) {
          return std::unexpected(queued.error());
        }
      }
      WebSocketMessage message;
      message.kind = opcode_ == WebSocketOpcode::kPing ? WebSocketMessageKind::kPing : WebSocketMessageKind::kPong;
      message.payload = Bytes::CopyFromSlice(payload);
      return std::optional<WebSocketMessage>(std::move(message));
    }
    if (opcode_ == WebSocketOpcode::kClose) {
      auto close = ws_detail::ParseClose(payload);
      if (!close.has_value()) {
        return std::unexpected(close.error());
      }
      WebSocketMessage closed;
      closed.kind = WebSocketMessageKind::kClose;
      closed.close_code = *close;
      if (payload.size() > 2) {
        closed.payload = Bytes::CopyFromSlice(payload.subspan(2));
      }
      close_received_ = true;
      in_active_ = false;
      incoming_len_ = 0;
      out_active_ = false;
      return std::optional<WebSocketMessage>(std::move(closed));
    }
    auto advanced = AdvanceFragment(in_active_, in_opcode_, in_size_, in_utf8_, fin_, opcode_, payload);
    if (!advanced.has_value()) {
      return std::unexpected(advanced.error());
    }
    in_active_ = true;
    in_opcode_ = advanced->opcode;
    in_size_ = advanced->size;
    in_utf8_ = advanced->utf8;
    if (!fin_) {
      return std::optional<WebSocketMessage>{};
    }
    WebSocketMessage done;
    done.kind = in_opcode_ == WebSocketOpcode::kText ? WebSocketMessageKind::kText : WebSocketMessageKind::kBinary;
    done.payload = Bytes::CopyFromSlice(std::span<const std::uint8_t>(incoming_.data(), incoming_len_));
    incoming_len_ = 0;
    in_active_ = false;
    in_size_ = 0;
    in_utf8_ = {};
    return std::optional<WebSocketMessage>(std::move(done));
  }

  [[nodiscard]] Result<void> QueuePong(std::span<const std::uint8_t> payload) noexcept {
    if (payload.size() > 125) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    const bool masked = role_ == WebSocketRole::kClient;
    std::array<std::uint8_t, 4> mask{};
    if (masked && RAND_bytes(mask.data(), 4) != 1) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketProtocolError));
    }
    if (pending_len_ > pending_.size()) {
      return std::unexpected(Error::FromProto(ProtoErrorCode::kWebSocketPayloadTooLarge));
    }
    auto wired = WriteFrame(std::span<std::uint8_t>(pending_.data() + pending_len_, pending_.size() - pending_len_), true,
                            WebSocketOpcode::kPong, payload, masked, mask);
    if (!wired.has_value()) {
      return std::unexpected(wired.error());
    }
    pending_len_ += *wired;
    return {};
  }

  WebSocketRole role_;
  bool close_sent_{false};
  bool close_received_{false};
  bool failed_{false};
  bool in_active_{false};
  bool out_active_{false};
  bool fin_{false};
  bool masked_{false};
  bool mask_ready_{false};
  bool control_{false};
  bool length_ready_{false};
  WebSocketOpcode opcode_{WebSocketOpcode::kContinuation};
  WebSocketOpcode in_opcode_{WebSocketOpcode::kContinuation};
  WebSocketOpcode out_opcode_{WebSocketOpcode::kContinuation};
  std::uint8_t short_len_{0};
  std::uint8_t hdr_got_{0};
  std::uint8_t hdr_need_{2};
  std::array<std::uint8_t, 14> hdr_{};
  std::array<std::uint8_t, 4> mask_{};
  std::uint64_t pay_len_{0};
  std::uint64_t pay_got_{0};
  std::size_t frame_base_{0};
  std::size_t in_size_{0};
  std::size_t out_size_{0};
  ws_detail::Utf8State in_utf8_{};
  ws_detail::Utf8State out_utf8_{};
  std::array<std::uint8_t, MaxMessage> incoming_{};
  std::size_t incoming_len_{0};
  std::array<std::uint8_t, 125> control_buf_{};
  std::array<std::uint8_t, 512> pending_{};
  std::size_t pending_len_{0};
};

}  // namespace nexora
