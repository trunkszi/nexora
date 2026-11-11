#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <uarch/uarch.hpp>
#include <utility>

#include "nexora/tls/tls_config.hpp"

namespace nexora {

/// Sans-IO TLS 1.3 session. Ciphertext crosses the memory BIO only.
class TlsSession {
 public:
  TlsSession(const TlsSession&) = delete ("single-owner TLS session; move instead");
  TlsSession& operator=(const TlsSession&) = delete ("single-owner TLS session; move instead");
  TlsSession(TlsSession&& other) noexcept;
  TlsSession& operator=(TlsSession&& other) noexcept;
  ~TlsSession();

  /// ClientHello is queued before this returns. `server_name` is SNI and the SAN/IP check.
  [[nodiscard]] static Result<TlsSession> CreateClient(const TlsClientConfig& cfg, std::string_view server_name) noexcept;
  [[nodiscard]] static Result<TlsSession> CreateServer(const TlsServerConfig& cfg) noexcept;

  /// Runs the handshake, then flushes queued plaintext and a deferred close_notify.
  [[nodiscard]] Result<void> DriveHandshake() noexcept;
  /// Accepts ciphertext, including a partial trailing record. Returns bytes consumed.
  [[nodiscard]] Result<std::size_t> FeedCiphertext(std::span<const std::uint8_t> data) noexcept;
  /// Copies queued ciphertext into `out`. Returns bytes copied.
  [[nodiscard]] Result<std::size_t> TakeCiphertext(std::span<std::uint8_t> out) noexcept;
  /// Encrypts plaintext, or queues it until the handshake finishes. Returns bytes accepted.
  [[nodiscard]] Result<std::size_t> WritePlaintext(std::span<const std::uint8_t> data) noexcept;
  /// Decrypts into `out`. Returns bytes produced. Zero means no plaintext is ready.
  [[nodiscard]] Result<std::size_t> ReadPlaintext(std::span<std::uint8_t> out) noexcept;
  /// Queues one close_notify. Further plaintext writes fail. Repeated calls succeed.
  [[nodiscard]] Result<void> SendCloseNotify() noexcept;

  [[nodiscard]] bool IsHandshakeComplete() const noexcept;
  /// True after the peer close_notify has been read.
  [[nodiscard]] bool IsPeerClosed() const noexcept { return peer_closed_; }
  [[nodiscard]] bool HasPendingCiphertextOut() const noexcept;
  [[nodiscard]] AlpnProtocol NegotiatedAlpn() const noexcept;

 private:
  explicit TlsSession(SSL* ssl) noexcept : ssl_(ssl) {}

  template <typename T>
  [[nodiscard]] Result<T> Fail(Error error) noexcept;
  [[nodiscard]] Result<void> FailVoid(Error error) noexcept;
  [[nodiscard]] bool WouldBlock(int rc) const noexcept;
  [[nodiscard]] Error Classify(int rc) const noexcept;
  [[nodiscard]] Result<void> FlushPlain() noexcept;
  [[nodiscard]] Result<void> FlushClose() noexcept;
  [[nodiscard]] Result<void> Adopt(SSL_CTX* ctx, bool client) noexcept;

  static constexpr std::size_t kRecordBodyMax = 18432;
  static constexpr std::size_t kQueueLimit = 65536;

  SSL* ssl_{nullptr};
  std::array<std::uint8_t, kRecordBodyMax + 5> inbound_{};
  std::size_t inbound_len_{0};
  std::array<std::uint8_t, kQueueLimit> queued_{};
  std::size_t queued_pos_{0};
  std::size_t queued_len_{0};
  Error failure_{};
  bool failed_{false};
  bool local_closed_{false};
  bool close_sent_{false};
  bool peer_closed_{false};
  AlpnProtocol required_alpn_{AlpnProtocol::kNone};
};

inline TlsSession::TlsSession(TlsSession&& other) noexcept
    : ssl_(std::exchange(other.ssl_, nullptr)),
      inbound_(other.inbound_),
      inbound_len_(other.inbound_len_),
      queued_(other.queued_),
      queued_pos_(other.queued_pos_),
      queued_len_(other.queued_len_),
      failure_(other.failure_),
      failed_(other.failed_),
      local_closed_(other.local_closed_),
      close_sent_(other.close_sent_),
      peer_closed_(other.peer_closed_),
      required_alpn_(std::exchange(other.required_alpn_, AlpnProtocol::kNone)) {
  OPENSSL_cleanse(other.queued_.data(), other.queued_.size());
  other.inbound_len_ = 0;
  other.queued_pos_ = 0;
  other.queued_len_ = 0;
  other.failed_ = false;
  other.local_closed_ = false;
  other.close_sent_ = false;
  other.peer_closed_ = false;
}

inline TlsSession& TlsSession::operator=(TlsSession&& other) noexcept {
  if (this != &other) {
    if (ssl_ != nullptr) SSL_free(ssl_);
    OPENSSL_cleanse(queued_.data(), queued_.size());
    ssl_ = std::exchange(other.ssl_, nullptr);
    inbound_ = other.inbound_;
    inbound_len_ = other.inbound_len_;
    queued_ = other.queued_;
    queued_pos_ = other.queued_pos_;
    queued_len_ = other.queued_len_;
    failure_ = other.failure_;
    failed_ = other.failed_;
    local_closed_ = other.local_closed_;
    close_sent_ = other.close_sent_;
    peer_closed_ = other.peer_closed_;
    required_alpn_ = std::exchange(other.required_alpn_, AlpnProtocol::kNone);
    OPENSSL_cleanse(other.queued_.data(), other.queued_.size());
    other.inbound_len_ = 0;
    other.queued_pos_ = 0;
    other.queued_len_ = 0;
    other.failed_ = false;
    other.local_closed_ = false;
    other.close_sent_ = false;
    other.peer_closed_ = false;
  }
  return *this;
}

inline TlsSession::~TlsSession() {
  if (ssl_ != nullptr) SSL_free(ssl_);
  OPENSSL_cleanse(queued_.data(), queued_.size());
}

template <typename T>
inline Result<T> TlsSession::Fail(Error error) noexcept {
  ERR_clear_error();
  failed_ = true;
  failure_ = error;
  return std::unexpected(error);
}

inline Result<void> TlsSession::FailVoid(Error error) noexcept { return Fail<void>(error); }

inline bool TlsSession::WouldBlock(int rc) const noexcept {
  const int status = SSL_get_error(ssl_, rc);
  return status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE;
}

inline Error TlsSession::Classify(int rc) const noexcept {
  if (SSL_get_verify_mode(ssl_) != SSL_VERIFY_NONE && SSL_get_verify_result(ssl_) != X509_V_OK) {
    return Error::FromProto(ProtoErrorCode::kTlsVerifyFailed);
  }
  const int status = SSL_get_error(ssl_, rc);
  if (status == SSL_ERROR_ZERO_RETURN) return Error::FromProto(ProtoErrorCode::kTlsClosed);
  if (status == SSL_ERROR_SYSCALL) return Error::FromProto(ProtoErrorCode::kTlsIoError);
  return Error::FromProto(ProtoErrorCode::kTlsHandshakeFailed);
}

inline bool TlsSession::IsHandshakeComplete() const noexcept { return ssl_ != nullptr && SSL_is_init_finished(ssl_) == 1; }

inline bool TlsSession::HasPendingCiphertextOut() const noexcept {
  return ssl_ != nullptr && BIO_ctrl_pending(SSL_get_wbio(ssl_)) != 0;
}

inline AlpnProtocol TlsSession::NegotiatedAlpn() const noexcept {
  if (ssl_ == nullptr) return AlpnProtocol::kNone;
  const std::uint8_t* data = nullptr;
  unsigned len = 0;
  SSL_get0_alpn_selected(ssl_, &data, &len);
  if (len == 2 && data[0] == 'h' && data[1] == '2') return AlpnProtocol::kHttp2;
  if (len == 8 && std::memcmp(data, "http/1.1", 8) == 0) return AlpnProtocol::kHttp11;
  return AlpnProtocol::kNone;
}

inline Result<void> TlsSession::Adopt(SSL_CTX* ctx, bool client) noexcept {
  ssl_ = SSL_new(ctx);
  if (uarch::unlikely(ssl_ == nullptr)) {
    ERR_clear_error();
    return std::unexpected(detail::ConfigError());
  }
  BIO* input = BIO_new(BIO_s_mem());
  BIO* output = BIO_new(BIO_s_mem());
  if (uarch::unlikely(input == nullptr || output == nullptr)) {
    BIO_free(input);
    BIO_free(output);
    SSL_free(ssl_);
    ssl_ = nullptr;
    ERR_clear_error();
    return std::unexpected(Error::FromProto(ProtoErrorCode::kTlsIoError));
  }
  SSL_set_bio(ssl_, input, output);
  if (client) {
    SSL_set_connect_state(ssl_);
  } else {
    SSL_set_accept_state(ssl_);
  }
  return {};
}

inline Result<void> TlsSession::FlushPlain() noexcept {
  while (queued_pos_ < queued_len_) {
    const auto remain = queued_len_ - queued_pos_;
    const int chunk = static_cast<int>(std::min<std::size_t>(remain, 16384));
    ERR_clear_error();
    const int wrote = SSL_write(ssl_, queued_.data() + queued_pos_, chunk);
    if (wrote > 0) {
      OPENSSL_cleanse(queued_.data() + queued_pos_, static_cast<std::size_t>(wrote));
      queued_pos_ += static_cast<std::size_t>(wrote);
      continue;
    }
    if (WouldBlock(wrote)) return {};
    return FailVoid(Classify(wrote));
  }
  queued_pos_ = 0;
  queued_len_ = 0;
  return {};
}

inline Result<void> TlsSession::FlushClose() noexcept {
  if (!local_closed_ || close_sent_ || !IsHandshakeComplete() || queued_pos_ < queued_len_) return {};
  ERR_clear_error();
  const int rc = SSL_shutdown(ssl_);
  if (rc >= 0) {
    close_sent_ = true;
    return {};
  }
  if (WouldBlock(rc)) return {};
  return FailVoid(Classify(rc));
}

inline Result<void> TlsSession::DriveHandshake() noexcept {
  if (uarch::unlikely(ssl_ == nullptr)) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
  if (uarch::unlikely(failed_)) return std::unexpected(failure_);
  if (!IsHandshakeComplete()) {
    ERR_clear_error();
    const int rc = SSL_do_handshake(ssl_);
    if (rc != 1 && !WouldBlock(rc)) return FailVoid(Classify(rc));
  }
  if (!IsHandshakeComplete()) return {};
  if (required_alpn_ != AlpnProtocol::kNone && NegotiatedAlpn() != required_alpn_) {
    return FailVoid(Error::FromProto(ProtoErrorCode::kTlsHandshakeFailed));
  }
  if (auto flushed = FlushPlain(); !flushed) return flushed;
  return FlushClose();
}

inline Result<std::size_t> TlsSession::FeedCiphertext(std::span<const std::uint8_t> data) noexcept {
  if (uarch::unlikely(ssl_ == nullptr)) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
  if (uarch::unlikely(failed_)) return std::unexpected(failure_);
  if (peer_closed_) return data.size();
  std::size_t consumed = 0;
  while (consumed < data.size()) {
    if (inbound_len_ < 5) {
      const std::size_t need = 5 - inbound_len_;
      const std::size_t take = std::min(need, data.size() - consumed);
      std::memcpy(inbound_.data() + inbound_len_, data.data() + consumed, take);
      inbound_len_ += take;
      consumed += take;
      if (inbound_len_ < 5) break;
    }
    const auto body = static_cast<std::size_t>(inbound_[3]) << 8 | inbound_[4];
    if (uarch::unlikely(body > kRecordBodyMax)) return Fail<std::size_t>(Error::FromProto(ProtoErrorCode::kTlsIoError));
    const std::size_t total = 5 + body;
    if (inbound_len_ < total) {
      const std::size_t take = std::min(total - inbound_len_, data.size() - consumed);
      std::memcpy(inbound_.data() + inbound_len_, data.data() + consumed, take);
      inbound_len_ += take;
      consumed += take;
      if (inbound_len_ < total) break;
    }
    ERR_clear_error();
    const int wrote = BIO_write(SSL_get_rbio(ssl_), inbound_.data(), static_cast<int>(total));
    inbound_len_ = 0;
    if (wrote != static_cast<int>(total)) return Fail<std::size_t>(Error::FromProto(ProtoErrorCode::kTlsIoError));
    if (auto drove = DriveHandshake(); !drove) return std::unexpected(drove.error());
  }
  if (consumed == 0) {
    if (auto drove = DriveHandshake(); !drove) return std::unexpected(drove.error());
  }
  return consumed;
}

inline Result<std::size_t> TlsSession::TakeCiphertext(std::span<std::uint8_t> out) noexcept {
  if (uarch::unlikely(ssl_ == nullptr)) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
  if (out.empty() || !HasPendingCiphertextOut()) return std::size_t{0};
  const int cap = static_cast<int>(std::min<std::size_t>(out.size(), static_cast<std::size_t>(INT32_MAX)));
  ERR_clear_error();
  const int read = BIO_read(SSL_get_wbio(ssl_), out.data(), cap);
  if (read > 0) return static_cast<std::size_t>(read);
  if (read == 0 || BIO_should_retry(SSL_get_wbio(ssl_))) return std::size_t{0};
  return Fail<std::size_t>(Error::FromProto(ProtoErrorCode::kTlsIoError));
}

inline Result<std::size_t> TlsSession::WritePlaintext(std::span<const std::uint8_t> data) noexcept {
  if (uarch::unlikely(ssl_ == nullptr)) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
  if (uarch::unlikely(failed_)) return std::unexpected(failure_);
  if (local_closed_) return std::unexpected(Error::FromProto(ProtoErrorCode::kTlsClosed));
  const auto pending = static_cast<std::size_t>(BIO_ctrl_pending(SSL_get_wbio(ssl_)));
  const std::size_t queued = queued_len_ - queued_pos_;
  const std::size_t used = pending + queued;
  if (used >= kQueueLimit) return std::size_t{0};
  const std::size_t room = std::min(data.size(), kQueueLimit - used);
  if (!IsHandshakeComplete()) {
    if (!data.empty()) std::memcpy(queued_.data() + queued_len_, data.data(), room);
    queued_len_ += room;
    return room;
  }
  if (auto flushed = FlushPlain(); !flushed) return std::unexpected(flushed.error());
  std::size_t accepted = 0;
  while (accepted < room) {
    const int chunk = static_cast<int>(std::min<std::size_t>(room - accepted, 16384));
    ERR_clear_error();
    const int wrote = SSL_write(ssl_, data.data() + accepted, chunk);
    if (wrote > 0) {
      accepted += static_cast<std::size_t>(wrote);
      continue;
    }
    if (WouldBlock(wrote)) break;
    return Fail<std::size_t>(Classify(wrote));
  }
  return accepted;
}

inline Result<std::size_t> TlsSession::ReadPlaintext(std::span<std::uint8_t> out) noexcept {
  if (uarch::unlikely(ssl_ == nullptr)) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
  if (uarch::unlikely(failed_)) return std::unexpected(failure_);
  if (auto drove = DriveHandshake(); !drove) return std::unexpected(drove.error());
  if (!IsHandshakeComplete() || out.empty() || peer_closed_) return std::size_t{0};
  const int cap = static_cast<int>(std::min<std::size_t>(out.size(), static_cast<std::size_t>(INT32_MAX)));
  ERR_clear_error();
  const int read = SSL_read(ssl_, out.data(), cap);
  if (read > 0) return static_cast<std::size_t>(read);
  const int status = SSL_get_error(ssl_, read);
  if (status == SSL_ERROR_ZERO_RETURN) {
    peer_closed_ = true;
    return std::size_t{0};
  }
  if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE) return std::size_t{0};
  return Fail<std::size_t>(Classify(read));
}

inline Result<void> TlsSession::SendCloseNotify() noexcept {
  if (uarch::unlikely(ssl_ == nullptr)) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
  if (uarch::unlikely(failed_)) return std::unexpected(failure_);
  local_closed_ = true;
  if (auto flushed = FlushPlain(); !flushed) return flushed;
  return FlushClose();
}

namespace tls_detail {

struct ServerName {
  static constexpr std::size_t kCap = 256;
  bool ip{false};
  std::array<char, kCap> text{};
  std::size_t len{0};
};

[[nodiscard]] inline bool DnsOk(std::string_view dns) noexcept {
  if (dns.empty() || dns.size() > 253) return false;
  std::size_t label = 0;
  bool at_start = true;
  for (const char ch : dns) {
    if (ch == '.') {
      if (label == 0 || label > 63) return false;
      label = 0;
      at_start = true;
      continue;
    }
    const bool alpha = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9');
    if (!alpha && ch != '-') return false;
    if (at_start && ch == '-') return false;
    ++label;
    at_start = false;
    if (label > 63) return false;
  }
  return label > 0 && dns.back() != '-';
}

[[nodiscard]] inline Result<ServerName> PrepareName(std::string_view name) noexcept {
  if (name.size() >= ServerName::kCap || name.find('\0') != std::string_view::npos) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidArgument));
  }
  ServerName out;
  std::memcpy(out.text.data(), name.data(), name.size());
  out.len = name.size();
  if (out.len > 0 && out.text[out.len - 1] == '.') {
    --out.len;
    out.text[out.len] = '\0';
  } else {
    out.text[out.len] = '\0';
  }
  std::array<unsigned char, 16> address{};
  if (inet_pton(AF_INET, out.text.data(), address.data()) == 1 || inet_pton(AF_INET6, out.text.data(), address.data()) == 1) {
    out.ip = true;
    return out;
  }
  if (!DnsOk(std::string_view(out.text.data(), out.len))) {
    return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidArgument));
  }
  return out;
}

}  // namespace tls_detail

inline Result<TlsSession> TlsSession::CreateClient(const TlsClientConfig& cfg, std::string_view server_name) noexcept {
  if (cfg.Raw() == nullptr) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
  auto prepared = tls_detail::PrepareName(server_name);
  if (!prepared) return std::unexpected(prepared.error());
  TlsSession session(nullptr);
  if (auto adopted = session.Adopt(cfg.Raw(), true); !adopted) return std::unexpected(adopted.error());
  session.required_alpn_ = cfg.required_alpn_;
  const detail::AlpnWire* wire = detail::AlpnOf(cfg.Raw());
  if (wire != nullptr && wire->len > 0 && SSL_set_alpn_protos(session.ssl_, wire->bytes.data(), wire->len) != 0) {
    return std::unexpected(detail::ConfigError());
  }
  X509_VERIFY_PARAM* params = SSL_get0_param(session.ssl_);
  if (params == nullptr) return std::unexpected(detail::ConfigError());
  if (prepared->ip) {
    if (X509_VERIFY_PARAM_set1_ip_asc(params, prepared->text.data()) != 1) return std::unexpected(detail::ConfigError());
  } else {
    X509_VERIFY_PARAM_set_hostflags(params, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
    if (SSL_set_tlsext_host_name(session.ssl_, prepared->text.data()) != 1 ||
        X509_VERIFY_PARAM_set1_host(params, prepared->text.data(), prepared->len) != 1) {
      return std::unexpected(detail::ConfigError());
    }
  }
  if (auto drove = session.DriveHandshake(); !drove) return std::unexpected(drove.error());
  return session;
}

inline Result<TlsSession> TlsSession::CreateServer(const TlsServerConfig& cfg) noexcept {
  if (cfg.Raw() == nullptr) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
  TlsSession session(nullptr);
  if (auto adopted = session.Adopt(cfg.Raw(), false); !adopted) return std::unexpected(adopted.error());
  session.required_alpn_ = cfg.required_alpn_;
  return session;
}

}  // namespace nexora
