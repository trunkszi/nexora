#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

#include "nexora/error/proto_error.hpp"
#include "nexora/tls/detail/tls_ctx.hpp"
#include "nexora/tls/tls_types.hpp"

namespace nexora {

/// Reusable TLS 1.3 client trust, identity, and ALPN policy.
class TlsClientConfig {
 public:
  TlsClientConfig(const TlsClientConfig&) = delete ("single-owner TLS session; move instead");
  TlsClientConfig& operator=(const TlsClientConfig&) = delete ("single-owner TLS session; move instead");
  TlsClientConfig(TlsClientConfig&& other) noexcept
      : ctx_(std::exchange(other.ctx_, nullptr)), required_alpn_(std::exchange(other.required_alpn_, AlpnProtocol::kNone)) {}
  TlsClientConfig& operator=(TlsClientConfig&& other) noexcept {
    if (this != &other) {
      Reset();
      ctx_ = std::exchange(other.ctx_, nullptr);
      required_alpn_ = std::exchange(other.required_alpn_, AlpnProtocol::kNone);
    }
    return *this;
  }
  ~TlsClientConfig() { Reset(); }

  /// Host trust anchors, TLS 1.3 only, ALPN `h2` then `http/1.1`.
  [[nodiscard]] static Result<TlsClientConfig> CreateDefault() noexcept;
  /// Skips X.509 trust and hostname checks. Handshake signatures still run.
  [[nodiscard]] static Result<TlsClientConfig> CreateInsecureForTest() noexcept;
  /// Adds every certificate in `pem` as a trust anchor.
  [[nodiscard]] Result<void> SetCaCertPem(std::string_view pem) noexcept;
  /// Installs a PEM certificate chain and matching private key for client auth.
  [[nodiscard]] Result<void> SetClientIdentityPem(std::string_view cert_pem, std::string_view key_pem) noexcept;
  /// Replaces the client ALPN offer list. `kNone` entries are rejected.
  [[nodiscard]] Result<void> SetAlpn(std::span<const AlpnProtocol> protos) noexcept;
  /// Reads one PEM trust bundle from `path` and installs it as `SetCaCertPem`.
  [[nodiscard]] Result<void> SetCaCertFile(std::string_view path) noexcept;
  /// Reads a PEM certificate chain and a PEM private key from the two paths.
  [[nodiscard]] Result<void> SetClientIdentityFiles(std::string_view cert_path, std::string_view key_path) noexcept;
  /// Requires `NegotiatedAlpn() == required` once the handshake finishes. `kNone` clears the check.
  [[nodiscard]] Result<void> SetRequiredAlpn(AlpnProtocol required) noexcept;

 private:
  friend class TlsSession;
  explicit TlsClientConfig(SSL_CTX* ctx) noexcept : ctx_(ctx) {}
  void Reset() noexcept {
    if (ctx_ != nullptr) SSL_CTX_free(ctx_);
    ctx_ = nullptr;
  }
  [[nodiscard]] SSL_CTX* Raw() const noexcept { return ctx_; }
  [[nodiscard]] AlpnProtocol RequiredAlpn() const noexcept { return required_alpn_; }

  SSL_CTX* ctx_{nullptr};
  AlpnProtocol required_alpn_{AlpnProtocol::kNone};
};

/// Reusable TLS 1.3 server identity and ALPN preference.
class TlsServerConfig {
 public:
  TlsServerConfig(const TlsServerConfig&) = delete ("single-owner TLS session; move instead");
  TlsServerConfig& operator=(const TlsServerConfig&) = delete ("single-owner TLS session; move instead");
  TlsServerConfig(TlsServerConfig&& other) noexcept
      : ctx_(std::exchange(other.ctx_, nullptr)), required_alpn_(std::exchange(other.required_alpn_, AlpnProtocol::kNone)) {}
  TlsServerConfig& operator=(TlsServerConfig&& other) noexcept {
    if (this != &other) {
      Reset();
      ctx_ = std::exchange(other.ctx_, nullptr);
      required_alpn_ = std::exchange(other.required_alpn_, AlpnProtocol::kNone);
    }
    return *this;
  }
  ~TlsServerConfig() { Reset(); }

  /// Server identity from a PEM chain and private key. Client auth is not requested.
  [[nodiscard]] static Result<TlsServerConfig> FromPem(std::string_view cert_pem, std::string_view key_pem) noexcept;
  /// Requires a client certificate trusted by `client_ca_pem`.
  [[nodiscard]] static Result<TlsServerConfig> FromPemWithClientAuth(std::string_view cert_pem, std::string_view key_pem,
                                                                     std::string_view client_ca_pem) noexcept;
  /// Fresh P-256 certificate for `localhost`, `127.0.0.1`, and `::1`.
  [[nodiscard]] static Result<TlsServerConfig> SelfSignedForLocalhost() noexcept;
  /// Replaces the server ALPN preference order.
  [[nodiscard]] Result<void> SetAlpn(std::span<const AlpnProtocol> protos) noexcept;
  /// Server identity loaded from a PEM chain file and a PEM key file.
  [[nodiscard]] static Result<TlsServerConfig> FromPemFiles(std::string_view cert_path, std::string_view key_path) noexcept;
  /// `FromPemFiles` plus a client-CA bundle read from `client_ca_path`.
  [[nodiscard]] static Result<TlsServerConfig> FromPemFilesWithClientAuth(std::string_view cert_path, std::string_view key_path,
                                                                          std::string_view client_ca_path) noexcept;
  /// Requires `NegotiatedAlpn() == required` once the handshake finishes. `kNone` clears the check.
  [[nodiscard]] Result<void> SetRequiredAlpn(AlpnProtocol required) noexcept;

 private:
  friend class TlsSession;
  explicit TlsServerConfig(SSL_CTX* ctx) noexcept : ctx_(ctx) {}
  void Reset() noexcept {
    if (ctx_ != nullptr) SSL_CTX_free(ctx_);
    ctx_ = nullptr;
  }
  [[nodiscard]] SSL_CTX* Raw() const noexcept { return ctx_; }
  [[nodiscard]] AlpnProtocol RequiredAlpn() const noexcept { return required_alpn_; }

  SSL_CTX* ctx_{nullptr};
  AlpnProtocol required_alpn_{AlpnProtocol::kNone};
};

inline Result<TlsClientConfig> TlsClientConfig::CreateDefault() noexcept {
  auto ctx = detail::MakeCtx(detail::VerifyMode::kPeer);
  if (!ctx) return std::unexpected(ctx.error());
  TlsClientConfig config(*ctx);
  if (auto roots = detail::LoadHostRoots(config.ctx_); !roots) return std::unexpected(roots.error());
  if (auto alpn = detail::ApplyAlpn(config.ctx_, detail::kDefaultAlpn); !alpn) return std::unexpected(alpn.error());
  *ctx = nullptr;
  return config;
}

inline Result<TlsClientConfig> TlsClientConfig::CreateInsecureForTest() noexcept {
  auto ctx = detail::MakeCtx(detail::VerifyMode::kInsecure);
  if (!ctx) return std::unexpected(ctx.error());
  TlsClientConfig config(*ctx);
  if (auto alpn = detail::ApplyAlpn(config.ctx_, detail::kDefaultAlpn); !alpn) return std::unexpected(alpn.error());
  *ctx = nullptr;
  return config;
}

inline Result<void> TlsClientConfig::SetCaCertPem(std::string_view pem) noexcept {
  if (ctx_ == nullptr) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
  return detail::AddPemTrust(ctx_, pem);
}

inline Result<void> TlsClientConfig::SetClientIdentityPem(std::string_view cert_pem, std::string_view key_pem) noexcept {
  if (ctx_ == nullptr) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
  return detail::UsePemIdentity(ctx_, cert_pem, key_pem);
}

inline Result<void> TlsClientConfig::SetAlpn(std::span<const AlpnProtocol> protos) noexcept {
  if (ctx_ == nullptr) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
  return detail::ApplyAlpn(ctx_, protos);
}

inline Result<TlsServerConfig> TlsServerConfig::FromPem(std::string_view cert_pem, std::string_view key_pem) noexcept {
  auto ctx = detail::MakeCtx(detail::VerifyMode::kNone);
  if (!ctx) return std::unexpected(ctx.error());
  TlsServerConfig config(*ctx);
  if (auto identity = detail::UsePemIdentity(config.ctx_, cert_pem, key_pem); !identity) {
    return std::unexpected(identity.error());
  }
  *ctx = nullptr;
  return config;
}

inline Result<TlsServerConfig> TlsServerConfig::FromPemWithClientAuth(std::string_view cert_pem, std::string_view key_pem,
                                                                      std::string_view client_ca_pem) noexcept {
  auto ctx = detail::MakeCtx(detail::VerifyMode::kPeerRequired);
  if (!ctx) return std::unexpected(ctx.error());
  TlsServerConfig config(*ctx);
  if (auto trust = detail::AddPemTrust(config.ctx_, client_ca_pem); !trust) return std::unexpected(trust.error());
  if (auto identity = detail::UsePemIdentity(config.ctx_, cert_pem, key_pem); !identity) {
    return std::unexpected(identity.error());
  }
  *ctx = nullptr;
  return config;
}

inline Result<TlsServerConfig> TlsServerConfig::SelfSignedForLocalhost() noexcept {
  auto ctx = detail::MakeCtx(detail::VerifyMode::kNone);
  if (!ctx) return std::unexpected(ctx.error());
  TlsServerConfig config(*ctx);
  if (auto identity = detail::InstallLocalhost(config.ctx_); !identity) return std::unexpected(identity.error());
  *ctx = nullptr;
  return config;
}

inline Result<void> TlsServerConfig::SetAlpn(std::span<const AlpnProtocol> protos) noexcept {
  if (ctx_ == nullptr) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
  return detail::ApplyAlpn(ctx_, protos);
}

inline Result<void> TlsClientConfig::SetCaCertFile(std::string_view path) noexcept {
  if (ctx_ == nullptr) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
  auto pem = detail::ReadPemFile(path);
  if (!pem) return std::unexpected(pem.error());
  return SetCaCertPem(*pem);
}

inline Result<void> TlsClientConfig::SetClientIdentityFiles(std::string_view cert_path, std::string_view key_path) noexcept {
  if (ctx_ == nullptr) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
  auto cert = detail::ReadPemFile(cert_path);
  if (!cert) return std::unexpected(cert.error());
  auto key = detail::ReadPemFile(key_path);
  if (!key) return std::unexpected(key.error());
  const detail::PemKeyCleanser cleanse{std::span{key->data(), key->size()}};
  return SetClientIdentityPem(*cert, *key);
}

inline Result<void> TlsClientConfig::SetRequiredAlpn(AlpnProtocol required) noexcept {
  if (ctx_ == nullptr) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
  if (required == AlpnProtocol::kNone) {
    required_alpn_ = AlpnProtocol::kNone;
    return {};
  }
  const std::array<AlpnProtocol, 1> one = {required};
  if (auto applied = detail::ApplyAlpn(ctx_, one); !applied) return applied;
  required_alpn_ = required;
  return {};
}

inline Result<TlsServerConfig> TlsServerConfig::FromPemFiles(std::string_view cert_path, std::string_view key_path) noexcept {
  auto cert = detail::ReadPemFile(cert_path);
  if (!cert) return std::unexpected(cert.error());
  auto key = detail::ReadPemFile(key_path);
  if (!key) return std::unexpected(key.error());
  const detail::PemKeyCleanser cleanse{std::span{key->data(), key->size()}};
  return FromPem(*cert, *key);
}

inline Result<TlsServerConfig> TlsServerConfig::FromPemFilesWithClientAuth(std::string_view cert_path,
                                                                           std::string_view key_path,
                                                                           std::string_view client_ca_path) noexcept {
  auto cert = detail::ReadPemFile(cert_path);
  if (!cert) return std::unexpected(cert.error());
  auto key = detail::ReadPemFile(key_path);
  if (!key) return std::unexpected(key.error());
  const detail::PemKeyCleanser cleanse{std::span{key->data(), key->size()}};
  auto client_ca = detail::ReadPemFile(client_ca_path);
  if (!client_ca) return std::unexpected(client_ca.error());
  return FromPemWithClientAuth(*cert, *key, *client_ca);
}

inline Result<void> TlsServerConfig::SetRequiredAlpn(AlpnProtocol required) noexcept {
  if (ctx_ == nullptr) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kInvalidState));
  if (required == AlpnProtocol::kNone) {
    required_alpn_ = AlpnProtocol::kNone;
    return {};
  }
  const std::array<AlpnProtocol, 1> one = {required};
  if (auto applied = detail::ApplyAlpn(ctx_, one); !applied) return applied;
  required_alpn_ = required;
  return {};
}

}  // namespace nexora
