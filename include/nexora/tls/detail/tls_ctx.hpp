#pragma once

#include <fcntl.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <uarch/uarch.hpp>
#include <utility>

#include "nexora/error/proto_error.hpp"
#include "nexora/tls/tls_types.hpp"

namespace nexora::detail {

/// Wire ALPN list stored in SSL_CTX extra data so it outlives the config object.
struct AlpnWire {
  std::array<std::uint8_t, 48> bytes{};
  std::uint8_t len{0};
};

enum class VerifyMode : std::uint8_t { kNone = 0, kPeer, kPeerRequired, kInsecure };

struct BioDel {
  void operator()(BIO* bio) const noexcept {
    if (bio != nullptr) BIO_free(bio);
  }
};
struct X509Del {
  void operator()(X509* cert) const noexcept {
    if (cert != nullptr) X509_free(cert);
  }
};
struct PkeyDel {
  void operator()(EVP_PKEY* key) const noexcept {
    if (key != nullptr) EVP_PKEY_free(key);
  }
};
struct PkeyCtxDel {
  void operator()(EVP_PKEY_CTX* ctx) const noexcept {
    if (ctx != nullptr) EVP_PKEY_CTX_free(ctx);
  }
};

using BioPtr = std::unique_ptr<BIO, BioDel>;
using X509Ptr = std::unique_ptr<X509, X509Del>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDel>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDel>;

[[nodiscard]] inline Error ConfigError() noexcept { return Error::FromProto(ProtoErrorCode::kTlsConfigError); }

inline void FreeAlpn(void* /*parent*/, void* ptr, CRYPTO_EX_DATA* /*ad*/, int /*index*/, long /*argl*/, void* /*argp*/) {
  OPENSSL_free(ptr);
}

[[nodiscard]] inline int AlpnIndex() noexcept {
  static const int index = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, &FreeAlpn);
  return index;
}

[[nodiscard]] inline AlpnWire* AlpnOf(const SSL_CTX* ctx) noexcept {
  return static_cast<AlpnWire*>(SSL_CTX_get_ex_data(ctx, AlpnIndex()));
}

/// X.509 verdict only. CertificateVerify is still enforced by the TLS 1.3 stack.
extern "C" inline ssl_verify_result_t AcceptCertificate(SSL* /*ssl*/, std::uint8_t* /*alert*/) { return ssl_verify_ok; }

extern "C" inline int SelectAlpn(SSL* ssl, const std::uint8_t** out, std::uint8_t* out_len, const std::uint8_t* in,
                                 unsigned in_len, void* /*arg*/) {
  const AlpnWire* pref = AlpnOf(SSL_get_SSL_CTX(ssl));
  if (pref == nullptr || pref->len == 0) return SSL_TLSEXT_ERR_NOACK;
  std::size_t pref_off = 0;
  while (pref_off < pref->len) {
    const auto pref_len = static_cast<std::size_t>(pref->bytes[pref_off]);
    if (pref_len == 0 || pref_off + 1 + pref_len > pref->len) return SSL_TLSEXT_ERR_ALERT_FATAL;
    const std::uint8_t* pref_bytes = pref->bytes.data() + pref_off + 1;
    std::size_t offer_off = 0;
    while (offer_off < in_len) {
      const auto offer_len = static_cast<std::size_t>(in[offer_off]);
      if (offer_len == 0 || offer_off + 1 + offer_len > in_len) return SSL_TLSEXT_ERR_ALERT_FATAL;
      if (offer_len == pref_len && std::memcmp(in + offer_off + 1, pref_bytes, pref_len) == 0) {
        *out = in + offer_off + 1;
        *out_len = static_cast<std::uint8_t>(offer_len);
        return SSL_TLSEXT_ERR_OK;
      }
      offer_off += 1 + offer_len;
    }
    pref_off += 1 + pref_len;
  }
  return SSL_TLSEXT_ERR_ALERT_FATAL;
}

[[nodiscard]] inline Result<SSL_CTX*> MakeCtx(VerifyMode mode) noexcept {
  SSL_CTX* ctx = SSL_CTX_new(TLS_method());
  if (uarch::unlikely(ctx == nullptr)) {
    ERR_clear_error();
    return std::unexpected(ConfigError());
  }
  const auto release = [ctx]() noexcept {
    ERR_clear_error();
    SSL_CTX_free(ctx);
  };
  if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 || SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1) {
    release();
    return std::unexpected(ConfigError());
  }
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_options(ctx, static_cast<std::uint32_t>(SSL_OP_NO_TICKET));
  if (SSL_CTX_set_num_tickets(ctx, 0) != 1) {
    release();
    return std::unexpected(ConfigError());
  }
  SSL_CTX_set_mode(ctx, static_cast<std::uint32_t>(SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER));
  void* memory = OPENSSL_malloc(sizeof(AlpnWire));
  if (uarch::unlikely(memory == nullptr)) {
    release();
    return std::unexpected(ConfigError());
  }
  auto* wire = static_cast<AlpnWire*>(memory);
  wire->len = 0;
  wire->bytes.fill(0);
  if (SSL_CTX_set_ex_data(ctx, AlpnIndex(), wire) != 1) {
    OPENSSL_free(wire);
    release();
    return std::unexpected(ConfigError());
  }
  SSL_CTX_set_alpn_select_cb(ctx, &SelectAlpn, nullptr);
  if (mode == VerifyMode::kInsecure) {
    SSL_CTX_set_custom_verify(ctx, SSL_VERIFY_PEER, &AcceptCertificate);
  } else if (mode == VerifyMode::kPeer) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
  } else if (mode == VerifyMode::kPeerRequired) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
  }
  ERR_clear_error();
  return ctx;
}

[[nodiscard]] inline Result<AlpnWire> EncodeAlpn(std::span<const AlpnProtocol> protos) noexcept {
  AlpnWire wire{};
  std::uint8_t len = 0;
  std::array<std::uint8_t, 48> bytes{};
  for (const AlpnProtocol proto : protos) {
    const char* text = nullptr;
    std::uint8_t text_len = 0;
    switch (proto) {
      case AlpnProtocol::kNone:
        return std::unexpected(Error::FromProto(ProtoErrorCode::kInvalidArgument));
      case AlpnProtocol::kHttp11:
        text = "http/1.1";
        text_len = 8;
        break;
      case AlpnProtocol::kHttp2:
        text = "h2";
        text_len = 2;
        break;
    }
    if (static_cast<std::size_t>(len) + 1 + text_len > bytes.size()) return std::unexpected(ConfigError());
    bytes[len] = text_len;
    std::memcpy(bytes.data() + len + 1, text, text_len);
    len = static_cast<std::uint8_t>(len + 1 + text_len);
  }
  if (len != 0) std::memcpy(wire.bytes.data(), bytes.data(), len);
  wire.len = len;
  return wire;
}

[[nodiscard]] inline Result<void> ApplyAlpn(SSL_CTX* ctx, std::span<const AlpnProtocol> protos) noexcept {
  AlpnWire* wire = AlpnOf(ctx);
  if (uarch::unlikely(wire == nullptr)) return std::unexpected(ConfigError());
  auto encoded = EncodeAlpn(protos);
  if (!encoded) return std::unexpected(encoded.error());
  *wire = *encoded;
  return {};
}

[[nodiscard]] inline BioPtr MemBio(std::string_view pem) noexcept {
  if (pem.size() > static_cast<std::size_t>(INT32_MAX)) return {};
  return BioPtr(BIO_new_mem_buf(pem.data(), static_cast<ossl_ssize_t>(pem.size())));
}

[[nodiscard]] inline Result<void> AddPemTrust(SSL_CTX* ctx, std::string_view pem) noexcept {
  BioPtr bio = MemBio(pem);
  X509_STORE* store = SSL_CTX_get_cert_store(ctx);
  if (uarch::unlikely(!bio || store == nullptr)) {
    ERR_clear_error();
    return std::unexpected(ConfigError());
  }
  // Explicit PEM anchors may be a single leaf. The system bundle stays a root store.
  if (X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN) != 1) {
    ERR_clear_error();
    return std::unexpected(ConfigError());
  }
  int added = 0;
  for (;;) {
    X509Ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (!cert) break;
    if (X509_STORE_add_cert(store, cert.get()) != 1) {
      ERR_clear_error();
      return std::unexpected(ConfigError());
    }
    ++added;
  }
  ERR_clear_error();
  if (added == 0) return std::unexpected(ConfigError());
  return {};
}

[[nodiscard]] inline Result<void> UsePemIdentity(SSL_CTX* ctx, std::string_view cert_pem, std::string_view key_pem) noexcept {
  BioPtr cert_bio = MemBio(cert_pem);
  BioPtr key_bio = MemBio(key_pem);
  if (uarch::unlikely(!cert_bio || !key_bio)) {
    ERR_clear_error();
    return std::unexpected(ConfigError());
  }
  X509Ptr leaf(PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
  if (!leaf) {
    ERR_clear_error();
    return std::unexpected(ConfigError());
  }
  if (SSL_CTX_use_certificate(ctx, leaf.get()) != 1) {
    ERR_clear_error();
    return std::unexpected(ConfigError());
  }
  for (;;) {
    X509Ptr extra(PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
    if (!extra) break;
    if (SSL_CTX_add1_chain_cert(ctx, extra.get()) != 1) {
      ERR_clear_error();
      return std::unexpected(ConfigError());
    }
  }
  ERR_clear_error();
  PkeyPtr key(PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr));
  if (!key || SSL_CTX_use_PrivateKey(ctx, key.get()) != 1 || SSL_CTX_check_private_key(ctx) != 1) {
    ERR_clear_error();
    return std::unexpected(ConfigError());
  }
  return {};
}

[[nodiscard]] inline bool AddExt(X509* cert, int nid, const char* value) noexcept {
  X509_EXTENSION* extension = X509V3_EXT_nconf_nid(nullptr, nullptr, nid, value);
  if (extension == nullptr) return false;
  const int added = X509_add_ext(cert, extension, -1);
  X509_EXTENSION_free(extension);
  return added == 1;
}

[[nodiscard]] inline Result<void> InstallLocalhost(SSL_CTX* ctx) noexcept {
  PkeyCtxPtr params(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
  if (!params || EVP_PKEY_keygen_init(params.get()) != 1 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(params.get(), NID_X9_62_prime256v1) != 1) {
    return std::unexpected(ConfigError());
  }
  EVP_PKEY* raw_key = nullptr;
  if (EVP_PKEY_keygen(params.get(), &raw_key) != 1) return std::unexpected(ConfigError());
  PkeyPtr key(raw_key);
  X509Ptr cert(X509_new());
  if (!cert) return std::unexpected(ConfigError());
  std::array<unsigned char, 4> serial_bytes{};
  if (RAND_bytes(serial_bytes.data(), serial_bytes.size()) != 1) return std::unexpected(ConfigError());
  const long serial =
      static_cast<long>((static_cast<unsigned>(serial_bytes[0]) << 24 | static_cast<unsigned>(serial_bytes[1]) << 16 |
                         static_cast<unsigned>(serial_bytes[2]) << 8 | static_cast<unsigned>(serial_bytes[3])) &
                        0x7fffffffu) |
      1L;
  X509* raw = cert.get();
  if (X509_set_version(raw, 2) != 1 || ASN1_INTEGER_set(X509_get_serialNumber(raw), serial) != 1 ||
      X509_gmtime_adj(X509_getm_notBefore(raw), -60) == nullptr ||
      X509_gmtime_adj(X509_getm_notAfter(raw), 31536000L) == nullptr || X509_set_pubkey(raw, key.get()) != 1) {
    return std::unexpected(ConfigError());
  }
  X509_NAME* name = X509_get_subject_name(raw);
  if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0) !=
          1 ||
      X509_set_issuer_name(raw, name) != 1) {
    return std::unexpected(ConfigError());
  }
  if (!AddExt(raw, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1,IP:::1") ||
      !AddExt(raw, NID_basic_constraints, "critical,CA:FALSE") || !AddExt(raw, NID_key_usage, "critical,digitalSignature") ||
      !AddExt(raw, NID_ext_key_usage, "serverAuth") || X509_sign(raw, key.get(), EVP_sha256()) <= 0) {
    return std::unexpected(ConfigError());
  }
  if (SSL_CTX_use_certificate(ctx, raw) != 1 || SSL_CTX_use_PrivateKey(ctx, key.get()) != 1 ||
      SSL_CTX_check_private_key(ctx) != 1) {
    return std::unexpected(ConfigError());
  }
  return {};
}

[[nodiscard]] inline Result<void> LoadHostRoots(SSL_CTX* ctx) noexcept {
  bool loaded = SSL_CTX_set_default_verify_paths(ctx) == 1;
  for (const char* path : {"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"}) {
    if (::access(path, R_OK) != 0) continue;
    loaded = SSL_CTX_load_verify_locations(ctx, path, nullptr) == 1 || loaded;
  }
  ERR_clear_error();
  if (!loaded) return std::unexpected(ConfigError());
  return {};
}

inline constexpr std::array<AlpnProtocol, 2> kDefaultAlpn = {AlpnProtocol::kHttp2, AlpnProtocol::kHttp11};

inline constexpr std::size_t kPemFileMax = 262144;

struct PemKeyCleanser {
  std::span<char> key_pem;
  ~PemKeyCleanser() { OPENSSL_cleanse(key_pem.data(), key_pem.size()); }
};

/// PEM identities stay bounded so a huge path cannot force an unbounded allocation.
[[nodiscard]] inline Result<std::string> ReadPemFile(std::string_view path) noexcept {
  if (path.empty() || path.size() >= 4096 || path.find('\0') != std::string_view::npos) {
    return std::unexpected(Error::InvalidArgument());
  }
  std::array<char, 4096> name{};
  std::memcpy(name.data(), path.data(), path.size());
  const int fd = ::open(name.data(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return std::unexpected(Error::FromErrno(errno));
  struct stat st{};
  if (::fstat(fd, &st) != 0) {
    const int err = errno;
    ::close(fd);
    return std::unexpected(Error::FromErrno(err));
  }
  if (st.st_size <= 0) {
    ::close(fd);
    return std::unexpected(ConfigError());
  }
  if (static_cast<std::uint64_t>(st.st_size) > kPemFileMax) {
    ::close(fd);
    return std::unexpected(Error::BufferOverflow());
  }
  std::string pem(static_cast<std::size_t>(st.st_size), '\0');
  std::size_t got = 0;
  while (got < pem.size()) {
    const ssize_t n = ::read(fd, pem.data() + got, pem.size() - got);
    if (n < 0) {
      if (errno == EINTR) continue;
      const int err = errno;
      ::close(fd);
      return std::unexpected(Error::FromErrno(err));
    }
    if (n == 0) break;
    got += static_cast<std::size_t>(n);
  }
  ::close(fd);
  if (got == 0) return std::unexpected(ConfigError());
  if (got != pem.size()) pem.resize(got);
  return pem;
}

}  // namespace nexora::detail
