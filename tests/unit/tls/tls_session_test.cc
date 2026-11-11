#include "nexora/tls/tls_session.hpp"

#include <fcntl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <source_location>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

int g_failed = 0;

void Check(bool ok, const std::source_location where = std::source_location::current()) {
  if (ok) return;
  std::fprintf(stderr, "FAIL %s:%u\n", where.file_name(), static_cast<unsigned>(where.line()));
  ++g_failed;
}

struct Identity {
  std::string cert_pem;
  std::string key_pem;
};

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

std::string BioText(BIO* bio) {
  BUF_MEM* mem = nullptr;
  BIO_get_mem_ptr(bio, &mem);
  if (mem == nullptr || mem->data == nullptr) return {};
  return {mem->data, mem->length};
}

bool AddExt(X509* cert, int nid, const char* value) {
  X509_EXTENSION* extension = X509V3_EXT_nconf_nid(nullptr, nullptr, nid, value);
  if (extension == nullptr) return false;
  const int added = X509_add_ext(cert, extension, -1);
  X509_EXTENSION_free(extension);
  return added == 1;
}

Identity Mint(const char* common_name, const char* san) {
  Identity out;
  EVP_PKEY_CTX* params = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  if (params == nullptr || EVP_PKEY_keygen_init(params) != 1 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(params, NID_X9_62_prime256v1) != 1) {
    EVP_PKEY_CTX_free(params);
    return out;
  }
  EVP_PKEY* raw_key = nullptr;
  if (EVP_PKEY_keygen(params, &raw_key) != 1) {
    EVP_PKEY_CTX_free(params);
    return out;
  }
  EVP_PKEY_CTX_free(params);
  std::unique_ptr<EVP_PKEY, PkeyDel> key(raw_key);
  std::unique_ptr<X509, X509Del> cert(X509_new());
  if (!cert) return out;
  X509* raw = cert.get();
  if (X509_set_version(raw, 2) != 1 || ASN1_INTEGER_set(X509_get_serialNumber(raw), 7) != 1 ||
      X509_gmtime_adj(X509_getm_notBefore(raw), -60) == nullptr ||
      X509_gmtime_adj(X509_getm_notAfter(raw), 31536000L) == nullptr || X509_set_pubkey(raw, key.get()) != 1) {
    return out;
  }
  X509_NAME* name = X509_get_subject_name(raw);
  if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(common_name), -1, -1, 0) !=
          1 ||
      X509_set_issuer_name(raw, name) != 1 || !AddExt(raw, NID_subject_alt_name, san) ||
      !AddExt(raw, NID_basic_constraints, "critical,CA:FALSE") || !AddExt(raw, NID_key_usage, "critical,digitalSignature") ||
      !AddExt(raw, NID_ext_key_usage, "serverAuth,clientAuth") || X509_sign(raw, key.get(), EVP_sha256()) <= 0) {
    return out;
  }
  std::unique_ptr<BIO, BioDel> cert_bio(BIO_new(BIO_s_mem()));
  std::unique_ptr<BIO, BioDel> key_bio(BIO_new(BIO_s_mem()));
  if (!cert_bio || !key_bio || PEM_write_bio_X509(cert_bio.get(), raw) != 1 ||
      PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
    return out;
  }
  out.cert_pem = BioText(cert_bio.get());
  out.key_pem = BioText(key_bio.get());
  return out;
}

using Session = nexora::TlsSession;

nexora::Result<void> Transfer(Session& src, Session& dst, std::size_t fragment) {
  std::array<std::uint8_t, 32768> buf{};
  for (;;) {
    auto taken = src.TakeCiphertext(buf);
    if (!taken) return std::unexpected(taken.error());
    if (*taken == 0) return {};
    std::size_t off = 0;
    while (off < *taken) {
      const std::size_t chunk = std::min(fragment, *taken - off);
      auto fed = dst.FeedCiphertext(std::span<const std::uint8_t>(buf.data() + off, chunk));
      if (!fed) return std::unexpected(fed.error());
      if (*fed != chunk) return std::unexpected(nexora::Error::FromProto(nexora::ProtoErrorCode::kTlsIoError));
      off += chunk;
    }
  }
}

nexora::Result<void> Pump(Session& client, Session& server, std::size_t fragment) {
  for (int round = 0; round < 48; ++round) {
    if (auto sent = Transfer(client, server, fragment); !sent) return sent;
    if (auto sent = Transfer(server, client, fragment); !sent) return sent;
    if (client.IsHandshakeComplete() && server.IsHandshakeComplete() && !client.HasPendingCiphertextOut() &&
        !server.HasPendingCiphertextOut()) {
      return {};
    }
  }
  if (client.IsHandshakeComplete() && server.IsHandshakeComplete()) return {};
  return std::unexpected(nexora::Error::FromProto(nexora::ProtoErrorCode::kTlsHandshakeFailed));
}

nexora::Result<std::vector<std::uint8_t>> ReadAll(Session& session, std::size_t expect) {
  std::vector<std::uint8_t> out(expect);
  std::size_t got = 0;
  for (int spin = 0; spin < 8 && got < expect; ++spin) {
    auto read = session.ReadPlaintext(std::span<std::uint8_t>(out.data() + got, expect - got));
    if (!read) return std::unexpected(read.error());
    if (*read == 0) break;
    got += *read;
  }
  if (got != expect) return std::unexpected(nexora::Error::FromProto(nexora::ProtoErrorCode::kTlsIoError));
  return out;
}

void Exchange(Session& client, Session& server, std::span<const std::uint8_t> payload, std::size_t fragment) {
  std::size_t off = 0;
  while (off < payload.size()) {
    auto wrote = client.WritePlaintext(payload.subspan(off));
    Check(wrote.has_value());
    if (!wrote || *wrote == 0) return;
    off += *wrote;
    Check(Pump(client, server, fragment).has_value());
  }
  auto got = ReadAll(server, payload.size());
  Check(got.has_value());
  if (got) Check(std::memcmp(got->data(), payload.data(), payload.size()) == 0);
}

void HandshakeFragmented() {
  auto server_cfg = nexora::TlsServerConfig::SelfSignedForLocalhost();
  auto client_cfg = nexora::TlsClientConfig::CreateInsecureForTest();
  Check(server_cfg.has_value() && client_cfg.has_value());
  if (!server_cfg || !client_cfg) return;
  constexpr std::array<nexora::AlpnProtocol, 1> alpn{nexora::AlpnProtocol::kHttp11};
  Check(server_cfg->SetAlpn(alpn).has_value());
  Check(client_cfg->SetAlpn(alpn).has_value());
  auto client = Session::CreateClient(*client_cfg, "localhost");
  auto server = Session::CreateServer(*server_cfg);
  Check(client.has_value() && server.has_value());
  if (!client || !server) return;
  Check(Pump(*client, *server, 1).has_value());
  Check(client->IsHandshakeComplete() && server->IsHandshakeComplete());
  Check(client->NegotiatedAlpn() == nexora::AlpnProtocol::kHttp11);
  constexpr std::array<std::uint8_t, 6> payload{1, 2, 3, 4, 5, 9};
  Exchange(*client, *server, payload, 1);
}

void HandshakeCoalesced() {
  const Identity id = Mint("localhost", "DNS:localhost,IP:127.0.0.1");
  Check(!id.cert_pem.empty());
  auto server_cfg = nexora::TlsServerConfig::FromPem(id.cert_pem, id.key_pem);
  auto client_cfg = nexora::TlsClientConfig::CreateInsecureForTest();
  Check(server_cfg && client_cfg);
  if (!server_cfg || !client_cfg) return;
  constexpr std::array<nexora::AlpnProtocol, 2> alpn{nexora::AlpnProtocol::kHttp2, nexora::AlpnProtocol::kHttp11};
  Check(server_cfg->SetAlpn(alpn).has_value());
  auto client = Session::CreateClient(*client_cfg, "localhost");
  auto server = Session::CreateServer(*server_cfg);
  Check(client && server);
  if (!client || !server) return;
  Check(Pump(*client, *server, 4096).has_value());
  Check(client->NegotiatedAlpn() == nexora::AlpnProtocol::kHttp2);
  std::vector<std::uint8_t> payload(20000);
  for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::uint8_t>(i % 251);
  Exchange(*client, *server, payload, payload.size());
}

void MutualAuth() {
  const Identity server_id = Mint("localhost", "DNS:localhost");
  const Identity client_id = Mint("client", "DNS:client.local");
  Check(!server_id.cert_pem.empty() && !client_id.cert_pem.empty());
  auto server_cfg = nexora::TlsServerConfig::FromPemWithClientAuth(server_id.cert_pem, server_id.key_pem, client_id.cert_pem);
  auto client_cfg = nexora::TlsClientConfig::CreateInsecureForTest();
  Check(server_cfg && client_cfg);
  if (!server_cfg || !client_cfg) return;
  Check(client_cfg->SetCaCertPem(server_id.cert_pem).has_value());
  Check(client_cfg->SetClientIdentityPem(client_id.cert_pem, client_id.key_pem).has_value());
  auto client = Session::CreateClient(*client_cfg, "localhost");
  auto server = Session::CreateServer(*server_cfg);
  Check(client && server);
  if (!client || !server) return;
  Check(Pump(*client, *server, 64).has_value());
  Check(client->IsHandshakeComplete() && server->IsHandshakeComplete());

  auto bare = nexora::TlsClientConfig::CreateInsecureForTest();
  Check(bare.has_value());
  if (!bare) return;
  auto rejected = Session::CreateClient(*bare, "localhost");
  auto server2 = Session::CreateServer(*server_cfg);
  Check(rejected && server2);
  if (!rejected || !server2) return;
  auto pumped = Pump(*rejected, *server2, 128);
  Check(!pumped.has_value());
}

void AlpnSelection() {
  const Identity id = Mint("localhost", "DNS:localhost");
  auto prefer = [&](nexora::AlpnProtocol server_proto, nexora::AlpnProtocol expect) {
    auto server_cfg = nexora::TlsServerConfig::FromPem(id.cert_pem, id.key_pem);
    auto client_cfg = nexora::TlsClientConfig::CreateInsecureForTest();
    Check(server_cfg && client_cfg);
    if (!server_cfg || !client_cfg) return;
    const std::array<nexora::AlpnProtocol, 1> server_list{server_proto};
    Check(server_cfg->SetAlpn(server_list).has_value());
    auto client = Session::CreateClient(*client_cfg, "localhost");
    auto server = Session::CreateServer(*server_cfg);
    Check(client && server);
    if (!client || !server) return;
    Check(Pump(*client, *server, 200).has_value());
    Check(client->NegotiatedAlpn() == expect);
    Check(server->NegotiatedAlpn() == expect);
  };
  prefer(nexora::AlpnProtocol::kHttp2, nexora::AlpnProtocol::kHttp2);
  prefer(nexora::AlpnProtocol::kHttp11, nexora::AlpnProtocol::kHttp11);

  auto server_cfg = nexora::TlsServerConfig::FromPem(id.cert_pem, id.key_pem);
  auto client_cfg = nexora::TlsClientConfig::CreateInsecureForTest();
  Check(server_cfg && client_cfg);
  if (!server_cfg || !client_cfg) return;
  constexpr std::array<nexora::AlpnProtocol, 1> server_only{nexora::AlpnProtocol::kHttp11};
  constexpr std::array<nexora::AlpnProtocol, 1> client_only{nexora::AlpnProtocol::kHttp2};
  Check(server_cfg->SetAlpn(server_only).has_value());
  Check(client_cfg->SetAlpn(client_only).has_value());
  auto client = Session::CreateClient(*client_cfg, "localhost");
  auto server = Session::CreateServer(*server_cfg);
  Check(client && server);
  if (!client || !server) return;
  Check(!Pump(*client, *server, 50).has_value());
}

void CloseNotifyDrains() {
  auto server_cfg = nexora::TlsServerConfig::SelfSignedForLocalhost();
  auto client_cfg = nexora::TlsClientConfig::CreateInsecureForTest();
  Check(server_cfg && client_cfg);
  if (!server_cfg || !client_cfg) return;
  auto client = Session::CreateClient(*client_cfg, "localhost.");
  auto server = Session::CreateServer(*server_cfg);
  Check(client && server);
  if (!client || !server) return;
  Check(Pump(*client, *server, 7).has_value());
  Check(!server->IsPeerClosed());
  constexpr std::array<std::uint8_t, 4> payload{'p', 'i', 'n', 'g'};
  Exchange(*client, *server, payload, 3);
  Check(!server->IsPeerClosed());
  Check(client->SendCloseNotify().has_value());
  Check(client->SendCloseNotify().has_value());
  auto again = client->WritePlaintext(payload);
  Check(!again && again.error() == nexora::Error::FromProto(nexora::ProtoErrorCode::kTlsClosed));
  Check(Pump(*client, *server, 5).has_value());
  std::array<std::uint8_t, 8> extra{};
  auto drained = server->ReadPlaintext(extra);
  Check(drained && *drained == 0);
  Check(server->SendCloseNotify().has_value());
  Check(Pump(*client, *server, 5).has_value());
  auto client_eof = client->ReadPlaintext(extra);
  Check(client_eof && *client_eof == 0);
  Check(server->IsPeerClosed() && client->IsPeerClosed());
}

void RejectUntrustedAndName() {
  const Identity server_id = Mint("localhost", "DNS:localhost,IP:127.0.0.1");
  const Identity other = Mint("other", "DNS:other.example");
  Check(!server_id.cert_pem.empty() && !other.cert_pem.empty());
  auto server_cfg = nexora::TlsServerConfig::FromPem(server_id.cert_pem, server_id.key_pem);
  auto untrusted = nexora::TlsClientConfig::CreateDefault();
  Check(server_cfg && untrusted);
  if (!server_cfg || !untrusted) return;
  Check(untrusted->SetCaCertPem(other.cert_pem).has_value());
  Check(untrusted->SetAlpn({}).has_value());
  auto bad_client = Session::CreateClient(*untrusted, "localhost");
  auto server = Session::CreateServer(*server_cfg);
  Check(bad_client && server);
  if (!bad_client || !server) return;
  auto untrusted_pump = Pump(*bad_client, *server, 90);
  Check(!untrusted_pump);
  if (!untrusted_pump) {
    Check(untrusted_pump.error() == nexora::Error::FromProto(nexora::ProtoErrorCode::kTlsVerifyFailed));
  }

  auto trusted = nexora::TlsClientConfig::CreateDefault();
  Check(trusted.has_value());
  if (!trusted) return;
  Check(trusted->SetCaCertPem(server_id.cert_pem).has_value());
  Check(trusted->SetAlpn({}).has_value());
  auto mismatch = Session::CreateClient(*trusted, "wrong.example");
  auto server_b = Session::CreateServer(*server_cfg);
  Check(mismatch && server_b);
  if (!mismatch || !server_b) return;
  auto mismatch_pump = Pump(*mismatch, *server_b, 40);
  Check(!mismatch_pump);
  if (!mismatch_pump) {
    Check(mismatch_pump.error() == nexora::Error::FromProto(nexora::ProtoErrorCode::kTlsVerifyFailed));
  }

  auto ip_client = Session::CreateClient(*trusted, "127.0.0.1");
  auto server_c = Session::CreateServer(*server_cfg);
  Check(ip_client && server_c);
  if (!ip_client || !server_c) return;
  Check(Pump(*ip_client, *server_c, 33).has_value());
  Check(ip_client->IsHandshakeComplete());

  auto bad_name = Session::CreateClient(*trusted, "bad..name");
  Check(!bad_name);
  if (!bad_name) Check(bad_name.error() == nexora::Error::FromProto(nexora::ProtoErrorCode::kInvalidArgument));
  auto empty_pem = nexora::TlsServerConfig::FromPem("", "");
  Check(!empty_pem);
}

struct PemScratch {
  std::string dir;
  ~PemScratch() {
    if (dir.empty()) return;
    ::unlink((dir + "/cert.pem").c_str());
    ::unlink((dir + "/key.pem").c_str());
    ::unlink((dir + "/ca.pem").c_str());
    ::rmdir(dir.c_str());
  }
};

bool WriteNew(const std::string& path, std::string_view bytes) {
  const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0) return false;
  std::size_t off = 0;
  while (off < bytes.size()) {
    const ssize_t n = ::write(fd, bytes.data() + off, bytes.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      ::close(fd);
      return false;
    }
    off += static_cast<std::size_t>(n);
  }
  return ::close(fd) == 0;
}

void PemFilesLoad() {
  const Identity id = Mint("localhost", "DNS:localhost,IP:127.0.0.1");
  Check(!id.cert_pem.empty() && !id.key_pem.empty());
  const char* env = std::getenv("TMPDIR");
  std::string root = (env != nullptr && env[0] != '\0') ? std::string(env) : std::string("tmp");
  if (::mkdir(root.c_str(), 0700) != 0 && errno != EEXIST) {
    Check(false);
    return;
  }
  if (!root.empty() && root.back() != '/') root.push_back('/');
  std::string pattern = root + "nexora-pem-XXXXXX";
  std::vector<char> tmpl(pattern.begin(), pattern.end());
  tmpl.push_back('\0');
  if (::mkdtemp(tmpl.data()) == nullptr) {
    Check(false);
    return;
  }
  PemScratch scratch;
  scratch.dir = tmpl.data();
  auto missing = nexora::TlsServerConfig::FromPemFiles(scratch.dir + "/missing.pem", scratch.dir + "/key.pem");
  Check(!missing);
  Check(WriteNew(scratch.dir + "/cert.pem", id.cert_pem));
  Check(WriteNew(scratch.dir + "/key.pem", id.key_pem));
  Check(WriteNew(scratch.dir + "/ca.pem", id.cert_pem));

  auto server_cfg = nexora::TlsServerConfig::FromPemFiles(scratch.dir + "/cert.pem", scratch.dir + "/key.pem");
  auto client_cfg = nexora::TlsClientConfig::CreateDefault();
  Check(server_cfg && client_cfg);
  if (!server_cfg || !client_cfg) return;
  Check(client_cfg->SetCaCertFile(scratch.dir + "/ca.pem").has_value());
  auto client = Session::CreateClient(*client_cfg, "localhost");
  auto server = Session::CreateServer(*server_cfg);
  Check(client && server);
  if (!client || !server) return;
  Check(Pump(*client, *server, 128).has_value());
  Check(client->IsHandshakeComplete() && server->IsHandshakeComplete());

  auto mutual = nexora::TlsServerConfig::FromPemFilesWithClientAuth(scratch.dir + "/cert.pem", scratch.dir + "/key.pem",
                                                                    scratch.dir + "/ca.pem");
  auto identified = nexora::TlsClientConfig::CreateInsecureForTest();
  Check(mutual && identified);
  if (!mutual || !identified) return;
  Check(identified->SetClientIdentityFiles(scratch.dir + "/cert.pem", scratch.dir + "/key.pem").has_value());
  auto authed = Session::CreateClient(*identified, "localhost");
  auto peer = Session::CreateServer(*mutual);
  Check(authed && peer);
  if (!authed || !peer) return;
  Check(Pump(*authed, *peer, 64).has_value());
}

void RequiredAlpnRejectsHttp11() {
  const Identity id = Mint("localhost", "DNS:localhost");
  Check(!id.cert_pem.empty());
  auto reject = [&](bool client_requires) {
    auto server_cfg = nexora::TlsServerConfig::FromPem(id.cert_pem, id.key_pem);
    auto client_cfg = nexora::TlsClientConfig::CreateInsecureForTest();
    Check(server_cfg && client_cfg);
    if (!server_cfg || !client_cfg) return;
    constexpr std::array<nexora::AlpnProtocol, 1> http11{nexora::AlpnProtocol::kHttp11};
    if (client_requires) {
      Check(server_cfg->SetAlpn(http11).has_value());
      Check(client_cfg->SetRequiredAlpn(nexora::AlpnProtocol::kHttp2).has_value());
    } else {
      Check(client_cfg->SetAlpn(http11).has_value());
      Check(server_cfg->SetRequiredAlpn(nexora::AlpnProtocol::kHttp2).has_value());
    }
    auto client = Session::CreateClient(*client_cfg, "localhost");
    auto server = Session::CreateServer(*server_cfg);
    Check(client && server);
    if (!client || !server) return;
    auto pumped = Pump(*client, *server, 80);
    Check(!pumped);
    if (!pumped) Check(pumped.error() == nexora::Error::FromProto(nexora::ProtoErrorCode::kTlsHandshakeFailed));
  };
  reject(true);
  reject(false);
}

void RequiredAlpnRejectsMissing() {
  for (const bool client_requires : {true, false}) {
    auto server_cfg = nexora::TlsServerConfig::SelfSignedForLocalhost();
    auto client_cfg = nexora::TlsClientConfig::CreateInsecureForTest();
    Check(server_cfg && client_cfg);
    if (!server_cfg || !client_cfg) return;
    if (client_requires) {
      Check(client_cfg->SetRequiredAlpn(nexora::AlpnProtocol::kHttp2).has_value());
      Check(server_cfg->SetAlpn({}).has_value());
    } else {
      Check(server_cfg->SetRequiredAlpn(nexora::AlpnProtocol::kHttp2).has_value());
      Check(client_cfg->SetAlpn({}).has_value());
    }
    auto client = Session::CreateClient(*client_cfg, "localhost");
    auto server = Session::CreateServer(*server_cfg);
    Check(client && server);
    if (!client || !server) return;
    const auto pumped = Pump(*client, *server, 80);
    const auto expected = nexora::Error::FromProto(nexora::ProtoErrorCode::kTlsHandshakeFailed);
    Check(!pumped && pumped.error() == expected);
    auto& requiring_peer = client_requires ? *client : *server;
    const auto completion = requiring_peer.DriveHandshake();
    Check(!completion && completion.error() == expected);
    Check(requiring_peer.NegotiatedAlpn() == nexora::AlpnProtocol::kNone);
  }
}

void RequiredAlpnMatchesAndClears() {
  auto server_cfg = nexora::TlsServerConfig::SelfSignedForLocalhost();
  auto client_cfg = nexora::TlsClientConfig::CreateInsecureForTest();
  Check(server_cfg && client_cfg);
  if (!server_cfg || !client_cfg) return;
  Check(server_cfg->SetRequiredAlpn(nexora::AlpnProtocol::kHttp2).has_value());
  Check(client_cfg->SetRequiredAlpn(nexora::AlpnProtocol::kHttp2).has_value());
  auto client = Session::CreateClient(*client_cfg, "localhost");
  auto server = Session::CreateServer(*server_cfg);
  Check(client && server);
  if (!client || !server) return;
  Check(Pump(*client, *server, 80).has_value());
  Check(client->IsHandshakeComplete() && server->IsHandshakeComplete());
  Check(client->NegotiatedAlpn() == nexora::AlpnProtocol::kHttp2);
  Check(server->NegotiatedAlpn() == nexora::AlpnProtocol::kHttp2);

  Check(client_cfg->SetRequiredAlpn(nexora::AlpnProtocol::kNone).has_value());
  Check(server_cfg->SetRequiredAlpn(nexora::AlpnProtocol::kNone).has_value());
  Check(client_cfg->SetAlpn({}).has_value());
  Check(server_cfg->SetAlpn({}).has_value());
  auto cleared_client = Session::CreateClient(*client_cfg, "localhost");
  auto cleared_server = Session::CreateServer(*server_cfg);
  Check(cleared_client && cleared_server);
  if (!cleared_client || !cleared_server) return;
  Check(Pump(*cleared_client, *cleared_server, 80).has_value());
  Check(cleared_client->IsHandshakeComplete() && cleared_server->IsHandshakeComplete());
  Check(cleared_client->NegotiatedAlpn() == nexora::AlpnProtocol::kNone);
  Check(cleared_server->NegotiatedAlpn() == nexora::AlpnProtocol::kNone);
}

}  // namespace

int main() {
  HandshakeFragmented();
  HandshakeCoalesced();
  MutualAuth();
  AlpnSelection();
  CloseNotifyDrains();
  RejectUntrustedAndName();
  PemFilesLoad();
  RequiredAlpnRejectsHttp11();
  RequiredAlpnRejectsMissing();
  RequiredAlpnMatchesAndClears();
  if (g_failed != 0) {
    std::fprintf(stderr, "%d checks failed\n", g_failed);
    return 1;
  }
  return 0;
}
