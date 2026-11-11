#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <nexora/server/listener.hpp>
#include <nexora/socket/tcp_transport.hpp>
#include <nexora/tls/secure_stream.hpp>
#include <source_location>
#include <vector>

namespace {
void Check(bool value, std::source_location location = std::source_location::current()) noexcept {
  if (!value) {
    std::fprintf(stderr, "native_tls:%u failed\n", location.line());
    std::abort();
  }
}
void Exchange(bool insecure) noexcept {
  auto listener = nexora::LoopbackListener::Bind();
  auto server_config = nexora::TlsServerConfig::SelfSignedForLocalhost();
  auto client_config = insecure ? nexora::TlsClientConfig::CreateInsecureForTest() : nexora::TlsClientConfig::CreateDefault();
  Check(listener.has_value() && server_config.has_value() && client_config.has_value());
  constexpr std::array protocols{nexora::AlpnProtocol::kHttp2, nexora::AlpnProtocol::kHttp11};
  Check(server_config->SetAlpn(protocols).has_value());
  const auto child = ::fork();
  Check(child >= 0);
  if (child == 0) {
    auto ring = uring::Proactor::Create();
    if (!ring) std::_Exit(1);
    nexora::SecureStream server(*ring);
    if (!server.Accept(listener->RawFd(), 2000)) std::_Exit(2);
    auto secured = server.StartServer(*server_config, 2000);
    if (!insecure) std::_Exit(secured ? 3 : 0);
    if (!secured || server.Alpn() != nexora::AlpnProtocol::kHttp2) std::_Exit(4);
    std::array<std::uint8_t, 4> bytes{};
    auto read = server.ReadSome(bytes, 2000);
    if (!read || *read != 4 || !server.WriteAll(bytes, 2000) || !server.SendCloseNotify(2000)) std::_Exit(5);
    read = server.ReadSome(bytes, 2000);
    std::_Exit(read && *read == 0 ? 0 : 6);
  }
  {
    auto ring = uring::Proactor::Create();
    Check(ring.has_value());
    nexora::SecureStream client(*ring);
    const cares::Endpoint endpoint{cares::IpAddress::FromV4HostOrder(0x7f000001U), listener->Port()};
    Check(client.Connect(endpoint, 2000).has_value());
    auto secured = client.StartClient(*client_config, "localhost", 2000);
    if (!insecure) {
      Check(!secured && secured.error() == nexora::Error::FromProto(nexora::ProtoErrorCode::kTlsVerifyFailed));
    } else {
      Check(secured.has_value() && client.Alpn() == nexora::AlpnProtocol::kHttp2);
      constexpr std::array<std::uint8_t, 4> request{4, 3, 2, 1};
      Check(client.WriteAll(request, 2000).has_value());
      std::array<std::uint8_t, 4> response{};
      auto read = client.ReadSome(response, 2000);
      Check(read.has_value() && *read == 4 && response == request);
      read = client.ReadSome(response, 2000);
      Check(read.has_value() && *read == 0);
      Check(client.SendCloseNotify(2000).has_value());
    }
  }
  int status = 0;
  Check(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

void LosslessTlsFlushAndDeferredReadError() noexcept {
  auto server_config = nexora::TlsServerConfig::SelfSignedForLocalhost();
  auto client_config = nexora::TlsClientConfig::CreateInsecureForTest();
  Check(server_config.has_value() && client_config.has_value());

  // 1. TlsTransport lossless ciphertext flush across saturated send buffer + timeout, then recovery.
  {
    auto listener = nexora::TcpListener::BindLoopbackV4(0);
    Check(listener.has_value());
    std::array<int, 2> sync_pipe{};
    Check(::pipe(sync_pipe.data()) == 0);

    std::vector<std::uint8_t> big_payload(524288);
    for (std::size_t i = 0; i < big_payload.size(); ++i) big_payload[i] = static_cast<std::uint8_t>((i * 13U) & 0xffU);

    const auto child = ::fork();
    Check(child >= 0);
    if (child == 0) {
      ::close(sync_pipe[1]);
      auto accepted_tcp = listener->Accept(2000);
      if (!accepted_tcp) std::_Exit(1);
      auto srv = nexora::TlsTransport::AcceptServer(std::move(*accepted_tcp), *server_config, 2000);
      if (!srv) std::_Exit(2);
      // Wait until parent hits WriteSome/Flush timeout with unsent ciphertext queued in pending_cipher_.
      char go = 0;
      if (::read(sync_pipe[0], &go, 1) != 1) std::_Exit(3);
      std::size_t total = 0;
      std::array<std::uint8_t, 8192> chunk{};
      while (total < big_payload.size()) {
        auto n = srv->ReadSome(chunk, 3000);
        if (!n || *n == 0) std::_Exit(4);
        if (std::memcmp(chunk.data(), big_payload.data() + total, *n) != 0) std::_Exit(5);
        total += *n;
      }
      // Also send back 6 bytes for deferred-flush-error ReadSome test!
      constexpr std::array<std::uint8_t, 6> reply{'i', 'n', 't', 'a', 'c', 't'};
      if (!srv->WriteAll(reply, 2000)) std::_Exit(6);
      ::close(sync_pipe[0]);
      std::_Exit(0);
    }
    ::close(sync_pipe[0]);
    auto cli = nexora::TlsTransport::ConnectClient(listener->LocalEndpoint(), *client_config, "localhost", 2000);
    Check(cli.has_value());
    const int small_snd = 4096;
    Check(::setsockopt(cli->Tcp().Fd(), SOL_SOCKET, SO_SNDBUF, &small_snd, sizeof(small_snd)) == 0);

    // A positive timeout can expire before the kernel buffer fills, so pending
    // ciphertext is not yet proof of saturation. Probe with a nonblocking flush.
    std::size_t sent_bytes = 0;
    while (sent_bytes < big_payload.size()) {
      const std::size_t step = std::min<std::size_t>(16384, big_payload.size() - sent_bytes);
      auto w = cli->WriteSome(std::span<const std::uint8_t>(big_payload.data() + sent_bytes, step), 0);
      if (!w) {
        Check(w.error() == nexora::Error::Timeout() && cli->HasPendingCiphertext());
        break;
      }
      Check(*w > 0);
      sent_bytes += *w;
      if (!cli->HasPendingCiphertext()) continue;
      auto blocked = cli->Flush(0);
      if (!blocked && blocked.error() == nexora::Error::Timeout()) break;
      Check(blocked.has_value());
    }
    Check(cli->HasPendingCiphertext());
    auto retry_timeout = cli->Flush(2);
    Check(!retry_timeout && retry_timeout.error() == nexora::Error::Timeout() && cli->HasPendingCiphertext());
    const int normal_snd = 262144;
    Check(::setsockopt(cli->Tcp().Fd(), SOL_SOCKET, SO_SNDBUF, &normal_snd, sizeof(normal_snd)) == 0);
    const char wake = 1;
    Check(::write(sync_pipe[1], &wake, 1) == 1);
    Check(cli->Flush(3000).has_value() && !cli->HasPendingCiphertext());
    if (sent_bytes < big_payload.size()) {
      Check(cli->WriteAll(std::span<const std::uint8_t>(big_payload.data() + sent_bytes, big_payload.size() - sent_bytes), 3000)
                .has_value());
    }

    // Read server's 6-byte reply into socket buffer, then buffer outbound TLS ciphertext while write-half is shut down:
    // ReadSome MUST deliver the 6 decrypted plaintext bytes FIRST and surface the flush error on the next ReadSome!
    std::array<std::uint8_t, 6> first_half{};
    auto r1 = cli->ReadSome(std::span<std::uint8_t>(first_half.data(), 3), 2000);
    Check(r1.has_value() && *r1 == 3);
    // Remaining 3 bytes ("act") are already decrypted inside TlsSession!
    // Stage outbound ciphertext via Tls()->WritePlaintext and shut down write half so Flush fails fatally with EPIPE.
    constexpr std::array<std::uint8_t, 4> outbound{'b', 'y', 'e', '!'};
    Check(cli->Tls()->WritePlaintext(outbound).has_value() && cli->HasPendingCiphertext());
    Check(::shutdown(cli->Tcp().Fd(), SHUT_WR) == 0);
    auto r2 = cli->ReadSome(std::span<std::uint8_t>(first_half.data() + 3, 3), 2000);
    Check(r2.has_value() && *r2 == 3 && std::string_view(reinterpret_cast<const char*>(first_half.data()), 6) == "intact");
    auto r3 = cli->ReadSome(first_half, 2000);
    Check(!r3 && r3.error() != nexora::Error::Timeout());

    ::close(sync_pipe[1]);
    int status = 0;
    Check(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }

  // 2. SecureStream lossless ciphertext flush across timeout_ms == 0 / small SO_SNDBUF + deferred flush error in ReadSome.
  {
    auto listener = nexora::LoopbackListener::Bind();
    Check(listener.has_value());
    std::array<int, 2> sync_pipe{};
    Check(::pipe(sync_pipe.data()) == 0);
    std::vector<std::uint8_t> payload(131072);
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::uint8_t>((i * 7U + 3U) & 0xffU);

    const auto child = ::fork();
    Check(child >= 0);
    if (child == 0) {
      ::close(sync_pipe[1]);
      auto ring = uring::Proactor::Create();
      if (!ring) std::_Exit(1);
      nexora::SecureStream srv(*ring);
      if (!srv.Accept(listener->RawFd(), 2000) || !srv.StartServer(*server_config, 2000)) std::_Exit(2);
      char go = 0;
      if (::read(sync_pipe[0], &go, 1) != 1) std::_Exit(3);
      std::size_t got = 0;
      std::array<std::uint8_t, 8192> buf{};
      while (got < payload.size()) {
        auto n = srv.ReadSome(buf, 3000);
        if (!n || *n == 0) std::_Exit(4);
        if (std::memcmp(buf.data(), payload.data() + got, *n) != 0) std::_Exit(5);
        got += *n;
      }
      ::close(sync_pipe[0]);
      std::_Exit(0);
    }
    ::close(sync_pipe[0]);
    auto ring = uring::Proactor::Create();
    Check(ring.has_value());
    nexora::SecureStream cli(*ring);
    const cares::Endpoint ep{cares::IpAddress::FromV4HostOrder(0x7f000001U), listener->Port()};
    Check(cli.Connect(ep, 2000).has_value() && cli.StartClient(*client_config, "localhost", 2000).has_value());
    std::size_t off = 0;
    while (off < payload.size()) {
      const std::size_t step = std::min<std::size_t>(16384, payload.size() - off);
      auto w = cli.WriteSome(std::span<const std::uint8_t>(payload.data() + off, step), 5);
      if (!w) {
        Check(w.error() == nexora::Error::Timeout() && cli.HasPendingCiphertext());
        break;
      }
      off += *w;
      if (cli.HasPendingCiphertext()) break;
    }
    const char wake = 1;
    Check(::write(sync_pipe[1], &wake, 1) == 1);
    Check(cli.Flush(3000).has_value() && !cli.HasPendingCiphertext());
    if (off < payload.size()) {
      Check(cli.WriteAll(std::span<const std::uint8_t>(payload.data() + off, payload.size() - off), 3000).has_value());
    }
    ::close(sync_pipe[1]);
    int status = 0;
    Check(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

void ReadPlainUnderTxPressure() noexcept {
  auto server_config = nexora::TlsServerConfig::SelfSignedForLocalhost();
  auto client_config = nexora::TlsClientConfig::CreateInsecureForTest();
  Check(server_config.has_value() && client_config.has_value());
  constexpr std::array<std::uint8_t, 32> note{1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                                              17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  auto listener = nexora::TcpListener::BindLoopbackV4(0);
  Check(listener.has_value());
  std::array<int, 2> sync_pipe{};
  Check(::pipe(sync_pipe.data()) == 0);
  const auto child = ::fork();
  Check(child >= 0);
  if (child == 0) {
    ::close(sync_pipe[1]);
    auto accepted = listener->Accept(2000);
    if (!accepted) std::_Exit(1);
    auto srv = nexora::TlsTransport::AcceptServer(std::move(*accepted), *server_config, 2000);
    if (!srv || !srv->WriteAll(note, 2000)) std::_Exit(2);
    char go = 0;
    if (::read(sync_pipe[0], &go, 1) != 1) std::_Exit(3);
    ::close(sync_pipe[0]);
    std::_Exit(0);
  }
  ::close(sync_pipe[0]);
  auto cli = nexora::TlsTransport::ConnectClient(listener->LocalEndpoint(), *client_config, "localhost", 2000);
  Check(cli.has_value());
  std::array<std::uint8_t, 8> prefix{};
  auto head = cli->ReadSome(prefix, 2000);
  Check(head.has_value() && *head == 8 && std::memcmp(prefix.data(), note.data(), 8) == 0);
  const int small_snd = 4096;
  static_cast<void>(::setsockopt(cli->Tcp().Fd(), SOL_SOCKET, SO_SNDBUF, &small_snd, sizeof(small_snd)));
  std::vector<std::uint8_t> bulk(524288, 0x5a);
  bool pending = false;
  for (std::size_t off = 0; off < bulk.size();) {
    const std::size_t step = std::min<std::size_t>(16384, bulk.size() - off);
    auto wrote = cli->WriteSome(std::span<const std::uint8_t>(bulk.data() + off, step), 5);
    if (!wrote) {
      Check(wrote.error() == nexora::Error::Timeout());
      pending = cli->HasPendingCiphertext();
      break;
    }
    off += *wrote;
    if (cli->HasPendingCiphertext()) {
      pending = true;
      break;
    }
  }
  Check(pending);
  std::array<std::uint8_t, 24> rest{};
  const auto started = std::chrono::steady_clock::now();
  auto tail = cli->ReadSome(rest, 2000);
  const auto elapsed = std::chrono::steady_clock::now() - started;
  Check(tail.has_value() && *tail == 24 && std::memcmp(rest.data(), note.data() + 8, 24) == 0);
  Check(elapsed < std::chrono::milliseconds(100));
  const char wake = 1;
  Check(::write(sync_pipe[1], &wake, 1) == 1);
  ::close(sync_pipe[1]);
  int status = 0;
  Check(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
}  // namespace
int main() {
  Exchange(true);
  Exchange(false);
  LosslessTlsFlushAndDeferredReadError();
  ReadPlainUnderTxPressure();
}
