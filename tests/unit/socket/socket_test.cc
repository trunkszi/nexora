#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <nexora/dispatch/dma_quarantine.hpp>
#include <nexora/socket/memory_pipe.hpp>
#include <nexora/socket/socket_word.hpp>
#include <nexora/socket/tcp_transport.hpp>
#include <nexora/socket/unix_socket.hpp>
#include <nexora/socket/uring_socket.hpp>
#include <string>
#include <string_view>

namespace {

int TestSocketWordFsm() noexcept {
  constexpr auto idle = nexora::SocketWord::IdleWord();
  static_assert(idle.Phase() == nexora::SocketPhase::kIdle);
  static_assert(idle.Superstate() == nexora::SocketSuperstate::kInactive);
  static_assert(idle.InFlight() == 0);

  constexpr auto connecting = idle.BeginConnect();
  static_assert(connecting.Phase() == nexora::SocketPhase::kConnecting);
  static_assert(connecting.Superstate() == nexora::SocketSuperstate::kEstablishing);
  static_assert(connecting.InFlight() == 1);

  constexpr auto open_plain = connecting.ConnectCompleted(false);
  static_assert(open_plain.Phase() == nexora::SocketPhase::kOpen);
  static_assert(open_plain.Superstate() == nexora::SocketSuperstate::kActive);
  static_assert(open_plain.InFlight() == 0);

  constexpr auto hs = connecting.ConnectCompleted(true);
  static_assert(hs.Phase() == nexora::SocketPhase::kHandshaking);
  static_assert(hs.InFlight() == 0);

  constexpr auto op1 = open_plain.BeginOp().BeginOp();
  static_assert(op1.InFlight() == 2);
  constexpr auto cancel = op1.RequestClose();
  static_assert(cancel.Phase() == nexora::SocketPhase::kCancelling);
  static_assert(cancel.Superstate() == nexora::SocketSuperstate::kTeardown);

  constexpr auto drain1 = cancel.CompleteOp();
  static_assert(drain1.Phase() == nexora::SocketPhase::kCancelling);
  static_assert(drain1.InFlight() == 1);

  constexpr auto ready = drain1.CompleteOp();
  static_assert(ready.Phase() == nexora::SocketPhase::kCloseReady);
  static_assert(ready.InFlight() == 0);

  constexpr auto closed = ready.CloseStarted().CloseCompleted();
  static_assert(closed.Phase() == nexora::SocketPhase::kClosed);
  static_assert(closed.Superstate() == nexora::SocketSuperstate::kInactive);
  static_assert(closed.InFlight() == 0);
  return 0;
}

int TestMemoryPipeDuplex() noexcept {
  auto pair = nexora::MemoryPipe::CreatePair(64);
  if (!pair) {
    return 10;
  }
  constexpr std::array<std::uint8_t, 5> ping{'h', 'e', 'l', 'l', 'o'};
  if (!pair->client.WriteAll(ping)) {
    return 11;
  }
  if (pair->server.PendingReadBytes() != 5) {
    return 12;
  }
  std::array<std::uint8_t, 16> rx{};
  auto n = pair->server.ReadSome(rx);
  if (!n || *n != 5 || std::memcmp(rx.data(), ping.data(), 5) != 0) {
    return 13;
  }
  pair->client.CloseWrite();
  auto eof = pair->server.ReadSome(rx);
  if (!eof || *eof != 0) {
    return 14;
  }
  return 0;
}

int TestUnixSocketPairAndListener() noexcept {
  auto pair = nexora::UnixSocket::CreatePair();
  if (!pair) {
    return 20;
  }
  constexpr std::array<std::uint8_t, 4> msg{'u', 'n', 'i', 'x'};
  if (!pair->first.WriteAll(msg, 1000)) {
    return 21;
  }
  std::array<std::uint8_t, 8> out{};
  auto n = pair->second.ReadSome(out, 1000);
  if (!n || *n != 4 || std::memcmp(out.data(), msg.data(), 4) != 0) {
    return 22;
  }

  const std::string sock_path = "/tmp/nexora_unit_unix_" + std::to_string(::getpid()) + ".sock";
  auto listener = nexora::UnixListener::Bind(sock_path);
  if (!listener) {
    return 23;
  }
  auto client = nexora::UnixSocket::Connect(sock_path, 1000);
  if (!client) {
    return 24;
  }
  auto server = listener->Accept(1000);
  if (!server) {
    return 25;
  }
  if (!client->WriteAll(msg, 1000)) {
    return 26;
  }
  auto srv_n = server->ReadSome(out, 1000);
  if (!srv_n || *srv_n != 4) {
    return 27;
  }
  return 0;
}

int TestTcpLoopbackPaths() noexcept {
  auto listener = nexora::TcpListener::BindLoopbackV4(0);
  if (!listener || listener->LocalPort() == 0) {
    return 30;
  }
  const cares::Endpoint bound_ep = listener->LocalEndpoint();
  auto client = nexora::TcpTransport::ConnectTo(bound_ep, 1000);
  if (!client || !client->IsOpen() || client->NativeFd() < 0) {
    return 31;
  }
  auto server = listener->Accept(1000);
  if (!server || !server->IsOpen()) {
    return 32;
  }
  constexpr std::array<std::uint8_t, 6> payload{'n', 'e', 'x', 'o', 'r', 'a'};
  if (!client->WriteAll(payload, 1000)) {
    return 33;
  }
  std::array<std::uint8_t, 16> rx{};
  auto n = server->ReadSome(rx, 1000);
  if (!n || *n != 6 || std::memcmp(rx.data(), payload.data(), 6) != 0) {
    return 34;
  }

  // Negative path 1: ReadSome times out when peer sends nothing within timeout_ms.
  auto timed_out = server->ReadSome(rx, 15);
  if (timed_out.has_value() || timed_out.error() != nexora::Error::Timeout()) {
    return 35;
  }

  // Negative path 2: Peer ShutdownWrite produces clean EOF (ReadSome == 0).
  client->ShutdownWrite();
  auto eof = server->ReadSome(rx, 1000);
  if (!eof || *eof != 0) {
    return 36;
  }

  // Negative path 3: Closing listener and connecting to the closed port returns kConnectionRefused.
  client->Close();
  server->Close();
  listener->Close();
  auto refused = nexora::TcpTransport::ConnectTo(bound_ep, 500);
  if (refused.has_value() || refused.error() != nexora::Error::FromRuntime(nexora::RuntimeErrorCode::kConnectionRefused)) {
    return 37;
  }
  return 0;
}

int TestUringTlsBioPump() noexcept {
  auto srv_cfg = nexora::TlsServerConfig::SelfSignedForLocalhost();
  auto cli_cfg = nexora::TlsClientConfig::CreateInsecureForTest();
  if (!srv_cfg || !cli_cfg) {
    return 40;
  }
  constexpr std::array<nexora::AlpnProtocol, 1> alpn{nexora::AlpnProtocol::kHttp2};
  if (!srv_cfg->SetAlpn(alpn) || !cli_cfg->SetAlpn(alpn)) {
    return 41;
  }
  auto cli_tls = nexora::TlsSession::CreateClient(*cli_cfg, "localhost");
  auto srv_tls = nexora::TlsSession::CreateServer(*srv_cfg);
  if (!cli_tls || !srv_tls) {
    return 42;
  }

  auto cli_sock = nexora::IoUringSocket::FromRawFd(-1, nexora::SocketWord::IdleWord(), std::nullopt, std::move(*cli_tls));
  auto srv_sock = nexora::IoUringSocket::FromRawFd(-1, nexora::SocketWord::IdleWord(), std::nullopt, std::move(*srv_tls));

  const cares::Endpoint ep{cares::IpAddress::FromV4({127, 0, 0, 1}), 443};
  if (!cli_sock.BeginConnect(ep) || !cli_sock.ConnectCompleted() || cli_sock.Phase() != nexora::SocketPhase::kHandshaking) {
    return 43;
  }
  if (!srv_sock.BeginConnect(ep) || !srv_sock.ConnectCompleted() || srv_sock.Phase() != nexora::SocketPhase::kHandshaking) {
    return 44;
  }

  std::array<std::uint8_t, 16384> wire{};
  for (int step = 0;
       step < 8 && (cli_sock.Phase() != nexora::SocketPhase::kOpen || srv_sock.Phase() != nexora::SocketPhase::kOpen); ++step) {
    if (auto c2s = cli_sock.TakeTlsCiphertext(wire); c2s && *c2s > 0) {
      if (!srv_sock.FeedTlsCiphertext(std::span<const std::uint8_t>{wire.data(), *c2s})) {
        return 45;
      }
    }
    if (auto s2c = srv_sock.TakeTlsCiphertext(wire); s2c && *s2c > 0) {
      if (!cli_sock.FeedTlsCiphertext(std::span<const std::uint8_t>{wire.data(), *s2c})) {
        return 46;
      }
    }
  }
  if (cli_sock.Phase() != nexora::SocketPhase::kOpen || srv_sock.Phase() != nexora::SocketPhase::kOpen) {
    return 47;
  }

  // Also verify TlsTransport over loopback TCP sockets (single-threaded Run-to-Completion).
  auto listener = nexora::TcpListener::BindLoopbackV4(0);
  if (!listener) {
    return 48;
  }
  auto raw_cli = nexora::TcpTransport::ConnectTo(listener->LocalEndpoint(), 1000);
  auto raw_srv = listener->Accept(1000);
  if (!raw_cli || !raw_srv) {
    return 49;
  }
  auto cli_tls2 = nexora::TlsSession::CreateClient(*cli_cfg, "localhost");
  auto srv_tls2 = nexora::TlsSession::CreateServer(*srv_cfg);
  if (!cli_tls2 || !srv_tls2) {
    return 50;
  }
  nexora::TlsTransport tls_cli{std::move(*raw_cli), std::move(*cli_tls2)};
  nexora::TlsTransport tls_srv{std::move(*raw_srv), std::move(*srv_tls2)};
  for (int i = 0; i < 8 && (!tls_cli.IsHandshakeComplete() || !tls_srv.IsHandshakeComplete()); ++i) {
    if (!tls_cli.IsHandshakeComplete()) {
      if (!tls_cli.StepHandshake(0)) {
        return 51;
      }
    }
    if (!tls_srv.IsHandshakeComplete()) {
      if (!tls_srv.StepHandshake(100)) {
        return 52;
      }
    }
  }
  if (!tls_cli.IsHandshakeComplete() || !tls_srv.IsHandshakeComplete() ||
      tls_cli.NegotiatedAlpn() != nexora::AlpnProtocol::kHttp2) {
    return 53;
  }
  constexpr std::array<std::uint8_t, 4> plain{'t', 'l', 's', '!'};
  if (!tls_cli.WriteAll(plain, 1000)) {
    return 54;
  }
  std::array<std::uint8_t, 8> dec{};
  auto dec_n = tls_srv.ReadSome(dec, 1000);
  if (!dec_n || *dec_n != 4 || std::memcmp(dec.data(), plain.data(), 4) != 0) {
    return 55;
  }
  tls_cli.Close();
  tls_srv.Close();
  return 0;
}

int TestUnixListenerReplacedInode() noexcept {
  const std::string path = "/tmp/nexora_inode_" + std::to_string(::getpid()) + ".sock";
  static_cast<void>(::unlink(path.c_str()));
  auto listener = nexora::UnixListener::Bind(path);
  if (!listener) return 60;
  if (::unlink(path.c_str()) != 0) return 61;
  const int replaced = ::open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
  if (replaced < 0) return 62;
  static_cast<void>(::close(replaced));
  listener->Close();
  if (::access(path.c_str(), F_OK) != 0) return 63;
  static_cast<void>(::unlink(path.c_str()));

  const std::string owned = path + ".owned";
  static_cast<void>(::unlink(owned.c_str()));
  auto second = nexora::UnixListener::Bind(owned);
  if (!second) return 64;
  second->Close();
  if (::access(owned.c_str(), F_OK) == 0) return 65;
  return 0;
}

int TestUnixListenerMoveSymlink() noexcept {
  const std::string path = "/tmp/nexora_move_" + std::to_string(::getpid()) + ".sock";
  const std::string hard_path = path + ".hard";
  static_cast<void>(::unlink(path.c_str()));
  static_cast<void>(::unlink(hard_path.c_str()));
  auto listener = nexora::UnixListener::Bind(path);
  if (!listener) return 80;
  nexora::UnixListener moved = std::move(*listener);
  if (!listener->Path().empty() || moved.Path() != path) return 81;
  listener->Close();
  nexora::UnixListener assigned;
  assigned = std::move(moved);
  // NOLINTNEXTLINE(bugprone-use-after-move) -- moved-from Path() is defined as empty.
  if (!moved.Path().empty() || assigned.Path() != path) return 82;
  moved.Close();
  if (::access(path.c_str(), F_OK) != 0) return 83;
  assigned.Close();
  struct ::stat st{};
  if (::lstat(path.c_str(), &st) == 0 || errno != ENOENT) return 84;

  auto rebound = nexora::UnixListener::Bind(path);
  if (!rebound) return 85;
  struct ::stat identity{};
  if (::lstat(path.c_str(), &identity) != 0 || !S_ISSOCK(identity.st_mode)) return 86;
  if (::link(path.c_str(), hard_path.c_str()) != 0) return 87;
  if (::unlink(path.c_str()) != 0 || ::symlink(hard_path.c_str(), path.c_str()) != 0) return 88;
  // Following this symlink yields the original live socket's exact identity.
  if (::stat(path.c_str(), &st) != 0 || !S_ISSOCK(st.st_mode) || st.st_dev != identity.st_dev || st.st_ino != identity.st_ino)
    return 89;
  rebound->Close();
  const bool preserved = ::lstat(path.c_str(), &st) == 0 && S_ISLNK(st.st_mode);
  const bool target_preserved = ::lstat(hard_path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode);
  static_cast<void>(::unlink(path.c_str()));
  static_cast<void>(::unlink(hard_path.c_str()));
  return preserved && target_preserved ? 0 : 90;
}

int TestUnixListenerBindPreservesNonSocket() noexcept {
  const std::string base = "/tmp/nexora_bind_guard_" + std::to_string(::getpid());
  const std::string reg_path = base + ".file";
  const std::string sym_path = base + ".link";
  const std::string sock_path = base + ".sock";
  static_cast<void>(::unlink(reg_path.c_str()));
  static_cast<void>(::unlink(sym_path.c_str()));
  static_cast<void>(::unlink(sock_path.c_str()));

  const int reg_fd = ::open(reg_path.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
  if (reg_fd < 0) return 91;
  static_cast<void>(::close(reg_fd));
  if (::symlink(reg_path.c_str(), sym_path.c_str()) != 0) {
    static_cast<void>(::unlink(reg_path.c_str()));
    return 92;
  }

  const auto reg_bind = nexora::UnixListener::Bind(reg_path);
  struct ::stat st{};
  const bool reg_rejected = !reg_bind && reg_bind.error() == nexora::Error::FromErrno(EADDRINUSE);
  const bool reg_intact = (::lstat(reg_path.c_str(), &st) == 0 && S_ISREG(st.st_mode));

  const auto sym_bind = nexora::UnixListener::Bind(sym_path);
  const bool sym_rejected = !sym_bind && sym_bind.error() == nexora::Error::FromErrno(EADDRINUSE);
  const bool sym_intact = (::lstat(sym_path.c_str(), &st) == 0 && S_ISLNK(st.st_mode));
  const bool target_intact = (::lstat(reg_path.c_str(), &st) == 0 && S_ISREG(st.st_mode));

  static_cast<void>(::unlink(sym_path.c_str()));
  static_cast<void>(::unlink(reg_path.c_str()));
  if (!reg_rejected || !reg_intact || !sym_rejected || !sym_intact || !target_intact) return 93;

  // Stale socket inode is still replaced cleanly.
  const int stale_fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (stale_fd < 0) return 94;
  ::sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::memcpy(addr.sun_path, sock_path.data(), sock_path.size());
  const int bound = ::bind(stale_fd, reinterpret_cast<const ::sockaddr*>(&addr), sizeof(addr));
  static_cast<void>(::close(stale_fd));
  if (bound != 0) return 95;
  auto rebound = nexora::UnixListener::Bind(sock_path);
  if (!rebound) {
    static_cast<void>(::unlink(sock_path.c_str()));
    return 96;
  }
  rebound->Close();
  return 0;
}

int TestGenerationSkipsZero() noexcept {
  auto sock = nexora::IoUringSocket::FromRawFd(-1, nexora::SocketWord::IdleWord().WithPhase(nexora::SocketPhase::kCloseReady),
                                               std::nullopt, std::nullopt,
                                               nexora::SocketConfig{.rx_buffer_capacity = 1, .tx_buffer_capacity = 1});
  if (sock.Generation() != 1) return 70;
  for (int step = 0; step < 65535; ++step) sock.CloseCompleted();
  if (sock.Generation() != 1) return 71;
  return 0;
}

int TestDmaQuarantineDoubleOverflowRetainsFd() noexcept {
  nexora::detail::SocketDmaQuarantine quarantine{};
  constexpr std::size_t base_total = nexora::detail::SocketDmaQuarantine::kCapacity * 2;
  for (std::size_t i = 0; i < base_total; ++i) {
    const auto tok = uring::MakeToken(static_cast<std::uint16_t>(i + 1U), 0, nexora::kSocketSubsystemId, 1);
    quarantine.Park(1, -1, {}, {}, tok, std::nullopt, std::nullopt);
  }
  if (quarantine.ActiveCount() != base_total) return 100;

  std::array<int, 2> sv{-1, -1};
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv.data()) != 0) return 101;
  const int tracked_fd = sv[0];
  static_cast<void>(::close(sv[1]));

  const auto rx_tok = uring::MakeToken(500, 0, nexora::kSocketSubsystemId, 2);
  const auto tx_tok = uring::MakeToken(501, 0, nexora::kSocketSubsystemId, 2);
  quarantine.Park(1, tracked_fd, std::vector<std::uint8_t>(16, 0xAB), std::vector<std::uint8_t>(16, 0xCD), rx_tok, tx_tok,
                  std::nullopt);
  if (quarantine.ActiveCount() != base_total + 1 || ::fcntl(tracked_fd, F_GETFD) == -1) return 102;
  if (!quarantine.TryRetire(rx_tok, 1, 0) || quarantine.ActiveCount() != base_total + 1 || ::fcntl(tracked_fd, F_GETFD) == -1) {
    return 103;
  }
  errno = 0;
  if (!quarantine.TryRetire(tx_tok, 1, 0) || quarantine.ActiveCount() != base_total || ::fcntl(tracked_fd, F_GETFD) != -1 ||
      errno != EBADF) {
    return 104;
  }
  for (std::size_t i = 0; i < base_total; ++i) {
    const auto tok = uring::MakeToken(static_cast<std::uint16_t>(i + 1U), 0, nexora::kSocketSubsystemId, 1);
    if (!quarantine.TryRetire(tok, 1, 0)) return 105;
  }
  if (quarantine.ActiveCount() != 0) return 106;
  return 0;
}

}  // namespace

int main() {
  if (const int rc = TestSocketWordFsm(); rc != 0) {
    return rc;
  }
  if (const int rc = TestMemoryPipeDuplex(); rc != 0) {
    return rc;
  }
  if (const int rc = TestUnixSocketPairAndListener(); rc != 0) {
    return rc;
  }
  if (const int rc = TestTcpLoopbackPaths(); rc != 0) {
    return rc;
  }
  if (const int rc = TestUringTlsBioPump(); rc != 0) {
    return rc;
  }
  if (const int rc = TestUnixListenerReplacedInode(); rc != 0) {
    return rc;
  }
  if (const int rc = TestUnixListenerMoveSymlink(); rc != 0) {
    return rc;
  }
  if (const int rc = TestUnixListenerBindPreservesNonSocket(); rc != 0) {
    return rc;
  }
  if (const int rc = TestGenerationSkipsZero(); rc != 0) {
    return rc;
  }
  if (const int rc = TestDmaQuarantineDoubleOverflowRetainsFd(); rc != 0) {
    return rc;
  }
  return 0;
}
