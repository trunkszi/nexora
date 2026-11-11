#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <nexora/dispatch/completion_routes.hpp>
#include <nexora/socket/tcp_transport.hpp>
#include <nexora/socket/uring_socket.hpp>
#include <optional>
#include <vector>

namespace {

template <typename T>
constexpr void Consume(T&& value) noexcept {
  static_cast<void>(value);
}

int CloseWaitsForInFlightOps() noexcept {
  auto sock =
      nexora::IoUringSocket::FromRawFd(-1, nexora::SocketWord::IdleWord(), std::nullopt, std::nullopt, nexora::SocketConfig{});
  const cares::Endpoint peer{cares::IpAddress::FromV4({127, 0, 0, 1}), 8080};

  if (!sock.BeginConnect(peer) || sock.Phase() != nexora::SocketPhase::kConnecting || sock.InFlightOps() != 1) {
    return 1;
  }
  if (!sock.ConnectCompleted() || sock.Phase() != nexora::SocketPhase::kOpen || sock.InFlightOps() != 0) {
    return 2;
  }

  // Two active operations (e.g., recv + send).
  if (!sock.BeginOp() || !sock.BeginOp() || sock.InFlightOps() != 2) {
    return 3;
  }

  sock.RequestClose();
  if (sock.Phase() != nexora::SocketPhase::kCancelling || sock.CanSubmitClose()) {
    return 4;
  }

  // Premature CloseCompleted() while InFlightOps() > 0 is ignored and does not close or transition.
  sock.CloseCompleted();
  if (sock.Phase() != nexora::SocketPhase::kCancelling || sock.InFlightOps() != 2) {
    return 5;
  }

  sock.CompleteOp();
  if (sock.Phase() != nexora::SocketPhase::kCancelling || sock.InFlightOps() != 1 || sock.CanSubmitClose()) {
    return 6;
  }

  sock.CompleteOp();
  if (sock.Phase() != nexora::SocketPhase::kCloseReady || sock.InFlightOps() != 0 || !sock.CanSubmitClose()) {
    return 7;
  }

  if (!sock.CloseStarted() || sock.Phase() != nexora::SocketPhase::kCloseSubmitted || sock.InFlightOps() != 1) {
    return 8;
  }
  sock.CompleteOp();

  sock.CloseCompleted();
  if (sock.Phase() != nexora::SocketPhase::kClosed || sock.InFlightOps() != 0 || sock.RawFd() != -1) {
    return 9;
  }
  return 0;
}

int BufferRenewalWaitsForClose() noexcept {
  auto sock = nexora::IoUringSocket::FromRawFd(-1, nexora::SocketWord::OpenWord(), std::nullopt, std::nullopt,
                                               nexora::SocketConfig{.rx_buffer_capacity = 256, .tx_buffer_capacity = 256});

  sock.RxBufferMut()[0] = 0xAA;
  sock.TxBufferMut()[0] = 0xBB;

  if (!sock.BeginOp()) {
    return 10;
  }
  if (sock.RenewBuffers().has_value()) {
    return 11;
  }

  sock.RequestCancel();
  if (sock.Phase() != nexora::SocketPhase::kCancelling || sock.RenewBuffers().has_value()) {
    return 12;
  }

  sock.CompleteOp();
  if (sock.Phase() != nexora::SocketPhase::kCloseReady) {
    return 13;
  }
  if (!sock.RenewBuffers() || sock.RxBuffer()[0] != 0 || sock.TxBuffer()[0] != 0) {
    return 14;
  }

  if (!sock.CloseStarted()) {
    return 15;
  }
  sock.CompleteOp();
  sock.CloseCompleted();
  return 0;
}

int CloseRetryAfterSqFull() noexcept {
  auto sock =
      nexora::IoUringSocket::FromRawFd(-1, nexora::SocketWord::OpenWord(), std::nullopt, std::nullopt, nexora::SocketConfig{});

  sock.RequestClose();
  if (sock.Phase() != nexora::SocketPhase::kCloseQueued || !sock.CanSubmitClose()) {
    return 20;
  }

  if (!sock.CloseSubmissionFailed() || sock.Phase() != nexora::SocketPhase::kCloseReady || !sock.CanSubmitClose()) {
    return 21;
  }

  sock.RequestClose();
  if (sock.Phase() != nexora::SocketPhase::kCloseQueued) {
    return 22;
  }

  if (!sock.CloseStarted() || sock.Phase() != nexora::SocketPhase::kCloseSubmitted || sock.InFlightOps() != 1) {
    return 23;
  }

  if (!sock.CloseCancelled() || sock.Phase() != nexora::SocketPhase::kCloseReady || sock.InFlightOps() != 0 ||
      !sock.CanSubmitClose()) {
    return 24;
  }

  if (!sock.CloseStarted()) {
    return 25;
  }
  sock.CompleteOp();
  sock.CloseCompleted();
  if (sock.Phase() != nexora::SocketPhase::kClosed || sock.InFlightOps() != 0) {
    return 26;
  }
  return 0;
}

int RecvCancelBeforeClose() noexcept {
  auto proactor = uring::Proactor::Create(64);
  if (!proactor) {
    return 30;
  }

  std::array<int, 2> sv{-1, -1};
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv.data()) != 0) {
    return 31;
  }

  auto sock = nexora::IoUringSocket::FromRawFd(sv[0], nexora::SocketWord::OpenWord(), std::nullopt, std::nullopt,
                                               nexora::SocketConfig{.rx_buffer_capacity = 256, .tx_buffer_capacity = 256});
  nexora::CompletionRoutes<8> routes{};
  sock.BindProactor(*proactor, routes);
  if (!routes.Register(nexora::CompletionRoute::BindMethod<nexora::kSocketSubsystemId, nexora::IoUringSocket,
                                                           &nexora::IoUringSocket::HandleCqe>(&sock))) {
    Consume(::close(sv[1]));
    return 32;
  }

  // Stage a real kernel RECV on sv[0] while sv[1] sends nothing -> genuinely in flight in io_uring.
  auto recv_tok = sock.SubmitRecv(64);
  if (!recv_tok || sock.InFlightOps() != 1 || !sock.RxToken().has_value()) {
    Consume(::close(sv[1]));
    return 33;
  }
  Consume(proactor->Drive(uring::DriveMode::kPoll, routes));
  if (sock.InFlightOps() != 1 || proactor->InFlight() != 1) {
    Consume(::close(sv[1]));
    return 34;
  }

  // A subsystem-3 CQE whose token does not match rx_token_ (even if its slab generation equals sock.Generation())
  // must be rejected without decrementing InFlightOps().
  const nexora::CompletionEvent unmatched_cqe{
      .token = uring::MakeToken(99, 0, nexora::kSocketSubsystemId, sock.Generation()),
      .result = 0,
      .flags = 0,
  };
  auto unmatched_res = sock.OnCompletion(unmatched_cqe);
  if (!unmatched_res.has_value() || *unmatched_res || sock.InFlightOps() != 1) {
    Consume(::close(sv[1]));
    return 35;
  }

  // Request close & cancel: socket enters kCancelling, keeps fd open in kernel.
  sock.RequestClose();
  if (!sock.SubmitCancel() || sock.Phase() != nexora::SocketPhase::kCancelling || sock.InFlightOps() != 1 ||
      ::fcntl(sv[0], F_GETFD) == -1) {
    Consume(::close(sv[1]));
    return 36;
  }

  // First kPoll drive stages the ASYNC_CANCEL SQE in the userspace SQ ring; while the target CQE has not been reaped,
  // sv[0] must remain a valid open file descriptor in the kernel.
  Consume(proactor->Drive(uring::DriveMode::kPoll, routes));
  if (sock.InFlightOps() > 0 && ::fcntl(sv[0], F_GETFD) == -1) {
    Consume(::close(sv[1]));
    return 37;
  }

  for (int step = 0; step < 16 && sock.InFlightOps() > 0; ++step) {
    Consume(proactor->Drive(uring::DriveMode::kWait, routes));
  }

  // Target -ECANCELED CQE has now arrived, transitioning phase to kCloseReady, while sv[0] is still open until
  // CloseCompleted() closes it.
  if (sock.InFlightOps() != 0 || sock.Phase() != nexora::SocketPhase::kCloseReady || sock.LastRxResult() != -ECANCELED ||
      ::fcntl(sv[0], F_GETFD) == -1) {
    Consume(::close(sv[1]));
    return 38;
  }

  sock.UnbindProactor();
  if (sock.HasProactor()) {
    Consume(::close(sv[1]));
    return 39;
  }

  const std::uint16_t gen_before = sock.Generation();
  sock.CloseCompleted();
  if (sock.Phase() != nexora::SocketPhase::kClosed || sock.RawFd() != -1 || sock.Generation() == gen_before ||
      ::fcntl(sv[0], F_GETFD) != -1 || errno != EBADF) {
    Consume(::close(sv[1]));
    return 40;
  }
  Consume(::close(sv[1]));
  return 0;
}

void CloseFds(std::initializer_list<int> fds) noexcept {
  for (int fd : fds) {
    if (fd >= 0) Consume(::close(fd));
  }
}

int DrainKeepsSiblingCqes() noexcept {
  auto proactor = uring::Proactor::Create(64);
  if (!proactor) return 41;

  std::array<int, 2> sv_scoped{-1, -1};
  std::array<int, 2> sv_sibling{-1, -1};
  std::array<int, 2> sv_foreign{-1, -1};
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv_scoped.data()) != 0) return 42;
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv_sibling.data()) != 0) {
    CloseFds({sv_scoped[0], sv_scoped[1]});
    return 43;
  }
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv_foreign.data()) != 0) {
    CloseFds({sv_scoped[0], sv_scoped[1], sv_sibling[0], sv_sibling[1]});
    return 44;
  }

  auto sibling_sock =
      nexora::IoUringSocket::FromRawFd(sv_sibling[0], nexora::SocketWord::OpenWord(), std::nullopt, std::nullopt,
                                       nexora::SocketConfig{.rx_buffer_capacity = 128, .tx_buffer_capacity = 128});
  std::vector<std::int32_t> foreign_cqes{};
  nexora::CompletionRoutes<8> shared_routes{};
  sibling_sock.BindProactor(*proactor, shared_routes);

  if (!shared_routes.Register(nexora::CompletionRoute::Make<nexora::kDnsSubsystemId>(
          &foreign_cqes, +[](void* ctx, nexora::CompletionEvent cqe) noexcept {
            static_cast<std::vector<std::int32_t>*>(ctx)->push_back(cqe.result);
          }))) {
    CloseFds({sv_scoped[0], sv_scoped[1], sv_sibling[1], sv_foreign[0], sv_foreign[1]});
    return 45;
  }
  if (!shared_routes.Register(nexora::CompletionRoute::BindMethod<nexora::kSocketSubsystemId, nexora::IoUringSocket,
                                                                  &nexora::IoUringSocket::HandleCqe>(&sibling_sock))) {
    CloseFds({sv_scoped[0], sv_scoped[1], sv_sibling[1], sv_foreign[0], sv_foreign[1]});
    return 46;
  }

  std::array<std::uint8_t, 16> foreign_rx{};
  {
    auto scoped_sock =
        nexora::IoUringSocket::FromRawFd(sv_scoped[0], nexora::SocketWord::OpenWord(), std::nullopt, std::nullopt,
                                         nexora::SocketConfig{.rx_buffer_capacity = 128, .tx_buffer_capacity = 128});
    scoped_sock.BindProactor(*proactor, shared_routes);
    if (!scoped_sock.SubmitRecv(64) || !sibling_sock.SubmitRecv(64)) {
      CloseFds({sv_scoped[1], sv_sibling[1], sv_foreign[0], sv_foreign[1]});
      return 47;
    }

    auto foreign_prep = uring::ops::PrepareRecv(sv_foreign[0], std::span<std::uint8_t>{foreign_rx});
    if (!foreign_prep || !proactor->Arm(nexora::kDnsSubsystemId, *foreign_prep)) {
      CloseFds({sv_scoped[1], sv_sibling[1], sv_foreign[0], sv_foreign[1]});
      return 48;
    }

    // Submit all 3 SQEs to the kernel, then trigger both the sibling kSocketSubsystemId CQE and the foreign
    // kDnsSubsystemId CQE right before scoped_sock's destructor runs DrainInFlightOnProactor().
    Consume(proactor->Drive(uring::DriveMode::kPoll, shared_routes));
    constexpr std::array<std::uint8_t, 7> sib_msg{'s', 'i', 'b', 'l', 'i', 'n', 'g'};
    constexpr std::array<std::uint8_t, 4> dns_msg{'d', 'n', 's', '!'};
    if (::send(sv_sibling[1], sib_msg.data(), sib_msg.size(), MSG_NOSIGNAL) != 7 ||
        ::send(sv_foreign[1], dns_msg.data(), dns_msg.size(), MSG_NOSIGNAL) != 4) {
      CloseFds({sv_scoped[1], sv_sibling[1], sv_foreign[0], sv_foreign[1]});
      return 49;
    }
  }

  const bool sibling_ok = sibling_sock.InFlightOps() == 0 && sibling_sock.LastRxResult() == 7 &&
                          std::memcmp(sibling_sock.RxBuffer().data(), "sibling", 7) == 0;
  CloseFds({sv_scoped[1], sv_sibling[1], sv_foreign[0], sv_foreign[1]});

  if (::fcntl(sv_scoped[0], F_GETFD) != -1 || errno != EBADF || !sibling_ok || foreign_cqes != std::vector<std::int32_t>{4} ||
      proactor->InFlight() != 0) {
    return 50;
  }
  return 0;
}

int DropKeepsKernelWrite() noexcept {
  // 1. Real kernel write AFTER re-entrant ~IoUringSocket() drop: the kernel writes 32 bytes directly into the parked
  // RX buffer (+32 CQE rather than -ECANCELED) without UAF, and CompletionRoutes retires and closes fd automatically.
  auto proactor = uring::Proactor::Create(64);
  if (!proactor) return 51;
  std::array<int, 2> sv_victim{-1, -1};
  std::array<int, 2> sv_trigger{-1, -1};
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv_victim.data()) != 0) return 52;
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv_trigger.data()) != 0) {
    CloseFds({sv_victim[0], sv_victim[1]});
    return 53;
  }

  nexora::CompletionRoutes<8> routes{};
  std::optional<nexora::IoUringSocket> victim_sock{};
  victim_sock.emplace(
      nexora::IoUringSocket::FromRawFd(sv_victim[0], nexora::SocketWord::OpenWord(), std::nullopt, std::nullopt,
                                       nexora::SocketConfig{.rx_buffer_capacity = 128, .tx_buffer_capacity = 128}));
  victim_sock->BindProactor(*proactor, routes);
  if (!victim_sock->SubmitRecv(64)) {
    CloseFds({sv_victim[1], sv_trigger[0], sv_trigger[1]});
    return 54;
  }

  struct ReentrantWriteCtx {
    std::optional<nexora::IoUringSocket>* victim;
    int peer_fd;
  } rw_ctx{.victim = &victim_sock, .peer_fd = sv_victim[1]};

  if (!routes.Register(nexora::CompletionRoute::Make<nexora::kInboxSubsystemId>(
          &rw_ctx, +[](void* ctx, nexora::CompletionEvent) noexcept {
            auto* c = static_cast<ReentrantWriteCtx*>(ctx);
            c->victim->reset();
            // Write 32 bytes from peer AFTER ~IoUringSocket() has already completed!
            std::array<std::uint8_t, 32> payload{};
            payload.fill(0x5A);
            Consume(::send(c->peer_fd, payload.data(), payload.size(), MSG_NOSIGNAL));
          }))) {
    CloseFds({sv_victim[1], sv_trigger[0], sv_trigger[1]});
    return 55;
  }

  std::array<std::uint8_t, 8> trig_rx{};
  auto trig_prep = uring::ops::PrepareRecv(sv_trigger[0], std::span<std::uint8_t>{trig_rx});
  if (!trig_prep || !proactor->Arm(nexora::kInboxSubsystemId, *trig_prep)) {
    CloseFds({sv_victim[1], sv_trigger[0], sv_trigger[1]});
    return 56;
  }
  constexpr std::array<std::uint8_t, 1> trig_byte{'!'};
  Consume(::send(sv_trigger[1], trig_byte.data(), trig_byte.size(), MSG_NOSIGNAL));

  // First kPoll dispatches kInboxSubsystemId -> destroys victim_sock (parking DMA buffers in routes.Quarantine()) and
  // writes 32 bytes into sv_victim[1] so the kernel completes RECV into the parked buffer.
  Consume(proactor->Drive(uring::DriveMode::kPoll, routes));
  if (victim_sock.has_value() || routes.Quarantine().ActiveCount() != 1 || ::fcntl(sv_victim[0], F_GETFD) == -1) {
    Consume(::close(sv_victim[1]));
    Consume(::close(sv_trigger[0]));
    Consume(::close(sv_trigger[1]));
    return 57;
  }

  for (int i = 0; i < 8 && proactor->InFlight() > 0; ++i) {
    for (int p = 0; p < 3 && proactor->InFlight() > 0; ++p) {
      Consume(proactor->Drive(uring::DriveMode::kPoll, routes));
    }
    if (proactor->InFlight() == 0) break;
    Consume(proactor->Drive(uring::DriveMode::kWait, routes));
  }

  Consume(::close(sv_victim[1]));
  Consume(::close(sv_trigger[0]));
  Consume(::close(sv_trigger[1]));
  const auto retired_rx = routes.Quarantine().LastRetiredRxPrefix();
  bool all_5a = (retired_rx.size() == 32);
  for (std::uint8_t b : retired_rx) all_5a = all_5a && (b == 0x5A);
  if (routes.Quarantine().ActiveCount() != 0 || routes.Quarantine().LastRetiredResult() != 32 || !all_5a ||
      proactor->InFlight() != 0 || ::fcntl(sv_victim[0], F_GETFD) != -1 || errno != EBADF) {
    return 58;
  }

  // 2. Cross-Proactor quarantine isolation (both separate CompletionRoutes AND misused shared CompletionRoutes across rings).
  auto proactor_a = uring::Proactor::Create(64);
  auto proactor_b = uring::Proactor::Create(64);
  if (!proactor_a || !proactor_b) return 59;
  std::array<int, 2> sv_a{-1, -1};
  std::array<int, 2> sv_trig_a{-1, -1};
  std::array<int, 2> sv_b{-1, -1};
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv_a.data()) != 0 ||
      ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv_trig_a.data()) != 0 ||
      ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv_b.data()) != 0) {
    for (int fd : {sv_a[0], sv_a[1], sv_trig_a[0], sv_trig_a[1], sv_b[0], sv_b[1]}) {
      if (fd >= 0) Consume(::close(fd));
    }
    return 60;
  }

  nexora::CompletionRoutes<8> routes_a{};
  nexora::CompletionRoutes<8> routes_b{};
  std::optional<nexora::IoUringSocket> sock_a{};
  sock_a.emplace(nexora::IoUringSocket::FromRawFd(sv_a[0], nexora::SocketWord::OpenWord()));
  sock_a->BindProactor(*proactor_a, routes_a);
  auto tok_a = sock_a->SubmitRecv(64);

  auto sock_b = nexora::IoUringSocket::FromRawFd(sv_b[0], nexora::SocketWord::OpenWord());
  sock_b.BindProactor(*proactor_b, routes_b);
  auto tok_b = sock_b.SubmitRecv(64);
  if (!tok_a || !tok_b || *tok_a != *tok_b) {
    for (int fd : {sv_a[1], sv_trig_a[0], sv_trig_a[1], sv_b[1]}) Consume(::close(fd));
    return 61;
  }

  Consume(routes_a.Register(nexora::CompletionRoute::Make<nexora::kInboxSubsystemId>(
      &sock_a,
      +[](void* ctx, nexora::CompletionEvent) noexcept { static_cast<std::optional<nexora::IoUringSocket>*>(ctx)->reset(); })));
  Consume(routes_b.Register(
      nexora::CompletionRoute::BindMethod<nexora::kSocketSubsystemId, nexora::IoUringSocket, &nexora::IoUringSocket::HandleCqe>(
          &sock_b)));

  auto prep_trig_a = uring::ops::PrepareRecv(sv_trig_a[0], std::span<std::uint8_t>{trig_rx});
  Consume(proactor_a->Arm(nexora::kInboxSubsystemId, *prep_trig_a));
  Consume(::send(sv_trig_a[1], trig_byte.data(), trig_byte.size(), MSG_NOSIGNAL));

  Consume(proactor_a->Drive(uring::DriveMode::kPoll, routes_a));
  if (routes_a.Quarantine().ActiveCount() != 1 || ::fcntl(sv_a[0], F_GETFD) == -1) {
    for (int fd : {sv_a[1], sv_trig_a[0], sv_trig_a[1], sv_b[1]}) Consume(::close(fd));
    return 62;
  }

  // Even if a caller misuses routes_a with a Delivery carrying proactor_b->Instance() and identical tok_a,
  // ring_instance mismatch MUST prevent retiring A's parked slot!
  const uring::Delivery foreign_ring_delivery{
      .key = {.token = *tok_a, .ring_instance = proactor_b->Instance()},
      .completion = {.token = *tok_a, .result = 1, .flags = 0},
  };
  Consume(routes_a.Dispatch(foreign_ring_delivery));
  if (routes_a.Quarantine().ActiveCount() != 1 || ::fcntl(sv_a[0], F_GETFD) == -1) {
    for (int fd : {sv_a[1], sv_trig_a[0], sv_trig_a[1], sv_b[1]}) Consume(::close(fd));
    return 63;
  }

  Consume(::send(sv_b[1], trig_byte.data(), trig_byte.size(), MSG_NOSIGNAL));
  for (int i = 0; i < 8 && sock_b.InFlightOps() > 0; ++i) {
    Consume(proactor_b->Drive(uring::DriveMode::kPoll, routes_b));
    if (sock_b.InFlightOps() == 0) break;
    Consume(proactor_b->Drive(uring::DriveMode::kWait, routes_b));
  }
  if (sock_b.InFlightOps() != 0 || routes_a.Quarantine().ActiveCount() != 1 || ::fcntl(sv_a[0], F_GETFD) == -1) {
    for (int fd : {sv_a[1], sv_trig_a[0], sv_trig_a[1], sv_b[1]}) Consume(::close(fd));
    return 64;
  }

  for (int i = 0; i < 8 && proactor_a->InFlight() > 0; ++i) {
    for (int p = 0; p < 3 && proactor_a->InFlight() > 0; ++p) Consume(proactor_a->Drive(uring::DriveMode::kPoll, routes_a));
    if (proactor_a->InFlight() == 0) break;
    Consume(proactor_a->Drive(uring::DriveMode::kWait, routes_a));
  }

  for (int fd : {sv_a[1], sv_trig_a[0], sv_trig_a[1], sv_b[1]}) Consume(::close(fd));
  if (routes_a.Quarantine().ActiveCount() != 0 || proactor_a->InFlight() != 0 || ::fcntl(sv_a[0], F_GETFD) != -1 ||
      errno != EBADF) {
    return 65;
  }
  return 0;
}

int OverflowRetireWithoutUaf() noexcept {
  // 1. Overflow all 64 slots + 2 extra leaked slots (annotated for LSan) and retire the 64 parked slots cleanly.
  nexora::CompletionRoutes<4> routes{};
  constexpr std::uint64_t ring = 777;
  for (std::uint16_t slot = 0; slot < 66; ++slot) {
    const auto tok = uring::MakeToken(slot, 0, nexora::kSocketSubsystemId, 1);
    routes.Quarantine().Park(ring, -1, std::vector<std::uint8_t>(128, 0xAB), std::vector<std::uint8_t>(128, 0xCD), tok,
                             std::nullopt, std::nullopt);
  }
  if (routes.Quarantine().ActiveCount() != 66) return 70;
  for (std::uint16_t slot = 0; slot < 64; ++slot) {
    const auto tok = uring::MakeToken(slot, 0, nexora::kSocketSubsystemId, 1);
    if (!routes.Quarantine().TryRetire(tok, ring, -ECANCELED)) return 71;
  }
  if (routes.Quarantine().ActiveCount() != 2) return 72;

  // 2. Destroying SocketDmaQuarantine while slots are still active leaks pinned buffers (via LeakDmaBuffer) rather than
  // freeing.
  std::uint8_t* pinned_rx_ptr = nullptr;
  {
    nexora::CompletionRoutes<4> transient_routes{};
    std::vector<std::uint8_t> rx(64, 0x11);
    pinned_rx_ptr = rx.data();
    const auto tok = uring::MakeToken(1, 0, nexora::kSocketSubsystemId, 1);
    transient_routes.Quarantine().Park(888, -1, std::move(rx), std::vector<std::uint8_t>(64, 0x22), tok, std::nullopt,
                                       std::nullopt);
    if (transient_routes.Quarantine().ActiveCount() != 1) return 73;
  }
  // Simulated late kernel DMA write into the intentionally leaked buffer must NOT trigger ASan heap-use-after-free!
  pinned_rx_ptr[0] = 0x7F;
  return (pinned_rx_ptr[0] == 0x7F) ? 0 : 74;
}

int ConnectAcceptLoopback() noexcept {
  auto proactor = uring::Proactor::Create(64);
  auto listener = nexora::TcpListener::BindLoopbackV4(0);
  if (!proactor || !listener) return 80;
  const cares::Endpoint server_ep = listener->LocalEndpoint();

  int accepted_fd = -1;
  nexora::CompletionRoutes<8> routes{};
  auto cli = nexora::IoUringSocket::CreateTcpIpv4(nexora::SocketConfig{.rx_buffer_capacity = 64, .tx_buffer_capacity = 8});
  if (!cli || cli->TxBuffer().size() < sizeof(::sockaddr_storage)) return 81;
  cli->BindProactor(*proactor, routes);

  Consume(routes.Register(nexora::CompletionRoute::Make<nexora::kServerSubsystemId>(
      &accepted_fd, +[](void* ctx, nexora::CompletionEvent cqe) noexcept { *static_cast<int*>(ctx) = cqe.result; })));
  Consume(routes.Register(
      nexora::CompletionRoute::BindMethod<nexora::kSocketSubsystemId, nexora::IoUringSocket, &nexora::IoUringSocket::HandleCqe>(
          &*cli)));

  if (!listener->SubmitAccept(*proactor, nexora::kServerSubsystemId) || !cli->SubmitConnect(server_ep)) return 82;
  for (int i = 0; i < 16 && (accepted_fd < 0 || cli->Phase() != nexora::SocketPhase::kOpen); ++i) {
    Consume(proactor->Drive(uring::DriveMode::kWait, routes));
  }
  if (accepted_fd < 0 || cli->Phase() != nexora::SocketPhase::kOpen || cli->InFlightOps() != 0 ||
      cli->LastConnectResult() != 0) {
    if (accepted_fd >= 0) Consume(::close(accepted_fd));
    return 83;
  }
  Consume(::close(accepted_fd));
  cli->Quiesce();

  // Negative path: SubmitConnect to closed port transitions cleanly out of kConnecting to kCloseReady.
  listener->Close();
  nexora::CompletionRoutes<4> neg_routes{};
  auto cli_refused = nexora::IoUringSocket::CreateTcpIpv4();
  if (!cli_refused) return 84;
  cli_refused->BindProactor(*proactor, neg_routes);
  Consume(neg_routes.Register(
      nexora::CompletionRoute::BindMethod<nexora::kSocketSubsystemId, nexora::IoUringSocket, &nexora::IoUringSocket::HandleCqe>(
          &*cli_refused)));
  if (!cli_refused->SubmitConnect(server_ep)) return 85;
  for (int i = 0; i < 16 && cli_refused->InFlightOps() > 0; ++i) {
    Consume(proactor->Drive(uring::DriveMode::kWait, neg_routes));
  }
  if (cli_refused->LastConnectResult() >= 0 || cli_refused->Phase() != nexora::SocketPhase::kCloseReady ||
      cli_refused->InFlightOps() != 0) {
    return 86;
  }
  return 0;
}

}  // namespace

int main() {
  if (const int rc = CloseWaitsForInFlightOps(); rc != 0) return rc;
  if (const int rc = BufferRenewalWaitsForClose(); rc != 0) return rc;
  if (const int rc = CloseRetryAfterSqFull(); rc != 0) return rc;
  if (const int rc = RecvCancelBeforeClose(); rc != 0) return rc;
  if (const int rc = DrainKeepsSiblingCqes(); rc != 0) return rc;
  if (const int rc = DropKeepsKernelWrite(); rc != 0) return rc;
  if (const int rc = OverflowRetireWithoutUaf(); rc != 0) return rc;
  if (const int rc = ConnectAcceptLoopback(); rc != 0) return rc;
  return 0;
}
