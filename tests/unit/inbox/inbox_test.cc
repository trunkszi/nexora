#include <chrono>
#include <cstdint>
#include <nexora/inbox/inbox.hpp>
#include <optional>

namespace {

int TestGenericRingSubsystemInbox() noexcept {
  nexora::SubsystemInbox<int, 4> ring{};
  if (!ring.Empty() || ring.Size() != 0) {
    return 1;
  }
  if (!ring.Push(10) || !ring.Push(20) || !ring.Push(30) || !ring.Push(40)) {
    return 2;
  }
  if (ring.Push(50)) {
    return 3;
  }
  if (ring.Size() != 4 || ring.Empty()) {
    return 4;
  }
  if (ring.Pop() != 10 || ring.Pop() != 20) {
    return 5;
  }
  if (!ring.Push(50) || !ring.Push(60) || ring.Push(70)) {
    return 6;
  }
  if (ring.Pop() != 30 || ring.Pop() != 40 || ring.Pop() != 50 || ring.Pop() != 60 || ring.Pop().has_value()) {
    return 7;
  }
  return ring.Empty() ? 0 : 8;
}

int TestIdLayoutsAndMasking() noexcept {
  constexpr nexora::RequestId req_id{42};
  constexpr nexora::TimerId timer_id{99};
  static_assert(req_id.Raw() == 42);
  static_assert(timer_id.Raw() == 99);

  constexpr std::uint64_t unmasked = (std::uint64_t{0xFFF} << 52) | 0x12345ULL;
  constexpr nexora::WebSocketSessionId ws_id{unmasked};
  static_assert(ws_id.Raw() == 0x12345ULL);

  nexora::SubsystemInbox inbox{};
  const auto s1 = inbox.AllocateWebSocketSessionId();
  const auto s2 = inbox.AllocateWebSocketSessionId();
  if (s1.Raw() != 1 || s2.Raw() != 2) {
    return 9;
  }
  return 0;
}

int TestStageAndPopAllCommandVariants() noexcept {
  nexora::SubsystemInbox inbox{};
  nexora::ClientContext ctx = inbox.Context();
  if (inbox.State() != nexora::InboxState::kOpen || !inbox.Empty()) {
    return 10;
  }

  auto req = nexora::Request::Get("https://example.com/v1/orders");
  if (!req) {
    return 11;
  }
  std::optional<nexora::Result<nexora::Response>> got_resp{};
  auto req_id = ctx.Submit(std::move(*req), [&](nexora::Result<nexora::Response> res) noexcept { got_resp = std::move(res); });
  if (!req_id || req_id->Raw() != 1) {
    return 12;
  }

  if (!ctx.Cancel(*req_id)) {
    return 13;
  }

  bool timer_fired = false;
  auto timer_id = ctx.ArmTimer(std::chrono::milliseconds(25), [&](nexora::ClientContext&) noexcept { timer_fired = true; });
  if (!timer_id || timer_id->Raw() != 1) {
    return 14;
  }

  if (!ctx.CancelTimer(*timer_id)) {
    return 15;
  }

  const auto ws_id = inbox.AllocateWebSocketSessionId();
  if (!ctx.SendWs(ws_id, nexora::MakeWebSocketText("hello"))) {
    return 16;
  }
  if (!ctx.CloseWs(ws_id, nexora::WebSocketCloseFrame{.code = 1000, .reason = "bye"})) {
    return 17;
  }

  if (inbox.Size() != 6) {
    return 18;
  }

  auto c1 = inbox.Pop();
  if (!c1 || c1->kind != nexora::InboxCommand::Kind::kSubmit || c1->request_id != *req_id) {
    return 19;
  }
  c1->response_callback(nexora::Response::Ok("filled"));
  if (!got_resp || !got_resp->has_value() || (*got_resp)->status.code() != 200) {
    return 20;
  }

  auto c2 = inbox.Pop();
  if (!c2 || c2->kind != nexora::InboxCommand::Kind::kCancel || c2->request_id != *req_id) {
    return 21;
  }

  auto c3 = inbox.Pop();
  if (!c3 || c3->kind != nexora::InboxCommand::Kind::kArmTimer || c3->timer_id != *timer_id) {
    return 22;
  }
  c3->timer_callback(ctx);
  if (!timer_fired) {
    return 23;
  }

  auto c4 = inbox.Pop();
  if (!c4 || c4->kind != nexora::InboxCommand::Kind::kCancelTimer || c4->timer_id != *timer_id) {
    return 24;
  }

  auto c5 = inbox.Pop();
  if (!c5 || c5->kind != nexora::InboxCommand::Kind::kSendWebSocket || c5->session_id != ws_id) {
    return 25;
  }

  auto c6 = inbox.Pop();
  if (!c6 || c6->kind != nexora::InboxCommand::Kind::kCloseWebSocket || c6->session_id != ws_id || !c6->ws_close.has_value() ||
      c6->ws_close->code != 1000) {
    return 26;
  }

  if (!inbox.Empty()) {
    return 27;
  }
  return 0;
}

}  // namespace

int main() {
  if (const int rc = TestGenericRingSubsystemInbox(); rc != 0) {
    return rc;
  }
  if (const int rc = TestIdLayoutsAndMasking(); rc != 0) {
    return rc;
  }
  if (const int rc = TestStageAndPopAllCommandVariants(); rc != 0) {
    return rc;
  }
  return 0;
}
