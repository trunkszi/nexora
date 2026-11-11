#include <chrono>
#include <cstdint>
#include <nexora/dispatch/completion_routes.hpp>
#include <nexora/inbox/inbox.hpp>
#include <string>
#include <vector>

namespace {

int ReenterSubmitCancelTimerWs() noexcept {
  nexora::SubsystemInbox inbox{};
  nexora::ClientContext ctx = inbox.Context();
  const auto ws_session = inbox.AllocateWebSocketSessionId();
  if (ws_session.Raw() != 1) {
    return 1;
  }

  std::vector<std::string> trace{};
  auto outer_ctx = ctx.Clone();
  auto req1 = nexora::Request::Get("https://api.example.com/v1/First");
  if (!req1) {
    return 2;
  }

  auto first_id = ctx.Submit(std::move(*req1), [&](nexora::Result<nexora::Response> res) noexcept {
    if (!res) {
      return;
    }
    trace.push_back("first:" + std::to_string(res->status.code()));

    auto follow_req = nexora::Request::Get("https://api.example.com/v1/second");
    if (!follow_req) {
      return;
    }
    auto second_id = outer_ctx.Submit(std::move(*follow_req), [&](nexora::Result<nexora::Response> res2) noexcept {
      if (res2) {
        trace.push_back("second:" + std::to_string(res2->status.code()));
      }
    });
    if (!second_id) {
      return;
    }
    if (const auto cancelled = outer_ctx.Cancel(*second_id); !cancelled) return;
    auto timer_id = outer_ctx.ArmTimer(std::chrono::milliseconds(15), [&](nexora::ClientContext& timer_ctx) noexcept {
      trace.emplace_back("timer");
      if (const auto sent = timer_ctx.SendWs(ws_session, nexora::MakeWebSocketText("from-timer")); !sent) return;
      if (const auto closed = timer_ctx.CloseWs(ws_session, nexora::WebSocketCloseFrame{.code = 1000, .reason = "done"});
          !closed)
        return;
    });
    if (timer_id) {
      if (const auto cancelled = outer_ctx.CancelTimer(*timer_id); !cancelled) return;
    }
  });
  if (!first_id || first_id->Raw() != 1 || inbox.Size() != 1) {
    return 3;
  }

  auto first_cmd = inbox.Pop();
  if (!first_cmd || first_cmd->kind != nexora::InboxCommand::Kind::kSubmit) {
    return 4;
  }
  first_cmd->response_callback(nexora::Response::Ok("one"));

  // Re-entrant operations staged 4 commands in FIFO order.
  if (inbox.Size() != 4) {
    return 5;
  }

  auto second_cmd = inbox.Pop();
  if (!second_cmd || second_cmd->kind != nexora::InboxCommand::Kind::kSubmit || second_cmd->request_id.Raw() != 2) {
    return 6;
  }
  second_cmd->response_callback(nexora::Response::WithStatus(nexora::StatusCode{201}, {}));

  auto cancel_cmd = inbox.Pop();
  if (!cancel_cmd || cancel_cmd->kind != nexora::InboxCommand::Kind::kCancel || cancel_cmd->request_id.Raw() != 2) {
    return 7;
  }

  auto arm_cmd = inbox.Pop();
  if (!arm_cmd || arm_cmd->kind != nexora::InboxCommand::Kind::kArmTimer || arm_cmd->timer_id.Raw() != 1) {
    return 8;
  }
  arm_cmd->timer_callback(ctx);

  auto cancel_timer_cmd = inbox.Pop();
  if (!cancel_timer_cmd || cancel_timer_cmd->kind != nexora::InboxCommand::Kind::kCancelTimer ||
      cancel_timer_cmd->timer_id.Raw() != 1) {
    return 9;
  }

  auto ws_send = inbox.Pop();
  if (!ws_send || ws_send->kind != nexora::InboxCommand::Kind::kSendWebSocket || ws_send->session_id != ws_session) {
    return 10;
  }

  auto ws_close = inbox.Pop();
  if (!ws_close || ws_close->kind != nexora::InboxCommand::Kind::kCloseWebSocket || ws_close->session_id != ws_session) {
    return 11;
  }

  if (!inbox.Empty() || trace.size() != 3 || trace[0] != "first:200" || trace[1] != "second:201" || trace[2] != "timer") {
    return 12;
  }
  return 0;
}

int CloseDrainsQueuedSubmits() noexcept {
  nexora::SubsystemInbox inbox{};
  nexora::ClientContext ctx = inbox.Context();

  bool got_cancelled = false;
  auto req = nexora::Request::Get("https://api.example.com/v1/pending");
  if (!req) {
    return 20;
  }
  auto submit_id = ctx.Submit(std::move(*req), [&](nexora::Result<nexora::Response> res) noexcept {
    if (!res && res.error() == nexora::Error::Cancelled()) {
      got_cancelled = true;
    }
  });
  if (!submit_id) {
    return 21;
  }

  inbox.Close();
  if (inbox.State() != nexora::InboxState::kClosed || !inbox.Empty() || !got_cancelled) {
    return 22;
  }

  auto late_req = nexora::Request::Get("https://api.example.com/v1/late");
  auto late = ctx.Submit(std::move(*late_req), [](nexora::Result<nexora::Response>) noexcept {});
  if (late.has_value() || late.error() != nexora::Error::FromRuntime(nexora::RuntimeErrorCode::kInvalidState)) {
    return 23;
  }
  return 0;
}

int DropLastHandleCancelsSubmits() noexcept {
  bool got_cancelled = false;
  nexora::ClientContext surviving_ctx{};
  {
    nexora::SubsystemInbox inbox{};
    nexora::ClientContext ctx = inbox.Context();
    surviving_ctx = ctx.Clone();
    auto req = nexora::Request::Get("https://api.example.com/v1/drop");
    if (!req) {
      return 30;
    }
    // Capture ctx by value inside the queued callback to verify zero reference-counting cycle!
    auto id = ctx.Submit(std::move(*req), [ctx, &got_cancelled](nexora::Result<nexora::Response> res) noexcept {
      static_cast<void>(ctx);
      if (!res && res.error() == nexora::Error::Cancelled()) {
        got_cancelled = true;
      }
    });
    if (!id) {
      return 31;
    }
  }
  if (!got_cancelled) {
    return 32;
  }
  auto post_drop_req = nexora::Request::Get("https://api.example.com/v1/after_drop");
  auto post_drop = surviving_ctx.Submit(std::move(*post_drop_req), [](nexora::Result<nexora::Response>) noexcept {});
  if (post_drop.has_value() || post_drop.error() != nexora::Error::FromRuntime(nexora::RuntimeErrorCode::kInvalidState)) {
    return 33;
  }
  return 0;
}

}  // namespace

int main() {
  if (const int rc = ReenterSubmitCancelTimerWs(); rc != 0) {
    return rc;
  }
  if (const int rc = CloseDrainsQueuedSubmits(); rc != 0) {
    return rc;
  }
  if (const int rc = DropLastHandleCancelsSubmits(); rc != 0) {
    return rc;
  }
  return 0;
}
