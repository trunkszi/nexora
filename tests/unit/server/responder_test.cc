#include <nexora/server/service.hpp>
#include <optional>

int main() {
  nexora::ResponseChannel channel;
  auto responder = channel.Open(3);
  if (!responder) return 1;
  const auto handle = responder->Handle();
  if (!responder->Respond(nexora::Response::Ok("done"))) return 2;
  if (responder->Respond(nexora::Response::Ok())) return 3;
  auto reply = channel.Poll();
  if (!reply || reply->stream_id != 3 || reply->response.status.AsU16() != 200) return 4;
  if (channel.Poll()) return 5;
  auto abandoned = channel.Open();
  if (!abandoned) return 6;
  abandoned = std::unexpected(nexora::Error::Cancelled());
  reply = channel.Poll();
  if (!reply || reply->response.status.AsU16() != 500) return 7;
  auto stale = channel.Open();
  if (!stale) return 8;
  channel.Cancel(stale->Handle());
  auto replacement = channel.Open();
  if (!replacement || replacement->Handle() == stale->Handle()) return 9;
  if (stale->Respond(nexora::Response::Ok())) return 10;
  channel.Cancel(handle);
  if (!replacement->Respond(nexora::Response::Ok())) return 11;
  auto survivor = channel.Open();
  channel.Close();
  if (!survivor || survivor->Respond(nexora::Response::Ok())) return 12;
  return 0;
}
