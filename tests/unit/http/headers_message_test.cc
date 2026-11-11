#include <array>
#include <cstdlib>
#include <nexora/http/headers.hpp>
#include <nexora/http/message.hpp>
#include <string>
#include <string_view>
#include <utility>

namespace {

void Check(bool condition) noexcept {
  if (!condition) {
    std::abort();
  }
}

void TestHeaderReplacementAndRemoval() {
  nexora::Headers<8> headers;
  Check(headers.Append("X-Token", "old").has_value());
  Check(headers.Append("Set-Cookie", "a=1").has_value());
  Check(headers.Append("x-TOKEN", "duplicate").has_value());
  Check(headers.Append("SET-COOKIE", "b=2").has_value());

  const auto cookies = headers.GetAll("set-COOKIE");
  Check(cookies.size() == 2 && cookies[0] == "a=1" && cookies[1] == "b=2");

  Check(headers.Insert("X-TOKEN", "new").has_value());
  const auto tokens = headers.GetAll("x-token");
  Check(tokens.size() == 1 && tokens[0] == "new");
  Check(headers.Get("X-TOKEN") == "new");

  const auto fields = headers.Fields();
  Check(fields.size() == 3);
  Check(fields[0].name == "x-token");
  Check(fields[1].name == "set-cookie");
  Check(fields[2].name == "set-cookie");

  const auto removed = headers.Remove("SET-cookie");
  Check(removed.has_value() && *removed == "a=1");
  Check(!headers.Contains("set-cookie"));
  Check(headers.Size() == 1);
  Check(headers.ByteSize() == std::string_view("x-token").size() + std::string_view("new").size());
  Check(!headers.Remove("absent").has_value());

  const nexora::Headers<8> retained = headers;
  headers.Clear();
  Check(headers.Empty());
  Check(retained.Get("x-token") == "new");

  Check(!headers.Add("Bad Name", "val").has_value());
  Check(!headers.Add("x-ok", "bad\r\nval").has_value());

  // Large real-world headers: 2048-byte JWT Authorization and 4096-byte Cookie header.
  const std::string jwt_val = "Bearer " + std::string(2041, 'J');
  const std::string cookie_val = "session=" + std::string(4088, 'C');
  Check(jwt_val.size() == 2048);
  Check(cookie_val.size() == 4096);
  Check(headers.Set("Authorization", jwt_val).has_value());
  Check(headers.Add("Cookie", cookie_val).has_value());
  Check(headers.Get("authorization") == jwt_val);
  Check(headers.Get("COOKIE") == cookie_val);
  nexora::Headers<8> moved_hdrs = std::move(headers);
  Check(moved_hdrs.Get("authorization") == jwt_val);
  Check(moved_hdrs.Get("cookie") == cookie_val);

  // Exceeding 8192-byte value limit returns kBufferOverflow.
  const std::string oversize_val(8193, 'X');
  Check(!moved_hdrs.Add("X-Too-Big", oversize_val).has_value());

  nexora::Headers<2> small;
  Check(small.Add("a", "1").has_value());
  Check(small.Add("b", "2").has_value());
  Check(!small.Add("c", "3").has_value());
}

void TestContentLengthValidation() noexcept {
  nexora::Headers<> headers;
  auto empty_cl = headers.ContentLength();
  Check(empty_cl.has_value() && !empty_cl->has_value());

  Check(headers.Append("Content-Length", " 5,\t005 ").has_value());
  Check(headers.Append("CONTENT-LENGTH", "5").has_value());
  auto valid_cl = headers.ContentLength();
  Check(valid_cl.has_value() && valid_cl->has_value() && **valid_cl == 5U);

  Check(headers.Append("content-length", "6").has_value());
  Check(!headers.ContentLength().has_value());

  constexpr std::array<std::string_view, 9> malformed{{
      "",
      " ",
      "+5",
      "-1",
      "0x10",
      "1 2",
      "1,",
      ",1",
      "99999999999999999999999999999999999999",
  }};
  for (std::string_view bad : malformed) {
    nexora::Headers<> h;
    Check(h.Append("content-length", bad).has_value());
    Check(!h.ContentLength().has_value());
  }
}

void TestTransferCodingChunked() noexcept {
  nexora::Headers<> headers;
  constexpr std::array<std::string_view, 5> not_chunked{{
      "xchunked",
      "chunkedx",
      "chunked;foo=bar",
      "chunked, gzip",
      "chunked,",
  }};
  for (std::string_view v : not_chunked) {
    Check(headers.Set("Transfer-Encoding", v).has_value());
    Check(!headers.IsChunked());
  }
  Check(headers.Set("TRANSFER-ENCODING", "gzip").has_value());
  Check(headers.Append("transfer-encoding", "\tChUnKeD ").has_value());
  Check(headers.IsChunked());
  Check(headers.Append("transfer-encoding", "identity").has_value());
  Check(!headers.IsChunked());
}

void TestMessagesAndStatusCodes() noexcept {
  for (nexora::Method m :
       {nexora::Method::kGet, nexora::Method::kPost, nexora::Method::kPut, nexora::Method::kDelete, nexora::Method::kHead,
        nexora::Method::kOptions, nexora::Method::kPatch, nexora::Method::kConnect, nexora::Method::kTrace}) {
    auto parsed = nexora::ParseMethod(nexora::MethodAsStr(m));
    Check(parsed.has_value() && *parsed == m);
  }
  Check(!nexora::ParseMethod("get").has_value());

  Check(nexora::StatusCode::FromU16(200).has_value());
  Check(!nexora::StatusCode::FromU16(99).has_value());
  Check(!nexora::StatusCode::FromU16(600).has_value());
  Check(nexora::StatusCode{101}.IsInformational());
  Check(nexora::StatusCode{204}.IsSuccess());
  Check(nexora::StatusCode{302}.IsRedirection());
  Check(nexora::StatusCode{404}.IsClientError());
  Check(nexora::StatusCode{503}.IsServerError());
  Check(nexora::StatusCode{200}.Code() == 200);
  Check(nexora::StatusCode{200}.ReasonPhrase() == "OK");

  auto req = nexora::Request::Post("https://example.test/v1/write?db=public", "payload");
  Check(req.has_value());
  Check(req->SetHeader("X-Request-Id", "42").has_value());
  Check(req->method == nexora::Method::kPost);
  Check(req->uri.PathAndQuery() == "/v1/write?db=public");
  Check(req->headers.Get("x-request-id") == "42");
  Check(req->body.AsStringView() == "payload");

  nexora::Response resp = nexora::Response::Ok("accepted");
  Check(resp.SetHeader("Content-Type", "text/plain").has_value());
  Check(resp.status == nexora::StatusCode{200});
  Check(resp.body.AsStringView() == "accepted");

  const auto checked_hdrs = nexora::MakeHeaders({
      {"x-service", "nexora"},
      {"content-type", "application/grpc"},
  });
  Check(checked_hdrs.has_value());
  Check(checked_hdrs->Get("X-Service") == "nexora");

  const auto overflow_hdrs = nexora::MakeHeaders<1>({
      {"x-service", "nexora"},
      {"content-type", "application/grpc"},
  });
  Check(!overflow_hdrs.has_value());
  Check(overflow_hdrs.error().code == static_cast<std::int32_t>(std::to_underlying(nexora::ProtoErrorCode::kBufferOverflow)));

  const auto h2_hdrs = nexora::MakeHttp2Headers({
      {":method", "POST"},
      {":path", "/greptime.v1.GreptimeDatabase/Handle"},
  });
  Check(h2_hdrs.has_value());
  Check(h2_hdrs->size() == 2 && (*h2_hdrs)[0].name == ":method");

  const auto overflow_h2 = nexora::MakeHttp2Headers<1>({
      {":method", "POST"},
      {":path", "/greptime.v1.GreptimeDatabase/Handle"},
  });
  Check(!overflow_h2.has_value());
  Check(overflow_h2.error().code == static_cast<std::int32_t>(std::to_underlying(nexora::ProtoErrorCode::kBufferOverflow)));
}

}  // namespace

int main() {
  TestHeaderReplacementAndRemoval();
  TestContentLengthValidation();
  TestTransferCodingChunked();
  TestMessagesAndStatusCodes();
  return 0;
}
