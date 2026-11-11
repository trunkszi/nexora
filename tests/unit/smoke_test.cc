#include <openssl/sha.h>
#include <openssl/ssl.h>

#ifndef OPENSSL_IS_AWSLC
#error "nexora requires AWS-LC"
#endif

#include <array>
#include <cares/cares.hpp>
#include <cstdint>
#include <memory>
#include <uarch/uarch.hpp>
#include <uring/uring.hpp>

static_assert(cares::QueryHandle::Pack(1, 2, 3).raw == 0x0000000300020001ULL);
static_assert(uring::ErrorName(uring::UringErrorCode::kAgain) == "try again");
static_assert(uarch::arithmetic::divisor_u32<3>().rem(10) == 1);
#if defined(NEXORA_CODEGEN_PROBE)
extern "C" [[nodiscard]] std::uint32_t nexora_dependency_probe(std::uint32_t value) noexcept {
  return uarch::arithmetic::divisor_u32<3>().rem(value);
}
#else
int main() {
  const auto endpoint = cares::ParseEndpoint("https://127.0.0.1");
  if (!endpoint || endpoint->port != 443) return 1;
  if (cares::Error::BadName().Message().empty()) return 2;
  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(SSL_CTX_new(TLS_method()), SSL_CTX_free);
  if (!context || SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION) != 1) return 3;
  std::unique_ptr<SSL, decltype(&SSL_free)> session(SSL_new(context.get()), SSL_free);
  if (!session) return 4;
  constexpr std::array<unsigned char, 3> input{'a', 'b', 'c'};
  constexpr std::array<unsigned char, SHA256_DIGEST_LENGTH> expected{
      0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
      0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
  std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
  if (SHA256(input.data(), input.size(), digest.data()) == nullptr || digest != expected) return 5;
  return 0;
}
#endif
