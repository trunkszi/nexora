#pragma once
#include <cstddef>
#include <cstdint>
#include <utility>

#if !defined(__x86_64__)
#error "the minimal gem5 guest requires the x86-64 Linux syscall ABI"
#endif

asm(".text\n.global _start\n.type _start,@function\n_start:\n"
    "xor %ebp,%ebp\nmov (%rsp),%rdi\nlea 8(%rsp),%rsi\nand $-16,%rsp\n"
    "call main\nmov %eax,%edi\nmov $231,%eax\nsyscall\nud2\n.size _start,.-_start\n");

inline void NexoraGuestWrite(const char* bytes, std::size_t length) noexcept {
  while (length != 0) {
    long written = 0;
    asm volatile("syscall" : "=a"(written) : "a"(1L), "D"(1L), "S"(bytes), "d"(length) : "rcx", "r11", "memory");
    if (written == -4) continue;
    if (written <= 0) return;
    bytes += written;
    length -= static_cast<std::size_t>(written);
  }
}
void FreestandingAbort() noexcept asm("abort");
[[gnu::used]] void FreestandingAbort() noexcept {
  asm volatile("syscall" : : "a"(231L), "D"(127L) : "rcx", "r11", "memory");
  std::unreachable();
}
std::size_t FreestandingStrlen(const char* text) noexcept asm("strlen");
[[gnu::used]] std::size_t FreestandingStrlen(const char* text) noexcept {
  std::size_t length = 0;
  while (text[length] != '\0') {
    asm volatile("" ::: "memory");
    ++length;
  }
  return length;
}
void* FreestandingMemcpy(void* destination, const void* source, std::size_t count) noexcept asm("memcpy");
[[gnu::used]] void* FreestandingMemcpy(void* destination, const void* source, std::size_t count) noexcept {
  auto* out = static_cast<unsigned char*>(destination);
  const auto* in = static_cast<const unsigned char*>(source);
  for (std::size_t index = 0; index < count; ++index) {
    asm volatile("" ::: "memory");
    out[index] = in[index];
  }
  return destination;
}
void* FreestandingMemset(void* destination, int value, std::size_t count) noexcept asm("memset");
[[gnu::used]] void* FreestandingMemset(void* destination, int value, std::size_t count) noexcept {
  auto* out = static_cast<unsigned char*>(destination);
  for (std::size_t index = 0; index < count; ++index) {
    asm volatile("" ::: "memory");
    out[index] = static_cast<unsigned char>(value);
  }
  return destination;
}
void* FreestandingMemmove(void* destination, const void* source, std::size_t count) noexcept asm("memmove");
[[gnu::used]] void* FreestandingMemmove(void* destination, const void* source, std::size_t count) noexcept {
  auto* out = static_cast<unsigned char*>(destination);
  const auto* in = static_cast<const unsigned char*>(source);
  if (reinterpret_cast<std::uintptr_t>(out) < reinterpret_cast<std::uintptr_t>(in))
    return FreestandingMemcpy(destination, source, count);
  while (count != 0) {
    asm volatile("" ::: "memory");
    --count;
    out[count] = in[count];
  }
  return destination;
}
int FreestandingMemcmp(const void* lhs, const void* rhs, std::size_t count) noexcept asm("memcmp");
[[gnu::used]] int FreestandingMemcmp(const void* lhs, const void* rhs, std::size_t count) noexcept {
  const auto* left = static_cast<const unsigned char*>(lhs);
  const auto* right = static_cast<const unsigned char*>(rhs);
  for (std::size_t index = 0; index < count; ++index) {
    asm volatile("" ::: "memory");
    if (left[index] != right[index]) return static_cast<int>(left[index]) - static_cast<int>(right[index]);
  }
  return 0;
}
