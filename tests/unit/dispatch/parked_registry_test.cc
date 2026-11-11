#include <atomic>
#include <cstdint>
#include <nexora/dispatch/completion_routes.hpp>
#include <nexora/dispatch/parked_registry.hpp>
#include <thread>

namespace {

bool CountRetire(void* owner, uring::UserDataToken, std::uint64_t) noexcept {
  ++*static_cast<int*>(owner);
  return true;
}

int TestOverflowSwallowAndDestroyedOwner() noexcept {
  auto& registry = nexora::detail::SharedParkedRegistry();
  int calls = 0;
  for (std::uint16_t slot = 0; slot < nexora::detail::ParkedRegistry::kCapacity; ++slot) {
    const auto token = uring::MakeToken(static_cast<std::uint32_t>(slot + 1), 0, 9, 1);
    if (!registry.Register(token, 5, {&calls, &CountRetire})) return 1;
  }
  const auto overflow = uring::MakeToken(200, 0, 9, 1);
  if (registry.Register(overflow, 5, {&calls, &CountRetire})) return 2;
  if (!registry.Retire(overflow, 0) || calls != 0) return 3;
  for (std::uint16_t slot = 0; slot < nexora::detail::ParkedRegistry::kCapacity; ++slot) {
    const auto token = uring::MakeToken(static_cast<std::uint32_t>(slot + 1), 0, 9, 1);
    if (!registry.Retire(token, 5)) return 4;
  }
  if (calls != static_cast<int>(nexora::detail::ParkedRegistry::kCapacity)) return 5;

  const auto late = uring::MakeToken(3, 0, 9, 4);
  if (!registry.Register(late, 9, {&calls, &CountRetire})) return 6;
  registry.Unregister(late, 9);
  const int before = calls;
  nexora::CompletionRoutes<1> routes{};
  const uring::Delivery delivery{
      .key = {.token = late, .ring_instance = 0},
      .completion = {.token = late, .result = -125, .flags = 0},
  };
  if (!routes.Dispatch(delivery) || calls != before) return 7;
  if (routes.Dispatch(delivery)) return 8;
  return 0;
}

int TestThreadLocalRegistriesStayIsolated() noexcept {
  std::atomic<int> stage{0};
  const auto foreign = uring::MakeToken(8, 0, 9, 2);
  std::thread worker([&] {
    int local_calls = 0;
    auto& local = nexora::detail::SharedParkedRegistry();
    if (!local.Register(foreign, 22, {&local_calls, &CountRetire})) {
      stage.store(-1, std::memory_order_release);
      return;
    }
    stage.store(1, std::memory_order_release);
    while (stage.load(std::memory_order_acquire) == 1) {
      std::this_thread::yield();
    }
    if (stage.load(std::memory_order_acquire) < 0) return;
    if (!local.Retire(foreign, 22) || local_calls != 1) {
      stage.store(-2, std::memory_order_release);
      return;
    }
    stage.store(3, std::memory_order_release);
  });
  while (stage.load(std::memory_order_acquire) == 0) {
    std::this_thread::yield();
  }
  if (stage.load(std::memory_order_acquire) < 0) {
    worker.join();
    return 10;
  }
  if (nexora::detail::SharedParkedRegistry().Retire(foreign, 22)) {
    stage.store(-3, std::memory_order_release);
    worker.join();
    return 11;
  }
  stage.store(2, std::memory_order_release);
  worker.join();
  if (stage.load(std::memory_order_acquire) != 3) return 12;
  return 0;
}

}  // namespace

int main() {
  if (const int rc = TestOverflowSwallowAndDestroyedOwner(); rc != 0) return rc;
  if (const int rc = TestThreadLocalRegistriesStayIsolated(); rc != 0) return rc;
  return 0;
}
