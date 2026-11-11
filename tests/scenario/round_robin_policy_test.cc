#include <array>
#include <cstdlib>
#include <nexora/pool/endpoint_failover.hpp>

namespace {
constexpr auto kPolicy = nexora::EndpointSelectionPolicy::kRoundRobin;
constexpr std::array<cares::Endpoint, 3> kEndpoints{{
    {cares::IpAddress::FromV4({192, 0, 2, 1}), 80},
    {cares::IpAddress::FromV4({192, 0, 2, 2}), 80},
    {cares::IpAddress::FromV4({192, 0, 2, 3}), 80},
}};
consteval bool PolicyHandlesReadinessAndRecovery() {
  nexora::EndpointFailover<3> pool{
      kEndpoints, nexora::EndpointFailoverConfig{.failure_threshold = 1, .base_cooldown_ns = 100, .max_cooldown_ns = 100}};
  if (pool.SelectNext<kPolicy>(1) != 0 || pool.SelectNext<kPolicy>(1) != 1 || pool.SelectNext<kPolicy>(1) != 2) return false;
  pool.MarkFailure(1, 10);
  if (pool.SelectNext<kPolicy>(20) != 0 || pool.SelectNext<kPolicy>(20) != 2) return false;
  pool.SetReady(0, false);
  pool.SetReady(2, false);
  auto unavailable = pool.SelectNext<kPolicy>(20);
  if (unavailable || unavailable.error() != nexora::Error::FromRuntime(nexora::RuntimeErrorCode::kAllEndpointsUnhealthy))
    return false;
  if (pool.SelectNext<kPolicy>(110) != 1) return false;
  return pool.FailureCount(1) == 1 && pool.QuarantinedUntilNs(1) == 0;
}
static_assert(PolicyHandlesReadinessAndRecovery());
void Check(bool value) {
  if (!value) std::abort();
}
}  // namespace
int main() {
  unsigned events = 0;
  nexora::EndpointFailover<3> observed{
      kEndpoints, nexora::EndpointFailoverConfig{.observer = [&events](const nexora::FailoverEvent&) noexcept { ++events; }}};
  auto invalid = observed.SelectNext<kPolicy>(1);
  Check(!invalid && invalid.error() == nexora::Error::InvalidArgument());
  observed.MarkFailure(0, 10);
  Check(events == 1 && observed.SelectNext(11) == 1);
  Check(observed.SelectNext(1'000'000'010) == 2 && events == 2);
  nexora::EndpointFailover<3> pick_first{kEndpoints,
                                         nexora::EndpointFailoverConfig{.policy = nexora::EndpointSelectionPolicy::kPickFirst}};
  invalid = pick_first.SelectNext<kPolicy>(1);
  Check(!invalid && invalid.error() == nexora::Error::InvalidArgument());
  Check(pick_first.SelectNext(1) == 0 && pick_first.SelectNext(1) == 0);
  nexora::EndpointFailover<3> empty;
  auto unavailable = empty.SelectNext<kPolicy>(1);
  Check(!unavailable && unavailable.error() == nexora::Error::FromRuntime(nexora::RuntimeErrorCode::kAllEndpointsUnhealthy));
}
