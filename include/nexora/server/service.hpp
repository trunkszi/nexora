#pragma once

#include <array>
#include <cares/channel/socket_bridge.hpp>
#include <cares/types/endpoint.hpp>
#include <cstdint>
#include <limits>
#include <memory>
#include <nexora/error/runtime_error.hpp>
#include <nexora/http/message.hpp>
#include <optional>
#include <string_view>
#include <type_traits>
#include <uarch/primitives.hpp>
#include <utility>

namespace nexora {
struct RequestContext {
  std::string_view target{};
  std::optional<cares::Endpoint> peer{};
  Version version{Version::kHttp11};
  std::uint32_t stream_id{0};
  std::uint64_t request_id{0};
};

struct ServerRequestHandle {
  using Word = std::uint64_t;
  std::uint32_t slot[[= uarch::bits::Field{0, 32}]] = 0;
  std::uint32_t generation[[= uarch::bits::Field{32, 32}]] = 0;
  [[nodiscard]] constexpr std::uint64_t Raw() const noexcept;
  constexpr bool operator==(const ServerRequestHandle&) const noexcept = default;
};
static_assert(uarch::NoPadding<ServerRequestHandle> && uarch::RegisterPassable<ServerRequestHandle>);

inline constexpr std::uint64_t ServerRequestHandle::Raw() const noexcept {
  return uarch::BitWord<ServerRequestHandle>{}
      .with<^^ServerRequestHandle::slot>(slot)
      .with<^^ServerRequestHandle::generation>(generation)
      .raw();
}

namespace detail {
struct ResponseSlotSpec {
  using Word = std::uint64_t;
  bool active[[= uarch::bits::Flag{0}]];
  std::uint32_t generation[[= uarch::bits::Field{32, 32}]];
};
struct ResponseCell {
  uarch::BitWord<ResponseSlotSpec> word{};
  std::uint32_t stream_id{0};
  std::optional<Response> response{};
};
struct ResponseState {
  std::array<ResponseCell, 64> cells{};
  uarch::Bitmap64 occupied{};
  uarch::Bitmap64 ready{};
  std::uint64_t references{1};
  bool alive{true};

  // NOLINTNEXTLINE(readability-convert-member-functions-to-static) -- stock clang-tidy lacks <meta> for BitWord cells.
  [[nodiscard]] bool Active(ServerRequestHandle handle) const noexcept {
    if (!alive || handle.slot >= cells.size()) return false;
    const auto& word = cells[handle.slot].word;
    return word.test<^^ResponseSlotSpec::active>() && word.get<^^ResponseSlotSpec::generation>() == handle.generation;
  }
  void Release() noexcept {
    if (--references == 0) {
      std::allocator<ResponseState> allocator;
      std::destroy_at(this);
      allocator.deallocate(this, 1);
    }
  }
  void Retire(std::uint32_t slot) noexcept {
    auto& cell = cells[slot];
    cell.word = cell.word.with<^^ResponseSlotSpec::active>(false);
    cell.response.reset();
    ready = ready.clear(slot);
    // Retiring exhausted generations prevents a retained responder from matching a reused slot.
    if (cell.word.get<^^ResponseSlotSpec::generation>() != std::numeric_limits<std::uint32_t>::max())
      occupied = occupied.clear(slot);
  }
};
}  // namespace detail

class ResponseChannel;
class Responder {
  detail::ResponseState* state_{nullptr};
  ServerRequestHandle handle_{};
  friend class ResponseChannel;
  Responder(detail::ResponseState* state, ServerRequestHandle handle) noexcept : state_(state), handle_(handle) {
    ++state_->references;
  }
  void Release() noexcept {
    if (state_ != nullptr) std::exchange(state_, nullptr)->Release();
  }

 public:
  Responder() noexcept = default;
  Responder(const Responder&) = delete ("single-owner one-shot response handle; move instead");
  Responder& operator=(const Responder&) = delete ("single-owner one-shot response handle; move instead");
  Responder(Responder&& other) noexcept : state_(std::exchange(other.state_, nullptr)), handle_(other.handle_) {}
  Responder& operator=(Responder&& other) noexcept {
    if (this != &other) {
      Abandon();
      state_ = std::exchange(other.state_, nullptr);
      handle_ = other.handle_;
    }
    return *this;
  }
  ~Responder() noexcept { Abandon(); }
  [[nodiscard]] ServerRequestHandle Handle() const noexcept { return handle_; }
  [[nodiscard]] bool IsClosed() const noexcept { return state_ == nullptr || !state_->Active(handle_); }
  [[nodiscard]] Result<void> Respond(Response response) noexcept {
    if (IsClosed()) {
      Release();
      return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    }
    auto& cell = state_->cells[handle_.slot];
    cell.word = cell.word.with<^^detail::ResponseSlotSpec::active>(false);
    cell.response.emplace(std::move(response));
    state_->ready = state_->ready.set(handle_.slot);
    Release();
    return {};
  }

 private:
  void Abandon() noexcept {
    if (!IsClosed()) {
      [[maybe_unused]] const auto sent = Respond(Response::WithStatus(StatusCode{500}));
    }
    Release();
  }
};

struct ServerReply {
  ServerRequestHandle handle{};
  std::uint32_t stream_id{0};
  Response response{};
};

class ResponseChannel {
  detail::ResponseState* state_{nullptr};

 public:
  ResponseChannel() noexcept {
    std::allocator<detail::ResponseState> allocator;
    state_ = allocator.allocate(1);
    std::construct_at(state_);
  }
  ResponseChannel(const ResponseChannel&) = delete ("single-owner server response channel; move instead");
  ResponseChannel& operator=(const ResponseChannel&) = delete ("single-owner server response channel; move instead");
  ResponseChannel(ResponseChannel&& other) noexcept : state_(std::exchange(other.state_, nullptr)) {}
  ResponseChannel& operator=(ResponseChannel&& other) noexcept {
    if (this != &other) {
      Close();
      state_ = std::exchange(other.state_, nullptr);
    }
    return *this;
  }
  ~ResponseChannel() noexcept { Close(); }
  [[nodiscard]] Result<Responder> Open(std::uint32_t stream_id = 0) noexcept {
    if (state_ == nullptr || !state_->alive) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kConnectionClosed));
    const auto slot = state_->occupied.lowest_zero();
    if (!slot) return std::unexpected(Error::FromRuntime(RuntimeErrorCode::kPoolExhausted));
    auto& cell = state_->cells[*slot];
    const auto generation = cell.word.get<^^detail::ResponseSlotSpec::generation>() + 1U;
    cell.word =
        cell.word.with<^^detail::ResponseSlotSpec::generation>(generation).with<^^detail::ResponseSlotSpec::active>(true);
    cell.stream_id = stream_id;
    state_->occupied = state_->occupied.set(*slot);
    return Responder(state_, {*slot, generation});
  }
  void Cancel(ServerRequestHandle handle) noexcept {
    if (state_ != nullptr && handle.slot < 64 &&
        state_->cells[handle.slot].word.get<^^detail::ResponseSlotSpec::generation>() == handle.generation)
      state_->Retire(handle.slot);
  }
  [[nodiscard]] std::optional<ServerReply> Poll() noexcept {
    if (state_ == nullptr) return std::nullopt;
    const auto slot = state_->ready.lowest_one();
    if (!slot) return std::nullopt;
    auto& cell = state_->cells[*slot];
    ServerReply reply{
        {*slot, cell.word.get<^^detail::ResponseSlotSpec::generation>()}, cell.stream_id, std::move(*cell.response)};
    state_->ready = state_->ready.clear(*slot);
    cell.response.reset();
    return reply;
  }
  void Complete(ServerRequestHandle handle) noexcept { Cancel(handle); }
  void Close() noexcept {
    if (state_ == nullptr) return;
    state_->alive = false;
    state_->ready = uarch::Bitmap64::empty();
    for (auto& cell : state_->cells) cell.response.reset();
    std::exchange(state_, nullptr)->Release();
  }
};

class HttpService {
  using Handler = cares::Delegate<Result<void>(RequestContext&, Request, Responder)>;
  Handler handler_{};

 public:
  HttpService() noexcept = default;
  explicit HttpService(Handler handler) noexcept : handler_(handler) {}
  template <auto Method, typename Service>
  [[nodiscard]] static HttpService Bind(Service& service) noexcept {
    static_assert(std::is_nothrow_invocable_r_v<Result<void>, decltype(Method), Service&, RequestContext&, Request, Responder>);
    return HttpService(Handler::template Bind<Method>(&service));
  }
  [[nodiscard]] Result<void> Call(RequestContext& context, Request request, Responder responder) const noexcept {
    if (!handler_) return responder.Respond(Response::WithStatus(StatusCode{404}));
    return handler_(context, std::move(request), std::move(responder));
  }
};
}  // namespace nexora
