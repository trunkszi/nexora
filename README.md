# nexora

C++26 Sans-IO and Proactor library for HTTP/1.1, HTTP/2, TLS 1.3, WebSocket, and byte transports. Protocol codecs operate on byte buffers. Native client and server drivers take a caller-owned `uring::Proactor`. Name lookup takes a `cares::Resolver<>`. TLS uses AWS-LC.

Requirements: Linux x86-64, a C++26 compiler with P2996 reflection, CMake 4.0 or newer, Ninja, and AWS-LC. Presets resolve dependencies in vcpkg manifest mode with `VCPKG_OVERLAY_PORTS=$HOME/.local/vcpkg`.

```sh
./nexora build --preset clang-glibc-release
./nexora test --preset clang-glibc-release
./nexora verify --preset clang-glibc-release
```

Use `find_package(nexora CONFIG REQUIRED)` and link `nexora::nexora`, or select `nexora::http1`, `nexora::http2`, `nexora::websocket`, `nexora::client`, or `nexora::server`. Include `<nexora/nexora.hpp>` for the complete API. Consumers need the same reflection-capable C++26 toolchain and standard-library ABI.

```cpp
#include <nexora/nexora.hpp>

int main() {
  auto request = nexora::Request::Get("https://example.com/");
  if (!request) return 1;
  nexora::HttpClient client;
  auto response = client.Execute(*request, 2000);
  return response && response->status.IsSuccess() ? 0 : 2;
}
```

The default `Execute` convenience creates a local Proactor and resolver. Construct `HttpClient(proactor, resolver, config, CompletionRoute::Bind(router))` to retain a connection across calls. `Connect(uri)` establishes DNS/TCP/TLS first; `Submit(request, callback)` and `DriveOnce()` then support concurrent HTTP/2 streams. `Cancel(id)` completes the callback once. `SetStreamHook` observes HTTP/2 headers, data, trailers, and completion events. Both native client constructors require an explicit completion route for every other subsystem sharing the Proactor. The convenience driver owns a private ring. The client retains one active origin connection. Switching that origin while requests are still active returns `kPoolExhausted`. `OriginPool` controls admission, expiry, and reuse, and its `EndpointFailover` chooses resolved addresses.

`WebSocketClient` shares that explicit `CompletionRoute` or `CompletionRoutes` binding when it uses the caller's Proactor. `HttpServer` accepts HTTP/1, an HTTP/2 preface, or a WebSocket upgrade on one connection. `TlsServerConfig` holds the server certificate and key. After the TLS handshake, `HttpServer::SetNegotiatedAlpn` selects HTTP/1.1 or HTTP/2 before any HTTP bytes are fed. Independent socket owners register with `CompletionRoute::Bind` on one `CompletionRoutes` table; each claims only its own completion token, and `Unregister(this)` removes those entries on shutdown.

`Execute` applies one deadline to DNS, connection establishment, TLS, response reads, and redirects. Redirect limits are configurable. Cross-origin redirects remove authorization, proxy authorization and cookies. HTTPS-to-HTTP redirects are rejected. TLS verifies host trust and the DNS/IP identity by default. `CreateInsecureForTest()` is explicitly used only by the self-contained TLS example. `Shutdown()` sends TLS close_notify before closing the connection.

For a deterministic transport, use `ExchangeOverPipe` or `ExchangeH2OverPipe` with one end of a `MemoryPipePair`. An unfinished exchange returns `Error::Incomplete()` and retains its request. Run the server with the other end, then call the same exchange method again to collect the response. An incomplete result does not submit another request. The lower-level `Submit` / `Feed` / `PendingOutput` / `ConsumeOutput` API lets an application schedule both sides itself.

A service receives `RequestContext`, an owned `Request`, and a move-only `Responder`. Retain the responder to reply later; dropping it without replying queues status 500. Reset, cancellation, and server destruction invalidate retained responders. HTTP/1 responses preserve request order; HTTP/2 responses can finish independently. A context reference is valid only during the handler call. A responder can outlive the server, and a late `Respond` returns a closed error.

```cpp
struct Service {
  [[=nexora::HttpRoute{nexora::Method::kGet, "/health"}]]
  nexora::Result<void> Health(nexora::RequestContext&, nexora::Request,
                             nexora::Responder responder) noexcept {
    return responder.Respond(nexora::Response::Ok("healthy"));
  }
};
```

Keep `Service` and `ReflectService<Service>` alive while the bound server uses them. Duplicate method/path pairs fail at compile time. `WebSocketRoute` binds message handlers to upgrade paths. `HttpServer` accepts HTTP/1, an HTTP/2 client preface, or a WebSocket upgrade through the same input API. `ServeOnce` drives one connection; `ListenAndServeLoopback` accepts one loopback connection for a caller-selected number of steps. An application owns its listener, connection scheduling, and maintenance timers. After an external TLS handshake, call SetNegotiatedAlpn before feeding HTTP bytes; HTTP/1.1 ALPN fixes the parser to HTTP/1, and disabled HTTP/2 is rejected even if TLS negotiated it. RequestContext::target preserves the original HTTP/2 request target, including OPTIONS *.

The bounded wrappers admit at most 64 pending requests/messages. HTTP/1 request and response bodies use the codec's 16 KiB bound. Configure smaller application body limits through `ClientConfig` or `ServerConfig`; larger bodies require a streaming codec/driver policy. All mutable session objects and bound callbacks belong to one execution thread. Response callbacks run after internal drive mutations finish and may destroy their HttpClient. Stream hooks must retain the driving client for the duration of the hook.

The following programs run a real loopback server and client in separate processes and exit after their exchange:

- `http1_keepalive_and_cares_dns`: localhost DNS and connection reuse.
- `http2_tls_multiplex_and_cancel`: TLS 1.3, ALPN h2, multiplexing and cancellation.
- `websocket_echo_and_push_timer`: echo and an io_uring timeout-triggered push.
- `unified_gateway_server`: reflection-bound gateway service.

They are built under `build/<preset>/examples/` and registered as CTest loopback tests. Unit, integration, lifecycle, scenario, and compile-fail tests live under `tests/`.

```sh
cmake --preset clang-glibc-release -DNEXORA_BUILD_BENCHES=ON
cmake --build --preset clang-glibc-release -j 4
build/clang-glibc-release/benches/runtime_hsm_bench --probe ws_mask --iterations 0000002560
```

The pool fixture uses the production observer-free round-robin specialization, including readiness and cooldown recovery. Other policies use the dynamic API and their functional tests. The benchmark accepts `socket_step`, `h2_frame_header`, `ws_mask`, and `pool_select`, plus a positive `--seed`. Probes execute the production operators over runtime BSS state, initialized before measurement. Keep iteration arguments fixed-width when collecting gem5 three-point differences at 512, 2560, and 4608 iterations. Native code generation is built independently of sanitizer instrumentation. Numerical code-generation and performance results must come from the matching build's audit output.

The freestanding `nexora_gem5_guest` uses the same native operator object as the benchmark and runs directly for checksum checks. `nexora_gem5_roi_guest` warms the operator, resets its state, and uses gem5 reset/dump instructions to bracket the measured loop; run this binary only inside gem5. The audit scripts validate checksums against independent host formulas, fixed-width three-point simulation inputs, counter stationarity, rename-slot attribution, and native counter scheduling:

```sh
python3 tests/scenario/gem5_verify.py --binary build/clang-glibc-release/benches/nexora_gem5_roi_guest --output build/clang-glibc-release/audit/gem5-roi
python3 tests/scenario/pmu_verify.py --binary build/clang-glibc-release/benches/runtime_hsm_bench --output build/clang-glibc-release/audit/pmu-final --cpu 2
```

Select an admitted CPU for native collection. gem5 defaults to `/opt/gem5/build/ALL/gem5.opt` and the uarch O3 configuration; override `--gem5` and `--config` for another installation. These measurements describe the selected fixture and execution domain.

The `port/` directory contains the vcpkg overlay metadata and usage. The package includes the MIT license from `LICENSE`. Generate `portfile.cmake` and `vcpkg.json` from the `.in` templates with the release version, verified commit SHA and archive SHA512.
